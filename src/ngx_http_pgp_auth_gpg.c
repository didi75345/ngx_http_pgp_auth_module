/*
 * ngx_http_pgp_auth_gpg.c - verify clear-signed PGP messages by invoking gpg.
 *
 * A throwaway GNUPGHOME is created per call so we never touch the system or
 * the worker user's keyring, and the public keyring to validate against is
 * passed explicitly. This only runs at login (then a session cookie takes
 * over), so the cost of spawning gpg is not on the hot path.
 */

#include "ngx_http_pgp_auth_gpg.h"

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


/* Upper bound on a single gpg verification before it is killed. */
#define NGX_HTTP_PGP_GPG_TIMEOUT_MS  5000


static int64_t
ngx_http_pgp_now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


static void
ngx_http_pgp_gpg_cleanup(const char *home, const char *msgpath)
{
    DIR            *d;
    struct dirent  *de;
    char            path[PATH_MAX];

    if (msgpath) {
        unlink(msgpath);
    }

    d = opendir(home);
    if (d != NULL) {
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
            (void) ngx_snprintf((u_char *) path, sizeof(path), "%s/%s%Z",
                                home, de->d_name);
            unlink(path);
        }
        closedir(d);
    }

    rmdir(home);
}


ngx_int_t
ngx_http_pgp_gpg_verify(ngx_log_t *log, ngx_str_t *keyring,
    u_char *msg, size_t msg_len, ngx_msec_t timeout_ms,
    ngx_http_pgp_verify_result_t *res)
{
    pid_t        pid;
    int          pfd[2], fd, status;
    ssize_t      n;
    size_t       off;
    char         home[] = "/tmp/ngx_pgp_XXXXXX";
    char         msgpath[PATH_MAX];
    char         plainpath[PATH_MAX];
    char         keyringz[PATH_MAX];
    char         out[8192];
    char        *p, *line, *save;
    int64_t      deadline;
    ngx_int_t    good, bad, truncated;
    sigset_t     chld, prev;

    truncated = 0;

    res->valid = 0;
    res->fpr_len = 0;
    res->plaintext_len = 0;

    if (keyring->len == 0 || keyring->len >= PATH_MAX) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "pgp_auth: invalid keyring path");
        return NGX_ERROR;
    }
    ngx_memcpy(keyringz, keyring->data, keyring->len);
    keyringz[keyring->len] = '\0';

    if (mkdtemp(home) == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "pgp_auth: mkdtemp() failed");
        return NGX_ERROR;
    }

    (void) ngx_snprintf((u_char *) msgpath, sizeof(msgpath), "%s/m%Z", home);
    (void) ngx_snprintf((u_char *) plainpath, sizeof(plainpath), "%s/p%Z", home);

    fd = open(msgpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "pgp_auth: open(%s) failed", msgpath);
        ngx_http_pgp_gpg_cleanup(home, NULL);
        return NGX_ERROR;
    }
    for (off = 0; off < msg_len; off += (size_t) n) {
        n = write(fd, msg + off, msg_len - off);
        if (n <= 0) {
            close(fd);
            ngx_http_pgp_gpg_cleanup(home, msgpath);
            return NGX_ERROR;
        }
    }
    close(fd);

    if (pipe(pfd) == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "pgp_auth: pipe() failed");
        ngx_http_pgp_gpg_cleanup(home, msgpath);
        return NGX_ERROR;
    }

    /*
     * Block SIGCHLD around the fork/wait. nginx installs its own SIGCHLD
     * handler that reaps every child it sees; without this it would reap our
     * gpg process before we can waitpid() for it, stealing the exit status and
     * leaving verification unreliable (the bug shows up under real browser use,
     * not single curl requests). The child restores the mask before exec so
     * gpg runs normally.
     */
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &prev);

    pid = fork();
    if (pid == -1) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "pgp_auth: fork() failed");
        sigprocmask(SIG_SETMASK, &prev, NULL);
        close(pfd[0]);
        close(pfd[1]);
        ngx_http_pgp_gpg_cleanup(home, msgpath);
        return NGX_ERROR;
    }

    if (pid == 0) {
        int devnull;

        /*
         * child: machine-readable status goes to the pipe (stdout, via
         * --status-fd 1); the verified plaintext goes to --output plainpath;
         * and gpg's human-readable chatter (stderr) is discarded. Keeping the
         * status stream separate from stderr is deliberate: an attacker must
         * not be able to smuggle a forged "VALIDSIG" line in via stderr.
         */
        dup2(pfd[1], STDOUT_FILENO);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull != -1) {
            dup2(devnull, STDERR_FILENO);
        }
        for (fd = 3; fd < 1024; fd++) {
            close(fd);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);   /* gpg runs with a normal mask */
        /*
         * --decrypt (not --verify) so gpg writes the signed plaintext to
         * --output; --verify alone produces no output to bind the challenge to.
         */
        execlp("gpg", "gpg",
               "--homedir", home,
               "--no-default-keyring",
               "--keyring", keyringz,
               "--status-fd", "1",
               "--output", plainpath,
               "--batch", "--no-tty", "--yes",
               "--no-autostart",       /* signature verify needs no gpg-agent */
               "--decrypt", msgpath,
               (char *) NULL);
        _exit(127);
    }

    /* parent */
    close(pfd[1]);

    /*
     * Read gpg's output, but never let a stuck gpg block the worker forever:
     * poll with a deadline and SIGKILL the child if it overruns. Verification
     * is normally a few milliseconds, so a several-second cap is generous.
     */
    off = 0;
    deadline = ngx_http_pgp_now_ms() + (int64_t) timeout_ms;
    for ( ;; ) {
        int64_t        left = deadline - ngx_http_pgp_now_ms();
        struct pollfd  pe = { pfd[0], POLLIN, 0 };

        if (left <= 0) {
            kill(pid, SIGKILL);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "pgp_auth: gpg verify timed out, killed");
            break;
        }

        n = poll(&pe, 1, (int) left);
        if (n == 0) {
            kill(pid, SIGKILL);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "pgp_auth: gpg verify timed out, killed");
            break;
        }
        if (n < 0) {
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
            kill(pid, SIGKILL);
            break;
        }

        n = read(pfd[0], out + off, sizeof(out) - 1 - off);
        if (n > 0) {
            off += (size_t) n;
            if (off >= sizeof(out) - 1) {
                /*
                 * Status stream longer than our buffer: a later BADSIG /
                 * REVKEYSIG marker could be cut off, so we must not trust a
                 * VALIDSIG seen so far. Fail the verification.
                 */
                truncated = 1;
                kill(pid, SIGKILL);
                break;
            }
            continue;
        }
        if (n == 0) {
            break;
        }
        if (ngx_errno == NGX_EINTR) {
            continue;
        }
        break;
    }
    out[off] = '\0';
    close(pfd[0]);

    while (waitpid(pid, &status, 0) == -1 && ngx_errno == NGX_EINTR) {
        /* retry */
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);

    /* Capture the verified plaintext before cleanup wipes the temp dir. */
    fd = open(plainpath, O_RDONLY);
    if (fd != -1) {
        off = 0;
        for ( ;; ) {
            n = read(fd, res->plaintext + off,
                     sizeof(res->plaintext) - off);
            if (n > 0) {
                off += (size_t) n;
                if (off >= sizeof(res->plaintext)) {
                    truncated = 1;      /* signed content exceeds our buffer */
                    break;
                }
                continue;
            }
            if (n < 0 && ngx_errno == NGX_EINTR) {
                continue;
            }
            break;
        }
        res->plaintext_len = off;
        close(fd);
    }

    ngx_http_pgp_gpg_cleanup(home, msgpath);

    /*
     * Parse gpg --status-fd output. Only trust lines carrying the exact
     * "[GNUPG:] " machine prefix (not human text), require a real fingerprint,
     * and reject the signature outright if gpg reported it revoked, made by an
     * expired key, or itself expired/bad.
     *   [GNUPG:] VALIDSIG <primary-key-fpr> <date> <timestamp> ...
     */
    good = 0;
    bad = 0;
    for (line = strtok_r(out, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        if (ngx_strncmp(line, "[GNUPG:] ", 9) != 0) {
            continue;                          /* not a status line */
        }
        p = line + 9;

        if (ngx_strncmp(p, "VALIDSIG ", 9) == 0) {
            p += 9;
            n = 0;
            while (p[n] != '\0' && p[n] != ' '
                   && (size_t) n < sizeof(res->fpr) - 1)
            {
                res->fpr[n] = (u_char) p[n];
                n++;
            }
            res->fpr[n] = '\0';
            res->fpr_len = (size_t) n;
            if (n >= 32) {                      /* reject empty/short fpr */
                good = 1;
            }

        } else if (ngx_strncmp(p, "REVKEYSIG", 9) == 0     /* revoked key   */
                   || ngx_strncmp(p, "EXPKEYSIG", 9) == 0  /* expired key   */
                   || ngx_strncmp(p, "EXPSIG", 6) == 0     /* expired sig   */
                   || ngx_strncmp(p, "BADSIG", 6) == 0     /* bad signature */
                   || ngx_strncmp(p, "ERRSIG", 6) == 0)    /* verify error  */
        {
            bad = 1;
        }
    }

    if (truncated) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "pgp_auth: gpg output truncated; rejecting");
    }

    res->valid = (good && !bad && !truncated) ? 1 : 0;
    if (!res->valid) {
        res->fpr_len = 0;
    }

    if (!res->valid) {
        /*
         * No good signature. Surface gpg's own message and exit code so an
         * operator can tell a genuinely bad/unknown signature apart from an
         * environment problem (e.g. the worker user cannot read the keyring,
         * or gpg is not installed -> exit 127).
         */
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

        for (p = out; *p; p++) {
            if (*p == '\n' || *p == '\r') {
                *p = ' ';
            }
        }

        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "pgp_auth: gpg verify produced no valid signature "
                      "(keyring \"%V\", exit %d): %s",
                      keyring, code, out[0] ? out : "(no output)");
    }

    return NGX_OK;
}
