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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


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
    u_char *msg, size_t msg_len, ngx_http_pgp_verify_result_t *res)
{
    pid_t        pid;
    int          pfd[2], fd, status;
    ssize_t      n;
    size_t       off;
    char         home[] = "/tmp/ngx_pgp_XXXXXX";
    char         msgpath[PATH_MAX];
    char         keyringz[PATH_MAX];
    char         out[8192];
    char        *p, *line, *save;
    sigset_t     chld, prev;

    res->valid = 0;
    res->fpr_len = 0;

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
        /*
         * child: capture both the machine-readable status (stdout, via
         * --status-fd 1) and gpg's human-readable diagnostics (stderr) on the
         * same pipe, so a failure such as an unreadable keyring is logged
         * rather than silently looking like "no valid signature".
         */
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        for (fd = 3; fd < 1024; fd++) {
            close(fd);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);   /* gpg runs with a normal mask */
        execlp("gpg", "gpg",
               "--homedir", home,
               "--no-default-keyring",
               "--keyring", keyringz,
               "--status-fd", "1",
               "--batch", "--no-tty",
               "--verify", msgpath,
               (char *) NULL);
        _exit(127);
    }

    /* parent */
    close(pfd[1]);

    off = 0;
    for ( ;; ) {
        n = read(pfd[0], out + off, sizeof(out) - 1 - off);
        if (n > 0) {
            off += (size_t) n;
            if (off >= sizeof(out) - 1) {
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

    ngx_http_pgp_gpg_cleanup(home, msgpath);

    /*
     * Parse gpg --status-fd output. A trustworthy good signature emits:
     *   [GNUPG:] VALIDSIG <primary-key-fpr> <date> <timestamp> ...
     * The first token after VALIDSIG is the signing key fingerprint.
     */
    for (line = strtok_r(out, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        p = strstr(line, "VALIDSIG ");
        if (p == NULL) {
            continue;
        }
        p += sizeof("VALIDSIG ") - 1;

        n = 0;
        while (p[n] != '\0' && p[n] != ' '
               && (size_t) n < sizeof(res->fpr) - 1)
        {
            res->fpr[n] = (u_char) p[n];
            n++;
        }
        res->fpr[n] = '\0';
        res->fpr_len = (size_t) n;
        res->valid = 1;
        break;
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
