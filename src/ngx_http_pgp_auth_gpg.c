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
#include <sys/syscall.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>


/* Upper bound on a single gpg verification before it is killed. */
#define NGX_HTTP_PGP_GPG_TIMEOUT_MS  5000

/* stringize a numeric macro so it can be passed as a gpg command-line arg */
#define ngx_http_pgp_str2(x)       #x
#define ngx_http_pgp_stringize(x)  ngx_http_pgp_str2(x)


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
ngx_http_pgp_gpg_verify(ngx_log_t *log, ngx_str_t *gpg_path,
    ngx_str_t *keyring, u_char *msg, size_t msg_len, ngx_msec_t timeout_ms,
    ngx_http_pgp_verify_result_t *res)
{
    pid_t        pid;
    int          pfd[2], fd, status;
    ssize_t      n;
    size_t       off;
    char         home[PATH_MAX];
    const char  *tmpdir;
    char         msgpath[PATH_MAX];
    char         plainpath[PATH_MAX];
    char         keyringz[PATH_MAX];
    char         gpgz[PATH_MAX];
    char         out[8192];
    char         parsebuf[8192];   /* strtok_r scratch; keeps `out` intact for logs */
    size_t       outlen;           /* status bytes in `out` (off is reused below) */
    char        *p, *line, *save;
    int64_t      deadline;
    ngx_int_t    good, bad, truncated;
    sigset_t     chld, prev;
    /* Minimal, fixed environment for the child: never forward whatever the
     * worker process happens to have (LD_PRELOAD, LD_LIBRARY_PATH, GNUPGHOME,
     * a hostile PATH, ...) into the subprocess we spawn on every
     * unauthenticated login attempt. */
    static char *child_envp[] = { NULL };

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

    /*
     * gpg_path is validated at config time to be a non-empty absolute path
     * (see ngx_http_pgp_auth_merge_loc_conf); re-check defensively before
     * handing it to execve() so a NULL/garbage value can never reach exec.
     */
    if (gpg_path->len == 0 || gpg_path->len >= PATH_MAX
        || gpg_path->data[0] != '/')
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "pgp_auth: invalid gpg binary path");
        return NGX_ERROR;
    }
    ngx_memcpy(gpgz, gpg_path->data, gpg_path->len);
    gpgz[gpg_path->len] = '\0';

    /*
     * Create the throwaway keyring dir under $TMPDIR when set (an absolute
     * path), else /tmp -- matching the documented "system temp dir" rather
     * than always hardcoding /tmp. gpg itself runs with an empty environment
     * and an absolute --homedir, so it does not depend on TMPDIR.
     */
    tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || tmpdir[0] != '/'
        || ngx_strlen(tmpdir) > sizeof(home) - sizeof("/ngx_pgp_XXXXXX"))
    {
        tmpdir = "/tmp";
    }
    (void) ngx_snprintf((u_char *) home, sizeof(home), "%s/ngx_pgp_XXXXXX%Z",
                        tmpdir);

    if (mkdtemp(home) == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "pgp_auth: mkdtemp() failed");
        return NGX_ERROR;
    }

    (void) ngx_snprintf((u_char *) msgpath, sizeof(msgpath), "%s/m%Z", home);
    (void) ngx_snprintf((u_char *) plainpath, sizeof(plainpath), "%s/p%Z", home);

    /*
     * O_NOFOLLOW: refuse to follow a symlink at this path. The directory is
     * created by mkdtemp() at mode 0700 owned by the worker, so nothing else
     * should be able to plant one -- but on a shared $TMPDIR this closes the
     * window between creating the directory and opening the file, so a write
     * can never be redirected outside it. O_EXCL for the same reason: create
     * it or fail, never open something already there.
     */
    fd = open(msgpath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
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
        /*
         * Close every inherited fd >= 3 before exec, so the gpg child never
         * holds nginx's listening sockets, client connections, log fds, etc.
         * A hardcoded "< 1024" bound is not safe: worker_rlimit_nofile is
         * commonly raised well above 1024 (10000+ is typical), which would
         * leave higher-numbered fds open and reachable to the child. Prefer
         * close_range() (one syscall, Linux 5.9+); fall back to sysconf's
         * actual fd ceiling if the syscall is unavailable or fails.
         */
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3, ~0U, 0) != 0)
#endif
        {
            long max_fd = sysconf(_SC_OPEN_MAX);
            if (max_fd <= 0 || max_fd > 1000000) {
                max_fd = 1024;    /* sane fallback if sysconf is unusable */
            }
            for (fd = 3; fd < max_fd; fd++) {
                close(fd);
            }
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);   /* gpg runs with a normal mask */
        /*
         * --decrypt (not --verify) so gpg writes the signed plaintext to
         * --output; --verify alone produces no output to bind the challenge to.
         *
         * execve() with an absolute path and an empty envp, NOT execlp():
         * execlp() searches $PATH for "gpg", so anything earlier in the
         * worker's PATH (or a hostile PATH set via the environment) could be
         * run instead of the real gpg binary. Using the operator-configured
         * absolute path (pgp_gpg_path) and clearing the environment removes
         * both the PATH-search risk and LD_PRELOAD/LD_LIBRARY_PATH-style
         * library injection via inherited environment variables.
         */
        {
            char *argv[] = {
                gpgz,
                "--homedir", home,
                "--no-default-keyring",
                "--keyring", keyringz,
                "--status-fd", "1",
                "--output", plainpath,
                /*
                 * Cap what gpg will write. --decrypt also inflates compressed
                 * OpenPGP packets, so without this a small (<=16k) but highly
                 * compressed body could make gpg write a huge file to the temp
                 * dir before the timeout -- a data-amplification DoS, worst on
                 * the small tmpfs /tmp common in containers. The verified
                 * plaintext we care about (a signed challenge) is a few hundred
                 * bytes; NGX_HTTP_PGP_PLAINTEXT_MAX is a generous ceiling and
                 * matches the buffer we read it into.
                 */
                "--max-output", ngx_http_pgp_stringize(NGX_HTTP_PGP_PLAINTEXT_MAX),
                "--batch", "--no-tty", "--yes",
                "--no-autostart",   /* signature verify needs no gpg-agent */
                "--decrypt", msgpath,
                NULL
            };
            execve(gpgz, argv, child_envp);
        }
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
    outlen = off;                  /* remember it: `off` is reused for plaintext */
    close(pfd[0]);

    while (waitpid(pid, &status, 0) == -1 && ngx_errno == NGX_EINTR) {
        /* retry */
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);

    /* Capture the verified plaintext before cleanup wipes the temp dir. */
    fd = open(plainpath, O_RDONLY | O_NOFOLLOW);   /* see msgpath open above */
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
    /*
     * strtok_r rewrites its input (each '\n' -> '\0'), which would truncate the
     * error log below to gpg's first line only. Parse a COPY and keep `out`
     * intact so the failure log can show gpg's full message.
     */
    ngx_memcpy(parsebuf, out, outlen + 1);         /* includes the '\0' at out[outlen] */
    for (line = strtok_r(parsebuf, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        if (ngx_strncmp(line, "[GNUPG:] ", 9) != 0) {
            continue;                          /* not a status line */
        }
        p = line + 9;

        if (ngx_strncmp(p, "VALIDSIG ", 9) == 0) {
            char    *q, *tok;
            size_t   i;

            p += 9;

            /*
             * VALIDSIG args:
             *   <signing-key-fpr> <date> <ts> <exp> <ver> <rsv> <algo>
             *   <hash> <sig-class> <primary-key-fpr>
             * Identify the signer by the PRIMARY key fingerprint (the last
             * field), not the first. When a signature is made by a signing
             * SUBKEY, field 1 is the subkey fpr; keying identity/revocation
             * off it would let a key revoked by its (primary) fingerprint
             * still authenticate, and would change a user's identity whenever
             * they rotate a subkey. The last field equals field 1 when the
             * primary signs directly, so using it is always correct.
             */
            tok = p;
            for (q = p; ; ) {
                while (*q == ' ') { q++; }
                if (*q == '\0') { break; }
                tok = q;                         /* start of a token       */
                while (*q != '\0' && *q != ' ') { q++; }
            }

            n = 0;
            while (tok[n] != '\0' && tok[n] != ' '
                   && (size_t) n < sizeof(res->fpr) - 1)
            {
                res->fpr[n] = (u_char) tok[n];
                n++;
            }
            res->fpr[n] = '\0';

            /* the last field must look like a fingerprint (hex, >= 32) */
            for (i = 0; i < (size_t) n; i++) {
                u_char c = res->fpr[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                      || (c >= 'A' && c <= 'F')))
                {
                    break;
                }
            }

            if (n >= 32 && i == (size_t) n) {
                res->fpr_len = (size_t) n;      /* primary key fingerprint */
                good = 1;
            } else {
                /*
                 * No usable primary-key-fpr (e.g. a very old gpg whose
                 * VALIDSIG omits it) -- fall back to field 1 (signing key).
                 */
                n = 0;
                while (p[n] != '\0' && p[n] != ' '
                       && (size_t) n < sizeof(res->fpr) - 1)
                {
                    res->fpr[n] = (u_char) p[n];
                    n++;
                }
                res->fpr[n] = '\0';
                res->fpr_len = (size_t) n;
                if (n >= 32) {
                    good = 1;
                }
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
            /* collapse newlines to spaces and strip anything else that isn't
             * plain printable ASCII, so gpg's own text can't inject escape
             * sequences or otherwise confuse whatever reads the log */
            if (*p == '\n' || *p == '\r') {
                *p = ' ';
            } else if ((unsigned char) *p < 0x20 || (unsigned char) *p == 0x7f) {
                *p = '?';
            }
        }

        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "pgp_auth: gpg verify produced no valid signature "
                      "(keyring \"%V\", exit %d): %s",
                      keyring, code, out[0] ? out : "(no output)");
    }

    return NGX_OK;
}
