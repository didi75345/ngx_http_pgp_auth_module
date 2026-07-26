/*
 * ngx_http_pgp_auth_gpg.h - signature verification via the system gpg binary.
 *
 * Verification is delegated to the system `gpg` so the module carries no
 * cryptographic dependency of its own beyond what nginx already links
 * (OpenSSL for the HMAC tokens). gpg is required anyway to manage the
 * keyring, so this adds nothing new to install.
 */

#ifndef NGX_HTTP_PGP_AUTH_GPG_H
#define NGX_HTTP_PGP_AUTH_GPG_H

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_HTTP_PGP_PLAINTEXT_MAX  8192

typedef struct {
    ngx_int_t  valid;            /* 1 if a good signature from a keyring key */
    u_char     fpr[80];          /* hex fingerprint of the signing key       */
    size_t     fpr_len;

    /*
     * The exact bytes gpg actually verified (the signed plaintext), captured
     * via --output. The caller MUST look for the challenge only inside this
     * region -- never in the raw submitted body -- so that text appended or
     * prepended outside the signature cannot be treated as signed.
     */
    u_char     plaintext[NGX_HTTP_PGP_PLAINTEXT_MAX];
    size_t     plaintext_len;

    /*
     * Deferred diagnostic. gpg verification can run on a thread-pool thread,
     * where nginx's logging is not thread-safe (Pentest CCS F-003). So
     * gpg_verify never logs itself: it records its message here and the caller
     * emits it from the worker event loop via ngx_http_pgp_gpg_log_diag().
     */
    ngx_uint_t diag_level;          /* 0 = nothing to log */
    u_char     diag[256];

    /*
     * Async path: the challenge MAC/expiry check and the single-use nonce
     * consumption run on the verification thread, right after gpg, so the
     * (possibly blocking) Redis nonce round-trip stays off the worker too
     * (Pentest CCS F-001). The worker reads the outcome here.
     */
    ngx_uint_t chal_done;           /* 1 = the thread already validated+consumed */
    ngx_int_t  chal_rc;             /* NGX_OK / NGX_DECLINED / NGX_ERROR */

    /*
     * Short, static-string reason code for the structured pgp_auth_event log
     * line (see ngx_http_pgp_log_event() in the module). Set alongside
     * ngx_http_pgp_defer_diag()/ngx_http_pgp_gpg_diag() at the same decision
     * points; a plain pointer assignment to a string literal, so it's just as
     * thread-safe to set from the verification thread as the diag mechanism
     * it travels with. NULL if nothing decided yet.
     */
    const char *chal_reason;
} ngx_http_pgp_verify_result_t;

/*
 * Verify a clear-signed PGP message against `keyring` (absolute path).
 * On a good signature from a key present in the keyring, sets res->valid = 1,
 * fills res->fpr, and copies the verified plaintext into res->plaintext.
 * Returns NGX_OK if the verification ran (regardless of result), NGX_ERROR on
 * an internal failure.
 */
ngx_int_t ngx_http_pgp_gpg_verify(ngx_log_t *log, ngx_str_t *gpg_path,
    ngx_str_t *keyring, u_char *msg, size_t msg_len, ngx_msec_t timeout_ms,
    ngx_http_pgp_verify_result_t *res);

/*
 * Record a diagnostic for the worker to log later (keeps the first one set).
 * Thread-safe: writes only into the caller-owned result buffer, never nginx's
 * shared log. Used by any code that can run on the verification thread (gpg and
 * the nonce backends). (Pentest CCS F-003.)
 */
void ngx_http_pgp_defer_diag(ngx_http_pgp_verify_result_t *res,
    ngx_uint_t level, const char *fmt, ...);

/*
 * Emit the diagnostic recorded above (if any), then clear it. MUST be called
 * from the worker event loop, never a thread -- this is what keeps
 * verification logging thread-safe (Pentest CCS F-003).
 */
void ngx_http_pgp_gpg_log_diag(ngx_log_t *log,
    ngx_http_pgp_verify_result_t *res);

#endif /* NGX_HTTP_PGP_AUTH_GPG_H */
