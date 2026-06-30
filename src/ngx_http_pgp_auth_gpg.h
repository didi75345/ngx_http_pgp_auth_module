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

typedef struct {
    ngx_int_t  valid;            /* 1 if a good signature from a keyring key */
    u_char     fpr[80];          /* hex fingerprint of the signing key       */
    size_t     fpr_len;
} ngx_http_pgp_verify_result_t;

/*
 * Verify a clear-signed PGP message against `keyring` (absolute path).
 * On a good signature from a key present in the keyring, sets
 * res->valid = 1 and fills res->fpr. Returns NGX_OK if the verification
 * ran (regardless of result), NGX_ERROR on an internal failure.
 */
ngx_int_t ngx_http_pgp_gpg_verify(ngx_log_t *log, ngx_str_t *keyring,
    u_char *msg, size_t msg_len, ngx_http_pgp_verify_result_t *res);

#endif /* NGX_HTTP_PGP_AUTH_GPG_H */
