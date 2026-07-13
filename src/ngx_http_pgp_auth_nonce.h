/*
 * ngx_http_pgp_auth_nonce.h - single-use challenge tracking (replay defence).
 *
 * The stateless HMAC design proves a challenge was issued by us and is
 * unexpired, but not that it is being used for the first time. This adds an
 * optional seen-nonce store so a captured, still-valid signed challenge cannot
 * be replayed within its lifetime.
 *
 * Backends (pgp_auth_nonce_storage):
 *   memory  - a shared-memory zone in nginx (default; works across workers of
 *             one instance)
 *   redis   - an external store (works across nodes)
 *   none    - no tracking (the original stateless behaviour)
 */

#ifndef NGX_HTTP_PGP_AUTH_NONCE_H
#define NGX_HTTP_PGP_AUTH_NONCE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_PGP_NONCE_NONE    0
#define NGX_HTTP_PGP_NONCE_MEMORY  1
#define NGX_HTTP_PGP_NONCE_REDIS   2


/*
 * Register the shared-memory zone for the "memory" backend. Called from the
 * location-merge step; returns the (shared) zone or NULL on error.
 */
ngx_shm_zone_t *ngx_http_pgp_nonce_add_zone(ngx_conf_t *cf, size_t size);

/*
 * Record a nonce as used, atomically.
 *   NGX_OK       - first use; the nonce is now recorded until `exp`
 *   NGX_DECLINED - already used (replay): reject the login
 *   NGX_ERROR    - backend failure
 * For NGX_HTTP_PGP_NONCE_NONE this is a no-op returning NGX_OK.
 */
ngx_int_t ngx_http_pgp_nonce_check_and_set(ngx_http_request_t *r,
    ngx_uint_t storage, ngx_shm_zone_t *zone, ngx_str_t *addr,
    ngx_str_t *password, ngx_str_t *nonce, time_t exp);

#endif /* NGX_HTTP_PGP_AUTH_NONCE_H */
