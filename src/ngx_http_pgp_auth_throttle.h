/*
 * ngx_http_pgp_auth_throttle.h - per-client-IP adaptive failure throttling.
 *
 * A shared-memory rbtree, keyed by client IP, counts failed verification
 * attempts within a sliding window and imposes a temporary ban once a
 * configured threshold is crossed -- a fail2ban-style layer that sits
 * *inside* the module, in addition to (not instead of) limit_req at the
 * nginx config level. The two serve different purposes: limit_req caps raw
 * request rate for everyone uniformly; this only engages for a specific
 * client IP that is actually failing verification, and resets on a
 * successful login.
 */

#ifndef NGX_HTTP_PGP_AUTH_THROTTLE_H
#define NGX_HTTP_PGP_AUTH_THROTTLE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_PGP_THROTTLE_ZONE_SIZE  (1 * 1024 * 1024)


/*
 * Register the shared-memory zone. Called from the location-merge step;
 * returns the (shared) zone, or NULL on error.
 */
ngx_shm_zone_t *ngx_http_pgp_throttle_add_zone(ngx_conf_t *cf, size_t size);

/*
 * Check whether this request's client IP is currently banned.
 *   NGX_OK       - not banned, proceed normally
 *   NGX_DECLINED - banned, the caller should reject without doing any
 *                  gpg/verification work at all
 * For a NULL zone (throttling disabled) this is always NGX_OK.
 */
ngx_int_t ngx_http_pgp_throttle_is_banned(ngx_http_request_t *r,
    ngx_shm_zone_t *zone);

/*
 * Record the outcome of a verification attempt for this request's client IP.
 * On failure, increments the sliding-window counter and, once it reaches
 * `limit` within `window` seconds, sets a ban lasting `ban_time` seconds.
 * On success, clears any counter/ban for that IP (a legitimate login is
 * treated as proof the client is not the attacker the throttle exists for).
 * A NULL zone is a no-op.
 */
void ngx_http_pgp_throttle_record(ngx_http_request_t *r, ngx_shm_zone_t *zone,
    ngx_flag_t success, ngx_uint_t limit, time_t window, time_t ban_time);

#endif /* NGX_HTTP_PGP_AUTH_THROTTLE_H */
