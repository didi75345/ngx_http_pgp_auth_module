/*
 * ngx_http_pgp_auth_throttle.c - see the header for the design rationale.
 *
 * Structurally this mirrors ngx_http_pgp_auth_nonce.c's "memory" backend
 * closely on purpose (rbtree + LRU queue in a slab-allocated shared zone):
 * it is a well-exercised, already-reviewed pattern in this codebase, and
 * reusing it exactly reduces the amount of genuinely new code a reviewer
 * has to trust.
 */

#include "ngx_http_pgp_auth_throttle.h"

extern ngx_module_t  ngx_http_pgp_auth_module;


typedef struct {
    ngx_rbtree_node_t   node;          /* .key = crc32(ip text) */
    ngx_queue_t         queue;         /* LRU: newest at head, oldest at tail */
    time_t              window_start;  /* start of the current failure window */
    time_t              banned_until;  /* 0 = not banned                      */
    ngx_uint_t          count;         /* failures seen in this window        */
    u_short             len;
    u_char              data[1];       /* client IP text                     */
} ngx_http_pgp_throttle_node_t;

typedef struct {
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         queue;
} ngx_http_pgp_throttle_sh_t;

typedef struct {
    ngx_http_pgp_throttle_sh_t  *sh;
    ngx_slab_pool_t             *shpool;
} ngx_http_pgp_throttle_ctx_t;


static void
ngx_http_pgp_throttle_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t             **p;
    ngx_http_pgp_throttle_node_t    *n, *nt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            n = (ngx_http_pgp_throttle_node_t *) node;
            nt = (ngx_http_pgp_throttle_node_t *) temp;

            if (n->len != nt->len) {
                p = (n->len < nt->len) ? &temp->left : &temp->right;
            } else {
                p = (ngx_memcmp(n->data, nt->data, n->len) < 0)
                        ? &temp->left : &temp->right;
            }
        }

        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_http_pgp_throttle_node_t *
ngx_http_pgp_throttle_lookup(ngx_http_pgp_throttle_sh_t *sh, uint32_t hash,
    ngx_str_t *ip)
{
    ngx_int_t                      rc;
    ngx_rbtree_node_t             *node, *sentinel;
    ngx_http_pgp_throttle_node_t  *n;

    node = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) { node = node->left;  continue; }
        if (hash > node->key) { node = node->right; continue; }

        n = (ngx_http_pgp_throttle_node_t *) node;

        if (ip->len != n->len) {
            node = (ip->len < n->len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(ip->data, n->data, n->len);
        if (rc == 0) {
            return n;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


/* Evict up to `max` of the oldest entries that are both unbanned and outside
 * their counting window -- i.e. truly stale, not just currently-clean.
 *
 * The stale threshold is tied to the configured failure_window rather than a
 * fixed hour: an entry is reclaimable once its window is well past. We keep a
 * one-hour floor so that with short windows entries aren't churned in and out
 * on every request, and scale up with the window so a long window (e.g. a
 * day-long tracking window) doesn't have its entries evicted an hour after the
 * window ends -- which would drop ban/counting state the operator asked to
 * keep. `window` is the caller's failure_window (0 = throttle disabled). */
static void
ngx_http_pgp_throttle_evict_stale(ngx_http_pgp_throttle_ctx_t *ctx, time_t now,
    time_t window, ngx_uint_t max)
{
    time_t                         stale_after;
    ngx_queue_t                   *q, *prev;
    ngx_http_pgp_throttle_node_t  *n;

    stale_after = ngx_max(window, 3600);

    q = ngx_queue_empty(&ctx->sh->queue) ? NULL : ngx_queue_last(&ctx->sh->queue);

    while (max-- > 0 && q != NULL && q != ngx_queue_sentinel(&ctx->sh->queue)) {
        n = ngx_queue_data(q, ngx_http_pgp_throttle_node_t, queue);
        prev = ngx_queue_prev(q);

        if (n->banned_until <= now && n->window_start + stale_after <= now) {
            ngx_queue_remove(q);
            ngx_rbtree_delete(&ctx->sh->rbtree, &n->node);
            ngx_slab_free_locked(ctx->shpool, n);
        }

        q = (prev == &ctx->sh->queue) ? NULL : prev;
    }
}


static ngx_str_t *
ngx_http_pgp_throttle_client_ip(ngx_http_request_t *r, ngx_str_t *buf)
{
    /* Text form of the already-resolved client address (post ngx_http_realip
     * if that module is in use ahead of us) -- the same value every other
     * client-identity decision in this module (IP binding, rate limiting)
     * is keyed on, so this stays consistent with the rest of the module. */
    *buf = r->connection->addr_text;
    return buf;
}


ngx_int_t
ngx_http_pgp_throttle_is_banned(ngx_http_request_t *r, ngx_shm_zone_t *zone)
{
    uint32_t                       hash;
    time_t                         now;
    ngx_str_t                      ip;
    ngx_http_pgp_throttle_ctx_t   *ctx;
    ngx_http_pgp_throttle_node_t  *n;

    if (zone == NULL) {
        return NGX_OK;
    }

    ngx_http_pgp_throttle_client_ip(r, &ip);
    if (ip.len == 0 || ip.len > 65535) {
        return NGX_OK;              /* can't key on it; fail open on this check only */
    }

    ctx = zone->data;
    hash = ngx_crc32_short(ip.data, ip.len);
    now = ngx_time();

    ngx_shmtx_lock(&ctx->shpool->mutex);
    n = ngx_http_pgp_throttle_lookup(ctx->sh, hash, &ip);
    if (n != NULL && n->banned_until > now) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "pgp_auth_event: result=\"denied\" reason=\"throttled\" "
            "ip=\"%V\" banned_for=%T", &ip, n->banned_until - now);
        return NGX_DECLINED;
    }
    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_OK;
}


void
ngx_http_pgp_throttle_record(ngx_http_request_t *r, ngx_shm_zone_t *zone,
    ngx_flag_t success, ngx_uint_t limit, time_t window, time_t ban_time)
{
    size_t                          size;
    uint32_t                        hash;
    time_t                          now;
    ngx_str_t                       ip;
    ngx_http_pgp_throttle_ctx_t    *ctx;
    ngx_http_pgp_throttle_node_t   *n;

    if (zone == NULL) {
        return;
    }

    ngx_http_pgp_throttle_client_ip(r, &ip);
    if (ip.len == 0 || ip.len > 65535) {
        return;
    }

    ctx = zone->data;
    hash = ngx_crc32_short(ip.data, ip.len);
    now = ngx_time();

    ngx_shmtx_lock(&ctx->shpool->mutex);

    n = ngx_http_pgp_throttle_lookup(ctx->sh, hash, &ip);

    if (success) {
        /* A valid login clears this IP's slate -- it demonstrates the
         * request stream from it is (at least now) legitimate. */
        if (n != NULL) {
            ngx_queue_remove(&n->queue);
            ngx_rbtree_delete(&ctx->sh->rbtree, &n->node);
            ngx_slab_free_locked(ctx->shpool, n);
        }
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return;
    }

    if (n == NULL) {
        ngx_http_pgp_throttle_evict_stale(ctx, now, window, 8);

        size = offsetof(ngx_http_pgp_throttle_node_t, data) + ip.len;
        n = ngx_slab_alloc_locked(ctx->shpool, size);
        if (n == NULL) {
            ngx_http_pgp_throttle_evict_stale(ctx, now, window, 512);
            n = ngx_slab_alloc_locked(ctx->shpool, size);
            if (n == NULL) {
                /*
                 * Zone full: fail OPEN on this best-effort layer rather than
                 * denying logins because of it. Unlike the nonce store (where
                 * failing open would defeat replay protection entirely), this
                 * is an extra layer on top of limit_req; losing it under
                 * memory pressure degrades to "just limit_req", not to "no
                 * protection at all".
                 */
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                    "pgp_auth: failure-throttle zone full; skipping this "
                    "attempt's accounting (raise pgp_auth_failure_zone_size)");
                return;
            }
        }

        n->node.key = hash;
        n->len = (u_short) ip.len;
        ngx_memcpy(n->data, ip.data, ip.len);
        n->window_start = now;
        n->banned_until = 0;
        n->count = 0;

        ngx_rbtree_insert(&ctx->sh->rbtree, &n->node);
        ngx_queue_insert_head(&ctx->sh->queue, &n->queue);
    } else {
        ngx_queue_remove(&n->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &n->queue);
    }

    if (n->window_start + window <= now) {
        /* window elapsed: start counting fresh, but a still-active ban
         * (set from a previous window) is left alone until it expires */
        n->window_start = now;
        n->count = 0;
    }

    n->count++;

    if (n->count >= limit) {
        n->banned_until = now + ban_time;
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "pgp_auth_event: result=\"throttle_triggered\" ip=\"%V\" "
            "failures=%ui ban_seconds=%T", &ip, n->count, ban_time);
        return;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);
}


static ngx_int_t
ngx_http_pgp_throttle_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_pgp_throttle_ctx_t  *octx = data;
    ngx_http_pgp_throttle_ctx_t  *ctx = shm_zone->data;
    ngx_slab_pool_t              *shpool;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = shpool->data;
        ctx->shpool = shpool;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(shpool, sizeof(ngx_http_pgp_throttle_sh_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }
    shpool->data = ctx->sh;
    ctx->shpool = shpool;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_pgp_throttle_rbtree_insert);
    ngx_queue_init(&ctx->sh->queue);

    return NGX_OK;
}


ngx_shm_zone_t *
ngx_http_pgp_throttle_add_zone(ngx_conf_t *cf, size_t size)
{
    ngx_str_t                     name = ngx_string("pgp_auth_throttle");
    ngx_shm_zone_t               *zone;
    ngx_http_pgp_throttle_ctx_t  *ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_pgp_throttle_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_pgp_auth_module);
    if (zone == NULL) {
        return NULL;
    }

    if (zone->data) {
        return zone;    /* already declared (e.g. multiple locations) */
    }

    zone->init = ngx_http_pgp_throttle_init_zone;
    zone->data = ctx;

    return zone;
}
