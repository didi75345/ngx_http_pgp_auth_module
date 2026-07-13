/*
 * ngx_http_pgp_auth_nonce.c - single-use challenge tracking.
 *
 * "memory": a shared-memory rbtree keyed by the challenge nonce, with an LRU
 * queue for eviction and a per-entry expiry equal to the challenge lifetime.
 * "redis": SET <key> NX EX <ttl> against an external server (opt-in; works
 * across nodes). "none": no-op.
 */

#include "ngx_http_pgp_auth_nonce.h"

#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

extern ngx_module_t  ngx_http_pgp_auth_module;

#define NGX_HTTP_PGP_REDIS_TIMEOUT_MS  500


typedef struct {
    ngx_rbtree_node_t   node;      /* .key = crc32(nonce) */
    ngx_queue_t         queue;     /* LRU: newest at head, oldest at tail */
    time_t              expire;    /* challenge expiry (unix time)        */
    u_short             len;
    u_char              data[1];   /* nonce bytes                         */
} ngx_http_pgp_nonce_node_t;

typedef struct {
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         queue;
} ngx_http_pgp_nonce_sh_t;

typedef struct {
    ngx_http_pgp_nonce_sh_t  *sh;
    ngx_slab_pool_t          *shpool;
} ngx_http_pgp_nonce_ctx_t;


static void
ngx_http_pgp_nonce_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t         **p;
    ngx_http_pgp_nonce_node_t  *n, *nt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            n = (ngx_http_pgp_nonce_node_t *) node;
            nt = (ngx_http_pgp_nonce_node_t *) temp;

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


static ngx_http_pgp_nonce_node_t *
ngx_http_pgp_nonce_lookup(ngx_http_pgp_nonce_sh_t *sh, uint32_t hash,
    ngx_str_t *nonce)
{
    ngx_int_t                   rc;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_pgp_nonce_node_t  *n;

    node = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) { node = node->left;  continue; }
        if (hash > node->key) { node = node->right; continue; }

        /* hash == node->key */
        n = (ngx_http_pgp_nonce_node_t *) node;

        if (nonce->len != n->len) {
            node = (nonce->len < n->len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(nonce->data, n->data, n->len);
        if (rc == 0) {
            return n;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_http_pgp_nonce_evict_expired(ngx_http_pgp_nonce_ctx_t *ctx, time_t now,
    ngx_uint_t max)
{
    ngx_queue_t                *q;
    ngx_http_pgp_nonce_node_t  *n;

    while (max-- > 0 && !ngx_queue_empty(&ctx->sh->queue)) {
        q = ngx_queue_last(&ctx->sh->queue);          /* oldest */
        n = ngx_queue_data(q, ngx_http_pgp_nonce_node_t, queue);

        if (n->expire > now) {
            break;                                    /* nothing older expired */
        }

        ngx_queue_remove(q);
        ngx_rbtree_delete(&ctx->sh->rbtree, &n->node);
        ngx_slab_free_locked(ctx->shpool, n);
    }
}


static ngx_int_t
ngx_http_pgp_nonce_memory(ngx_http_request_t *r, ngx_shm_zone_t *zone,
    ngx_str_t *nonce, time_t exp)
{
    size_t                      size;
    uint32_t                    hash;
    time_t                      now;
    ngx_http_pgp_nonce_ctx_t   *ctx;
    ngx_http_pgp_nonce_node_t  *n;

    if (zone == NULL) {
        return NGX_ERROR;
    }
    ctx = zone->data;
    hash = ngx_crc32_short(nonce->data, nonce->len);
    now = ngx_time();

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_pgp_nonce_evict_expired(ctx, now, 8);

    if (ngx_http_pgp_nonce_lookup(ctx->sh, hash, nonce) != NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_DECLINED;                          /* replay */
    }

    size = offsetof(ngx_http_pgp_nonce_node_t, data) + nonce->len;

    n = ngx_slab_alloc_locked(ctx->shpool, size);
    if (n == NULL) {
        /* zone full: drop the oldest entries and retry once */
        ngx_http_pgp_nonce_evict_expired(ctx, now + 0x7fffffff, 32);
        n = ngx_slab_alloc_locked(ctx->shpool, size);
        if (n == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "pgp_auth: nonce zone full");
            return NGX_ERROR;
        }
    }

    n->node.key = hash;
    n->expire = exp;
    n->len = (u_short) nonce->len;
    ngx_memcpy(n->data, nonce->data, nonce->len);

    ngx_rbtree_insert(&ctx->sh->rbtree, &n->node);
    ngx_queue_insert_head(&ctx->sh->queue, &n->queue);

    ngx_shmtx_unlock(&ctx->shpool->mutex);
    return NGX_OK;
}


static ngx_int_t
ngx_http_pgp_nonce_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_pgp_nonce_ctx_t  *octx = data;
    ngx_http_pgp_nonce_ctx_t  *ctx = shm_zone->data;
    ngx_slab_pool_t           *shpool;

    if (octx) {                                       /* reload: reuse */
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

    ctx->sh = ngx_slab_alloc(shpool, sizeof(ngx_http_pgp_nonce_sh_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }
    shpool->data = ctx->sh;
    ctx->shpool = shpool;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_pgp_nonce_rbtree_insert);
    ngx_queue_init(&ctx->sh->queue);

    return NGX_OK;
}


ngx_shm_zone_t *
ngx_http_pgp_nonce_add_zone(ngx_conf_t *cf, size_t size)
{
    ngx_str_t                  name = ngx_string("pgp_auth_nonce");
    ngx_shm_zone_t            *zone;
    ngx_http_pgp_nonce_ctx_t  *ctx;

    zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_pgp_auth_module);
    if (zone == NULL) {
        return NULL;
    }

    if (zone->data != NULL) {
        return zone;                                  /* already registered */
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_pgp_nonce_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    zone->init = ngx_http_pgp_nonce_init_zone;
    zone->data = ctx;

    return zone;
}


/* --- redis backend: SET <key> 1 NX EX <ttl> --------------------------------
 * A deliberately small blocking client, bounded by a timeout, for the opt-in
 * "redis" backend (multi-node). Not on the hot path -- only at login.
 */

static int
ngx_http_pgp_nonce_wait(int fd, short ev, int timeout_ms)
{
    struct pollfd  p = { fd, ev, 0 };
    int            rc;

    do {
        rc = poll(&p, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);

    return rc;                                         /* >0 ready, 0 timeout */
}


/*
 * Send one RESP command and read one reply into `reply` (NUL-terminated).
 * Returns the number of bytes read (>0) or -1 on error/timeout/closed.
 */
static ssize_t
ngx_http_pgp_nonce_redis_roundtrip(int fd, const char *cmd, size_t cmdlen,
    char *reply, size_t replysz)
{
    size_t   k;
    ssize_t  w;

    for (k = 0; k < cmdlen; ) {
        if (ngx_http_pgp_nonce_wait(fd, POLLOUT,
                                    NGX_HTTP_PGP_REDIS_TIMEOUT_MS) <= 0)
        {
            return -1;
        }
        w = send(fd, cmd + k, cmdlen - k, MSG_NOSIGNAL);
        if (w <= 0) {
            return -1;
        }
        k += (size_t) w;
    }

    if (ngx_http_pgp_nonce_wait(fd, POLLIN, NGX_HTTP_PGP_REDIS_TIMEOUT_MS)
        <= 0)
    {
        return -1;
    }
    w = recv(fd, reply, replysz - 1, 0);
    if (w <= 0) {
        return -1;
    }
    reply[w] = '\0';
    return w;
}


static ngx_int_t
ngx_http_pgp_nonce_redis(ngx_http_request_t *r, ngx_str_t *addr,
    ngx_str_t *password, ngx_str_t *nonce, time_t exp)
{
    int               fd = -1, err;
    long              ttl;
    size_t            ttl_len;
    socklen_t         elen;
    ssize_t           k;
    size_t            off;
    char              host[256], *colon, buf[512], reply[128], ttlbuf[24];
    struct addrinfo   hints, *ai = NULL, *rp;

    ttl = (long) (exp - ngx_time());
    if (ttl <= 0) {
        return NGX_DECLINED;                           /* already expired */
    }
    ttl_len = (size_t) (ngx_sprintf((u_char *) ttlbuf, "%l", ttl)
                        - (u_char *) ttlbuf);

    if (addr->len == 0 || addr->len >= sizeof(host)) {
        return NGX_ERROR;
    }
    ngx_memcpy(host, addr->data, addr->len);
    host[addr->len] = '\0';
    colon = strrchr(host, ':');
    if (colon == NULL) {
        return NGX_ERROR;
    }
    *colon = '\0';

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, colon + 1, &hints, &ai) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "pgp_auth: redis getaddrinfo(%s) failed", host);
        return NGX_ERROR;
    }

    for (rp = ai; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, 0);
        if (fd == -1) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        if (errno == EINPROGRESS
            && ngx_http_pgp_nonce_wait(fd, POLLOUT,
                                       NGX_HTTP_PGP_REDIS_TIMEOUT_MS) > 0)
        {
            elen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0
                && err == 0)
            {
                break;
            }
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(ai);

    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "pgp_auth: redis connect failed");
        return NGX_ERROR;
    }

    /*
     * Authenticate first if a password is configured. A misconfigured or
     * rejected AUTH must not fall through to an unauthenticated SET -- fail
     * closed on anything other than a clean "+OK".
     */
    if (password->len) {
        off = (size_t) (ngx_snprintf((u_char *) buf, sizeof(buf),
            "*2\r\n$4\r\nAUTH\r\n$%uz\r\n%V\r\n",
            password->len, password) - (u_char *) buf);

        k = ngx_http_pgp_nonce_redis_roundtrip(fd, buf, off, reply,
                                               sizeof(reply));
        if (k <= 0 || reply[0] != '+') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "pgp_auth: redis AUTH failed");
            close(fd);
            return NGX_ERROR;
        }
    }

    /* RESP: SET pgp:<nonce> 1 NX EX <ttl> */
    off = (size_t) (ngx_snprintf((u_char *) buf, sizeof(buf),
        "*6\r\n$3\r\nSET\r\n$%uz\r\npgp:%V\r\n$1\r\n1\r\n"
        "$2\r\nNX\r\n$2\r\nEX\r\n$%uz\r\n%*s\r\n",
        (size_t) (nonce->len + 4), nonce,
        ttl_len, ttl_len, ttlbuf) - (u_char *) buf);

    k = ngx_http_pgp_nonce_redis_roundtrip(fd, buf, off, reply, sizeof(reply));
    close(fd);
    if (k <= 0) {
        return NGX_ERROR;
    }

    /* +OK => first use; $-1 / _ (nil) => key existed => replay */
    if (reply[0] == '+') {
        return NGX_OK;
    }
    if (reply[0] == '$' || reply[0] == '_' || reply[0] == '-') {
        return NGX_DECLINED;
    }
    return NGX_ERROR;
}


ngx_int_t
ngx_http_pgp_nonce_check_and_set(ngx_http_request_t *r, ngx_uint_t storage,
    ngx_shm_zone_t *zone, ngx_str_t *addr, ngx_str_t *password,
    ngx_str_t *nonce, time_t exp)
{
    switch (storage) {

    case NGX_HTTP_PGP_NONCE_MEMORY:
        return ngx_http_pgp_nonce_memory(r, zone, nonce, exp);

    case NGX_HTTP_PGP_NONCE_REDIS:
        return ngx_http_pgp_nonce_redis(r, addr, password, nonce, exp);

    default:                                           /* NONE */
        return NGX_OK;
    }
}
