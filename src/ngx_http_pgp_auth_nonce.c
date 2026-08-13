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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

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
ngx_http_pgp_nonce_memory(ngx_http_pgp_verify_result_t *vr,
    ngx_shm_zone_t *zone,
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

    /*
     * n->len is a u_short. The issued nonce is 32 hex chars so this cannot
     * trigger today, but guard it explicitly: if the nonce format ever grows
     * past 65535 the silent truncation would corrupt comparisons rather than
     * fail visibly.
     */
    if (nonce->len > 65535) {
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
        /*
         * Zone full. Try harder to reclaim entries that have GENUINELY
         * expired -- but never evict a live one. Dropping a nonce that is
         * still inside its challenge window would let that challenge be
         * replayed, which is the exact thing this store exists to prevent;
         * an eviction pass with an artificial "everything is expired" cutoff
         * would silently turn this into a fail-OPEN store under load. If
         * nothing has really expired, deny the login instead.
         */
        ngx_http_pgp_nonce_evict_expired(ctx, now, 512);
        n = ngx_slab_alloc_locked(ctx->shpool, size);
        if (n == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                          "pgp_auth: nonce zone full with no expired entries to "
                          "reclaim; denying login (raise pgp_auth_nonce_zone_size, "
                          "or use pgp_auth_nonce_storage redis)");
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
 * Establish TLS on an already-connected (non-blocking) socket.
 *
 * `host` is the numeric IP we dialled. Because the address must be numeric
 * (see the AI_NUMERICHOST note below), certificate identity cannot be checked
 * against a DNS name unless the operator tells us which name to expect --
 * that is what pgp_auth_nonce_storage_tls_name is for. With a name we send SNI
 * and verify against it; without one we verify against the IP, which requires
 * the certificate to carry an iPAddress SAN.
 *
 * Returns the SSL* (caller frees it and *ctx_out) or NULL on failure.
 */
static SSL *
ngx_http_pgp_nonce_tls(ngx_http_pgp_verify_result_t *vr, int fd, const char *host,
    ngx_flag_t verify, ngx_str_t *ca, ngx_str_t *name, SSL_CTX **ctx_out)
{
    int                 rc;
    char                buf[512];
    SSL                *ssl;
    SSL_CTX            *ctx;
    X509_VERIFY_PARAM  *param;

    *ctx_out = NULL;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return NULL;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (verify) {
        if (ca->len) {
            if (ca->len >= sizeof(buf)) {
                goto failed;
            }
            ngx_memcpy(buf, ca->data, ca->len);
            buf[ca->len] = '\0';
            if (SSL_CTX_load_verify_locations(ctx, buf, NULL) != 1) {
                ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                              "pgp_auth: redis TLS: cannot load CA \"%V\"", ca);
                goto failed;
            }
        } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            goto failed;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto failed;
    }
    if (SSL_set_fd(ssl, fd) != 1) {
        SSL_free(ssl);
        goto failed;
    }

    if (name->len && name->len < sizeof(buf)) {
        ngx_memcpy(buf, name->data, name->len);
        buf[name->len] = '\0';
        SSL_set_tlsext_host_name(ssl, buf);          /* SNI: real hostname */
    }

    if (verify) {
        param = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set_hostflags(param,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (name->len && name->len < sizeof(buf)) {
            rc = X509_VERIFY_PARAM_set1_host(param, buf, 0);
        } else {
            rc = X509_VERIFY_PARAM_set1_ip_asc(param, host);
        }
        if (rc != 1) {
            SSL_free(ssl);
            goto failed;
        }
    }

    for ( ;; ) {
        rc = SSL_connect(ssl);
        if (rc == 1) {
            break;
        }
        rc = SSL_get_error(ssl, rc);
        if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
            if (ngx_http_pgp_nonce_wait(fd,
                    (rc == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT,
                    NGX_HTTP_PGP_REDIS_TIMEOUT_MS) > 0)
            {
                continue;
            }
        }
        ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                      "pgp_auth: redis TLS handshake failed "
                      "(verify=%d, cert must match %s)",
                      (int) verify, name->len ? "the configured tls_name"
                                              : "the IP address");
        SSL_free(ssl);
        goto failed;
    }

    *ctx_out = ctx;
    return ssl;

failed:

    SSL_CTX_free(ctx);
    return NULL;
}


/*
 * Send one RESP command and read one reply into `reply` (NUL-terminated).
 * Uses TLS when `ssl` is non-NULL, the plain socket otherwise.
 * Returns the number of bytes read (>0) or -1 on error/timeout/closed.
 */
static ssize_t
ngx_http_pgp_nonce_redis_roundtrip(int fd, SSL *ssl, const char *cmd,
    size_t cmdlen, char *reply, size_t replysz)
{
    int      e;
    size_t   k;
    ssize_t  w;

    for (k = 0; k < cmdlen; ) {
        if (ssl == NULL) {
            if (ngx_http_pgp_nonce_wait(fd, POLLOUT,
                                        NGX_HTTP_PGP_REDIS_TIMEOUT_MS) <= 0)
            {
                return -1;
            }
            w = send(fd, cmd + k, cmdlen - k, MSG_NOSIGNAL);

        } else {
            w = SSL_write(ssl, cmd + k, (int) (cmdlen - k));
            if (w <= 0) {
                e = SSL_get_error(ssl, (int) w);
                if ((e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                    && ngx_http_pgp_nonce_wait(fd,
                           (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT,
                           NGX_HTTP_PGP_REDIS_TIMEOUT_MS) > 0)
                {
                    continue;
                }
                return -1;
            }
        }

        if (w <= 0) {
            return -1;
        }
        k += (size_t) w;
    }

    for ( ;; ) {
        if (ssl == NULL) {
            if (ngx_http_pgp_nonce_wait(fd, POLLIN,
                                        NGX_HTTP_PGP_REDIS_TIMEOUT_MS) <= 0)
            {
                return -1;
            }
            w = recv(fd, reply, replysz - 1, 0);

        } else {
            w = SSL_read(ssl, reply, (int) (replysz - 1));
            if (w <= 0) {
                e = SSL_get_error(ssl, (int) w);
                if ((e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                    && ngx_http_pgp_nonce_wait(fd,
                           (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT,
                           NGX_HTTP_PGP_REDIS_TIMEOUT_MS) > 0)
                {
                    continue;
                }
                return -1;
            }
        }
        break;
    }

    if (w <= 0) {
        return -1;
    }
    reply[w] = '\0';
    return w;
}


static ngx_int_t
ngx_http_pgp_nonce_redis(ngx_http_pgp_verify_result_t *vr, ngx_http_pgp_nonce_conf_t *nc,
    ngx_str_t *nonce, time_t exp)
{
    int               fd = -1, err;
    long              ttl;
    size_t            ttl_len;
    socklen_t         elen;
    ssize_t           k;
    size_t            off;
    char              host[256], *colon, buf[512], reply[128], ttlbuf[24];
    ngx_int_t         rc = NGX_ERROR;
    SSL              *ssl = NULL;
    SSL_CTX          *ssl_ctx = NULL;
    ngx_str_t        *addr = &nc->addr;
    ngx_str_t        *password = &nc->password;
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

    /*
     * AI_NUMERICHOST|AI_NUMERICSERV: parse the address as a literal IP and
     * port only -- never consult DNS. getaddrinfo() is otherwise a *blocking*
     * call with no timeout, run inside the nginx worker on an unauthenticated
     * login path: a hostname whose DNS is slow or unreachable would hang the
     * worker for the system resolver's timeout, uncovered by the per-op poll
     * deadlines below or by limit_req. So pgp_auth_nonce_storage_address must
     * be a numeric host:port (e.g. 10.0.0.5:6379); resolution is instant.
     */
    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    if (getaddrinfo(host, colon + 1, &hints, &ai) != 0) {
        ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                      "pgp_auth: redis address \"%s\" is not a numeric host:port "
                      "(hostnames are not supported; use an IP)", host);
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
        ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                      "pgp_auth: redis connect failed");
        /*
         * Could not reach Redis at all (refused/timeout/partition, or this
         * worker being out of file descriptors) -- a genuine outage. Kept
         * distinct from NGX_ERROR (reachable but erroring: AUTH rejected, TLS
         * error, protocol error, error reply) so the two can be told apart in
         * the log and by an operator. BOTH fail closed at the caller: neither
         * can speak for the fleet, and the per-node store must never be
         * substituted for one that can.
         */
        return NGX_ABORT;
    }

    /*
     * Wrap the connection in TLS before anything is sent -- the AUTH password
     * and the nonce must never cross the network in clear when TLS is enabled.
     */
    if (nc->tls) {
        ssl = ngx_http_pgp_nonce_tls(vr, fd, host, nc->tls_verify, &nc->tls_ca,
                                     &nc->tls_name, &ssl_ctx);
        if (ssl == NULL) {
            close(fd);
            return NGX_ERROR;
        }
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

        k = ngx_http_pgp_nonce_redis_roundtrip(fd, ssl, buf, off, reply,
                                               sizeof(reply));
        if (k <= 0 || reply[0] != '+') {
            ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                          "pgp_auth: redis AUTH failed");
            goto done;
        }
    }

    /*
     * RESP: SET <prefix><nonce> 1 NX EX <ttl>
     *
     * The prefix is configurable (pgp_auth_nonce_storage_key_prefix) so two
     * deployments can share one Redis without sharing a keyspace -- otherwise
     * anything else able to write that instance can delete this module's keys
     * and defeat single-use, or pre-create them and deny logins.
     */
    off = (size_t) (ngx_snprintf((u_char *) buf, sizeof(buf),
        "*6\r\n$3\r\nSET\r\n$%uz\r\n%V%V\r\n$1\r\n1\r\n"
        "$2\r\nNX\r\n$2\r\nEX\r\n$%uz\r\n%*s\r\n",
        (size_t) (nc->key_prefix.len + nonce->len), &nc->key_prefix, nonce,
        ttl_len, ttl_len, ttlbuf) - (u_char *) buf);

    k = ngx_http_pgp_nonce_redis_roundtrip(fd, ssl, buf, off, reply,
                                           sizeof(reply));
    if (k <= 0) {
        goto done;
    }

    /*
     * +OK               => SET succeeded, first use of this nonce => allow.
     * $-1 (RESP2 nil) /
     * _   (RESP3 null)  => NX found the key => nonce already used => replay.
     * -...              => a Redis ERROR reply (-NOAUTH, -LOADING, -OOM, ...).
     *                      This is an operational failure, NOT a replay: report
     *                      it as an error so it is logged as such and denied
     *                      deliberately (fail closed), rather than being
     *                      mislabelled "challenge already used" in the log,
     *                      which would send an operator hunting the wrong thing
     *                      during a Redis outage.
     */
    if (reply[0] == '+') {
        rc = NGX_OK;

    } else if (reply[0] == '$' || reply[0] == '_') {
        rc = NGX_DECLINED;

    } else if (reply[0] == '-') {
        ngx_http_pgp_defer_diag(vr, NGX_LOG_ERR,
                      "pgp_auth: redis error reply: %s", reply);
    }

done:

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
    }
    close(fd);
    return rc;
}


ngx_int_t
ngx_http_pgp_nonce_check_and_set(ngx_http_pgp_verify_result_t *vr,
    ngx_http_pgp_nonce_conf_t *nc, ngx_str_t *nonce, time_t exp)
{
    ngx_int_t  redis_rc;

    switch (nc->storage) {

    case NGX_HTTP_PGP_NONCE_MEMORY:
        return ngx_http_pgp_nonce_memory(vr, nc->zone, nonce, exp);

    case NGX_HTTP_PGP_NONCE_REDIS:
        /*
         * Cross-node single-use via Redis. The nonce is recorded in BOTH stores:
         * Redis holds the fleet-wide view, and the per-node shared-memory zone
         * is a REJECT-ONLY second line -- it can turn a login down on its own,
         * it can never wave one through.
         *
         * That asymmetry is the whole point. A local "I have not seen this"
         * says nothing about the other nodes, because each node's zone is
         * private (ngx_shared_memory_add, one zone per instance); granting on
         * it during a Redis outage would hand one captured signed response a
         * session on every node in the fleet -- the exact fleet-wide single-use
         * guarantee the operator selected this backend to get. A local "I have
         * seen this" is a fact about a nonce that was definitely used once, and
         * stays true no matter what Redis says -- which is what still covers a
         * Redis that came back up empty after a restart, a flush, or an eviction.
         *
         * Precedence:
         *   1. this node has already seen the nonce      -> replay, deny now
         *   2. Redis answers (fresh / already-used)      -> that verdict wins
         *   3. Redis cannot answer, for any reason       -> fail closed
         *
         * Case 3 covers an unreachable Redis (NGX_ABORT) exactly as it covers a
         * reachable-but-erroring one (NGX_ERROR): a store that cannot speak for
         * the fleet must not be substituted with one that can only speak for
         * this node. An outage therefore denies new logins rather than
         * degrading the guarantee -- deliberately trading availability for
         * integrity. An operator who wants the opposite trade already has
         * `pgp_auth_nonce_storage memory`, which states per-node enforcement
         * honestly instead of pretending to a fleet-wide one it cannot keep.
         */
        if (nc->zone != NULL
            && ngx_http_pgp_nonce_memory(vr, nc->zone, nonce, exp)
               == NGX_DECLINED)
        {
            return NGX_DECLINED;                   /* this node already saw it */
        }

        redis_rc = ngx_http_pgp_nonce_redis(vr, nc, nonce, exp);
        if (redis_rc == NGX_OK || redis_rc == NGX_DECLINED) {
            return redis_rc;                       /* Redis gave a fleet verdict */
        }

        /*
         * NGX_ABORT (unreachable: connect refused/timeout/partition, or the
         * worker being out of file descriptors) or NGX_ERROR (reachable but
         * errored: AUTH rejected, TLS/protocol failure, error reply). Neither
         * yields a fleet-wide answer, so neither may grant.
         */
        return NGX_ERROR;

    default:                                           /* NONE */
        return NGX_OK;
    }
}
