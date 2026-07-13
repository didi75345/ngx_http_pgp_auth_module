/*
 * ngx_http_pgp_auth_module.c
 *
 * PGP-signature authentication for nginx, as a drop-in alternative to
 * auth_basic. A protected location issues a one-time challenge; the user
 * clear-signs it with their own tooling (e.g. Kleopatra -> Notepad -> Sign)
 * and pastes the result back. The module verifies the signature against a
 * public keyring and grants a session.
 *
 * Design goals:
 *   - Fully stateless: nothing is stored server-side, so it runs unchanged
 *     across multiple nginx containers that share only a secret.
 *   - Minimal dependencies: HMAC via OpenSSL (already linked by nginx),
 *     signature verification via the system gpg binary.
 *
 * Statelessness is achieved by HMAC-signing both artifacts:
 *   challenge = v1|<exp>|<nonce>|<mac>      mac = HMAC(secret, "v1|exp|nonce")
 *   session   = <exp>|<fpr>|<mac>           mac = HMAC(secret, "exp|fpr")
 * The server re-derives each MAC to recognise its own tokens; no lookup table.
 *
 * Licensed under the MIT License.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>     /* nginx_version, for the cookie-API compatibility shim */

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "ngx_http_pgp_auth_gpg.h"
#include "ngx_http_pgp_auth_nonce.h"


#define NGX_HTTP_PGP_COOKIE       "pgp_session"
#define NGX_HTTP_PGP_COOKIE_HOST  "__Host-pgp_session"
#define NGX_HTTP_PGP_AUTH_ARG     "__pgp_auth"
#define NGX_HTTP_PGP_FIELD        "signed"
#define NGX_HTTP_PGP_NONCE_LEN    16          /* raw bytes -> 32 hex chars */
#define NGX_HTTP_PGP_NONCE_ZONE_SIZE  (8 * 1024 * 1024)


typedef struct {
    ngx_flag_t   enable;
    ngx_str_t    keyring;
    time_t       challenge_timeout;   /* seconds a challenge stays valid    */
    time_t       session_timeout;     /* seconds; 0 == unlimited            */
    ngx_flag_t   cookie_secure;       /* add "; Secure" to the cookie       */
    ngx_flag_t   cookie_host_prefix;  /* use the __Host- cookie name prefix */
    ngx_uint_t   cookie_samesite;     /* SameSite: 0=Lax 1=Strict 2=None    */
    ngx_flag_t   bind_ip;             /* mix client IP into the HMAC        */
    ngx_flag_t   bind_ua;             /* mix User-Agent into the HMAC       */
    ngx_uint_t   nonce_storage;       /* none | memory | redis              */
    ngx_shm_zone_t *nonce_zone;       /* shared zone for the memory backend */
    ngx_str_t    nonce_addr;          /* redis host:port                    */
    ngx_str_t    revocation_list;     /* path: revoked key fingerprints     */
    ngx_flag_t   revoc_fail_open;     /* on error, allow (1) or deny (0)    */
    time_t       revoc_mtime;         /* cached file mtime (per worker)     */
    ngx_str_t    revoc_cache;         /* cached file contents (per worker)  */
    ngx_msec_t   gpg_timeout;         /* max ms for one gpg verify          */
    size_t       max_body_size;       /* cap on the submitted auth body     */
    ngx_str_t    secret_file;
    ngx_str_t    secret;              /* loaded HMAC secret bytes           */
} ngx_http_pgp_auth_loc_conf_t;


static ngx_conf_enum_t  ngx_http_pgp_nonce_storage_enum[] = {
    { ngx_string("none"),   NGX_HTTP_PGP_NONCE_NONE },
    { ngx_string("memory"), NGX_HTTP_PGP_NONCE_MEMORY },
    { ngx_string("redis"),  NGX_HTTP_PGP_NONCE_REDIS },
    { ngx_null_string, 0 }
};

/* SameSite attribute for the session cookie; index into ngx_http_pgp_samesite */
#define NGX_HTTP_PGP_SAMESITE_LAX     0
#define NGX_HTTP_PGP_SAMESITE_STRICT  1
#define NGX_HTTP_PGP_SAMESITE_NONE    2

static ngx_conf_enum_t  ngx_http_pgp_samesite_enum[] = {
    { ngx_string("Lax"),    NGX_HTTP_PGP_SAMESITE_LAX },
    { ngx_string("Strict"), NGX_HTTP_PGP_SAMESITE_STRICT },
    { ngx_string("None"),   NGX_HTTP_PGP_SAMESITE_NONE },
    { ngx_null_string, 0 }
};

static const char *ngx_http_pgp_samesite[] = { "Lax", "Strict", "None" };


static ngx_int_t ngx_http_pgp_auth_handler(ngx_http_request_t *r);
static void ngx_http_pgp_auth_submit(ngx_http_request_t *r);

static ngx_int_t ngx_http_pgp_hmac_hex(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, u_char *data, size_t len,
    ngx_str_t *out);
static ngx_int_t ngx_http_pgp_ct_eq(ngx_str_t *a, ngx_str_t *b);

static ngx_int_t ngx_http_pgp_check_session(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf);
static ngx_int_t ngx_http_pgp_verify_challenge(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, u_char *msg, size_t len);
static ngx_int_t ngx_http_pgp_send_challenge(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, ngx_uint_t failed);
static ngx_int_t ngx_http_pgp_grant(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, ngx_str_t *fpr);

static void *ngx_http_pgp_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_pgp_auth_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_pgp_auth_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_pgp_auth_commands[] = {

    { ngx_string("pgp_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, enable),
      NULL },

    { ngx_string("pgp_keyring"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, keyring),
      NULL },

    { ngx_string("pgp_challenge_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, challenge_timeout),
      NULL },

    { ngx_string("pgp_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, session_timeout),
      NULL },

    { ngx_string("pgp_session_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, secret_file),
      NULL },

    { ngx_string("pgp_session_cookie_secure"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, cookie_secure),
      NULL },

    { ngx_string("pgp_session_cookie_host_prefix"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, cookie_host_prefix),
      NULL },

    { ngx_string("pgp_session_cookie_samesite"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, cookie_samesite),
      &ngx_http_pgp_samesite_enum },

    { ngx_string("pgp_auth_bind_client_ip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, bind_ip),
      NULL },

    { ngx_string("pgp_auth_bind_user_agent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, bind_ua),
      NULL },

    { ngx_string("pgp_auth_nonce_storage"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, nonce_storage),
      &ngx_http_pgp_nonce_storage_enum },

    { ngx_string("pgp_auth_nonce_storage_address"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, nonce_addr),
      NULL },

    { ngx_string("pgp_revocation_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, revocation_list),
      NULL },

    { ngx_string("pgp_revocation_fail_open"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, revoc_fail_open),
      NULL },

    { ngx_string("pgp_gpg_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, gpg_timeout),
      NULL },

    { ngx_string("pgp_auth_max_body_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_pgp_auth_loc_conf_t, max_body_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_pgp_auth_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_pgp_auth_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_pgp_auth_create_loc_conf,     /* create location configuration */
    ngx_http_pgp_auth_merge_loc_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_pgp_auth_module = {
    NGX_MODULE_V1,
    &ngx_http_pgp_auth_module_ctx,         /* module context */
    ngx_http_pgp_auth_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/*
 * HMAC-SHA256(secret, data [|| client binding]) hex-encoded into out.
 *
 * When pgp_auth_bind_client_ip / pgp_auth_bind_user_agent are on, the client's
 * IP and/or User-Agent are folded into the MAC input. Because the same request
 * attributes are present when a challenge is issued and when it (or a session)
 * is verified, a token lifted to a different client no longer validates -- it
 * blocks cross-client replay of both challenges and session cookies. The bound
 * values are NOT carried in the token; they are re-derived from the request.
 *
 * NOTE: behind a reverse proxy the client IP nginx sees is the proxy's unless
 * ngx_http_realip_module is configured; see SECURITY.md.
 */
static ngx_int_t
ngx_http_pgp_hmac_hex(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, u_char *data, size_t len,
    ngx_str_t *out)
{
    unsigned int   mdlen;
    unsigned char  md[EVP_MAX_MD_SIZE];
    ngx_str_t      ip, ua;
    u_char        *buf, *b;
    size_t         total;

    ngx_str_null(&ip);
    ngx_str_null(&ua);

    if (plcf->bind_ip) {
        ip = r->connection->addr_text;
    }
    if (plcf->bind_ua && r->headers_in.user_agent != NULL) {
        ua = r->headers_in.user_agent->value;
    }

    if (ip.len == 0 && ua.len == 0) {
        if (HMAC(EVP_sha256(), plcf->secret.data, (int) plcf->secret.len,
                 data, len, md, &mdlen) == NULL)
        {
            return NGX_ERROR;
        }
    } else {
        /* data || 0x1e || ip || 0x1e || ua */
        total = len + 1 + ip.len + 1 + ua.len;
        buf = ngx_pnalloc(r->pool, total);
        if (buf == NULL) {
            return NGX_ERROR;
        }
        b = ngx_cpymem(buf, data, len);
        *b++ = 0x1e;
        b = ngx_cpymem(b, ip.data, ip.len);
        *b++ = 0x1e;
        ngx_memcpy(b, ua.data, ua.len);

        if (HMAC(EVP_sha256(), plcf->secret.data, (int) plcf->secret.len,
                 buf, total, md, &mdlen) == NULL)
        {
            return NGX_ERROR;
        }
    }

    out->data = ngx_pnalloc(r->pool, mdlen * 2);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(out->data, md, mdlen);
    out->len = mdlen * 2;

    return NGX_OK;
}


/*
 * Compare a revocation-list entry [a, ae) against a fingerprint, ignoring
 * ASCII whitespace in the entry and case on both sides. This tolerates the
 * spaced, mixed-case form that `gpg --fingerprint` prints (e.g. "ABCD 1234
 * ...") so a mere formatting difference cannot silently defeat revocation.
 */
static ngx_int_t
ngx_http_pgp_fpr_eq(u_char *a, u_char *ae, ngx_str_t *fpr)
{
    u_char  *b, *be;

    b = fpr->data;
    be = fpr->data + fpr->len;

    while (a < ae) {
        if (*a == ' ' || *a == '\t') { a++; continue; }
        if (b == be) { return 0; }                  /* entry longer than fpr */
        if (ngx_tolower(*a) != ngx_tolower(*b)) { return 0; }
        a++;
        b++;
    }
    return (b == be) ? 1 : 0;                        /* all fpr chars matched */
}


/*
 * Is `fpr` listed in the revocation file? The file holds one key fingerprint
 * per line (# comments and blank lines ignored); case-insensitive. The file is
 * re-read only when its mtime changes, so an operator can revoke a key (or all
 * of that key's live sessions -- the session cookie carries the fpr) simply by
 * appending to the file, with no nginx reload. Cache is per worker.
 */
static ngx_int_t
ngx_http_pgp_is_revoked(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, ngx_str_t *fpr)
{
    u_char           *buf, *line, *nl, *end, *s, *e;
    ssize_t           n;
    size_t            sz;
    ngx_int_t         deny;
    ngx_fd_t          fd;
    ngx_file_info_t   fi;

    if (plcf->revocation_list.len == 0 || fpr->len == 0) {
        return 0;
    }

    /*
     * A configured-but-unreadable revocation list must not silently disable
     * revocation. Fail closed (deny) unless pgp_revocation_fail_open is set.
     */
    deny = plcf->revoc_fail_open ? 0 : 1;

    if (ngx_file_info(plcf->revocation_list.data, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "pgp_auth: cannot stat revocation list \"%V\"%s",
                      &plcf->revocation_list, deny ? " (failing closed)" : "");
        return deny;
    }

    /* (re)load only when the file changed */
    if (plcf->revoc_cache.data == NULL
        || ngx_file_mtime(&fi) != plcf->revoc_mtime)
    {
        fd = ngx_open_file(plcf->revocation_list.data, NGX_FILE_RDONLY,
                           NGX_FILE_OPEN, 0);
        if (fd == NGX_INVALID_FILE) {
            return deny;
        }
        sz = (size_t) ngx_file_size(&fi);
        buf = ngx_alloc(sz + 1, r->connection->log);
        if (buf == NULL) {
            ngx_close_file(fd);
            return deny;
        }
        n = ngx_read_fd(fd, buf, sz);
        ngx_close_file(fd);
        if (n < 0) {
            ngx_free(buf);
            return deny;
        }
        buf[n] = '\0';

        if (plcf->revoc_cache.data != NULL) {
            ngx_free(plcf->revoc_cache.data);
        }
        plcf->revoc_cache.data = buf;
        plcf->revoc_cache.len = (size_t) n;
        plcf->revoc_mtime = ngx_file_mtime(&fi);
    }

    /* scan lines, trim, skip comments, compare case-insensitively */
    line = plcf->revoc_cache.data;
    end = line + plcf->revoc_cache.len;

    while (line < end) {
        nl = ngx_strlchr(line, end, '\n');
        if (nl == NULL) {
            nl = end;
        }
        s = line;
        e = nl;
        while (s < e && (*s == ' ' || *s == '\t')) { s++; }
        while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) { e--; }

        if (s < e && *s != '#'
            && ngx_http_pgp_fpr_eq(s, e, fpr))
        {
            return 1;
        }
        line = nl + 1;
    }

    return 0;
}


/* Constant-time equality for equal-length strings. */
static ngx_int_t
ngx_http_pgp_ct_eq(ngx_str_t *a, ngx_str_t *b)
{
    if (a->len != b->len) {
        return 0;
    }
    return CRYPTO_memcmp(a->data, b->data, a->len) == 0 ? 1 : 0;
}


/*
 * Session cookie name: __Host-prefixed when pgp_session_cookie_host_prefix is on
 * AND the cookie is Secure. The __Host- prefix *requires* Secure (browsers drop
 * a __Host- cookie sent without it), so with pgp_session_cookie_secure off the
 * prefix is not applied -- otherwise the cookie would be rejected and login
 * would loop. The merge step warns when this happens.
 */
static void
ngx_http_pgp_cookie_name(ngx_http_pgp_auth_loc_conf_t *plcf, ngx_str_t *name)
{
    if (plcf->cookie_host_prefix && plcf->cookie_secure) {
        ngx_str_set(name, NGX_HTTP_PGP_COOKIE_HOST);
    } else {
        ngx_str_set(name, NGX_HTTP_PGP_COOKIE);
    }
}


/*
 * Look up a cookie by name. nginx 1.23.0 changed cookie storage from an array
 * to a linked list and reworked ngx_http_parse_multi_header_lines(), so this
 * shim keeps the module building on both Debian Bookworm (1.22) and Trixie
 * (1.26). Returns NGX_OK and fills `value` if found.
 */
static ngx_int_t
ngx_http_pgp_get_cookie(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
#if (nginx_version >= 1023000)
    if (ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, name, value)
        == NULL)
    {
        return NGX_DECLINED;
    }
#else
    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, name, value)
        == NGX_DECLINED)
    {
        return NGX_DECLINED;
    }
#endif
    return NGX_OK;
}


/*
 * Validate the session cookie. Returns NGX_OK if a well-formed, unexpired
 * cookie signed with our secret is present, NGX_DECLINED otherwise.
 */
static ngx_int_t
ngx_http_pgp_check_session(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf)
{
    time_t       exp;
    u_char      *p, *last, *sep1, *sep2;
    ngx_str_t    cookie, name, payload, mac_have, mac_want;

    ngx_http_pgp_cookie_name(plcf, &name);

    if (ngx_http_pgp_get_cookie(r, &name, &cookie) != NGX_OK) {
        return NGX_DECLINED;
    }

    /* cookie = <exp>|<fpr>|<mac> */
    p = cookie.data;
    last = cookie.data + cookie.len;

    sep1 = ngx_strlchr(p, last, '|');
    if (sep1 == NULL) {
        return NGX_DECLINED;
    }
    sep2 = ngx_strlchr(sep1 + 1, last, '|');
    if (sep2 == NULL) {
        return NGX_DECLINED;
    }

    payload.data = p;
    payload.len = sep2 - p;                    /* "exp|fpr" */

    mac_have.data = sep2 + 1;
    mac_have.len = last - (sep2 + 1);

    if (ngx_http_pgp_hmac_hex(r, plcf, payload.data, payload.len,
                              &mac_want) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (!ngx_http_pgp_ct_eq(&mac_have, &mac_want)) {
        return NGX_DECLINED;
    }

    exp = ngx_atotm(p, sep1 - p);
    if (exp != 0 && exp < ngx_time()) {
        return NGX_DECLINED;                   /* expired */
    }

    /* revoked key -> revoke every session it holds (cookie carries the fpr) */
    payload.data = sep1 + 1;
    payload.len = sep2 - (sep1 + 1);           /* fpr */
    if (ngx_http_pgp_is_revoked(r, plcf, &payload)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: session key revoked");
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/*
 * Verify a submitted clear-signed message: it must contain a challenge that
 * we issued (valid HMAC, unexpired) and carry a good PGP signature from a key
 * in the keyring. On success, fpr receives the signing key fingerprint.
 */
static ngx_int_t
ngx_http_pgp_verify_challenge(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, u_char *msg, size_t len)
{
    time_t                          exp;
    u_char                         *p, *last, *line_end, *s1, *s2, *s3;
    ngx_str_t                       payload, mac_have, mac_want, fpr;
    ngx_http_pgp_verify_result_t    vr;

    /*
     * Verify the PGP signature FIRST, and from here on look at only the bytes
     * gpg actually verified (vr.plaintext) -- never the raw submitted body.
     * Otherwise an attacker could take any message signed by a keyring key and
     * append/prepend a genuine challenge outside the signed region.
     */
    /*
     * Cheap pre-filter: only fork gpg for something that at least looks like a
     * clear-signed block. Garbage submissions are rejected here, before the
     * (blocking) gpg process is ever spawned -- important given this endpoint
     * is unauthenticated. Pair with limit_req (see examples/nginx.conf).
     */
    if (ngx_strnstr(msg, "-----BEGIN PGP SIGNED MESSAGE-----", len) == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: submission is not a clear-signed message");
        return NGX_DECLINED;
    }

    if (ngx_http_pgp_gpg_verify(r->connection->log, &plcf->keyring, msg, len,
                                plcf->gpg_timeout, &vr) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (!vr.valid) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: signature not from a keyring key");
        return NGX_DECLINED;
    }

    fpr.data = vr.fpr;
    fpr.len = vr.fpr_len;
    if (ngx_http_pgp_is_revoked(r, plcf, &fpr)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: signing key is revoked");
        return NGX_DECLINED;
    }

    /* locate our challenge line ("v1|...") inside the SIGNED plaintext */
    last = vr.plaintext + vr.plaintext_len;
    for (p = vr.plaintext; p + 3 <= last; p++) {
        if (p[0] == 'v' && p[1] == '1' && p[2] == '|') {
            break;
        }
    }
    if (p + 3 > last) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: no challenge inside the signed content");
        return NGX_DECLINED;
    }

    line_end = ngx_strlchr(p, last, '\n');
    if (line_end == NULL) {
        line_end = last;
    }
    if (line_end > p && line_end[-1] == '\r') {
        line_end--;
    }

    /* split: v1 | exp | nonce | mac */
    s1 = ngx_strlchr(p, line_end, '|');                       /* after v1   */
    if (s1 == NULL) { return NGX_DECLINED; }
    s2 = ngx_strlchr(s1 + 1, line_end, '|');                  /* after exp  */
    if (s2 == NULL) { return NGX_DECLINED; }
    s3 = ngx_strlchr(s2 + 1, line_end, '|');                  /* after nonce*/
    if (s3 == NULL) { return NGX_DECLINED; }

    payload.data = p;
    payload.len = s3 - p;                                     /* v1|exp|nonce */

    mac_have.data = s3 + 1;
    mac_have.len = line_end - (s3 + 1);

    if (ngx_http_pgp_hmac_hex(r, plcf, payload.data, payload.len,
                              &mac_want) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (!ngx_http_pgp_ct_eq(&mac_have, &mac_want)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: challenge MAC mismatch");
        return NGX_DECLINED;
    }

    exp = ngx_atotm(s1 + 1, s2 - (s1 + 1));
    if (exp == NGX_ERROR || exp < ngx_time()) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: challenge expired");
        return NGX_DECLINED;
    }

    /*
     * Single-use enforcement: record this challenge's nonce and reject if it
     * was already used. Fails closed (rejects) if the backend errors, so a
     * misconfigured/unreachable store never silently disables replay defence.
     */
    {
        ngx_str_t  nonce;
        ngx_int_t  rc;

        nonce.data = s2 + 1;
        nonce.len = s3 - (s2 + 1);

        rc = ngx_http_pgp_nonce_check_and_set(r, plcf->nonce_storage,
                 plcf->nonce_zone, &plcf->nonce_addr, &nonce, exp);
        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "pgp_auth: challenge already used (replay)");
            return NGX_DECLINED;
        }
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "pgp_auth: nonce store error; rejecting");
            return NGX_DECLINED;
        }
    }

    fpr.data = vr.fpr;
    fpr.len = vr.fpr_len;
    return ngx_http_pgp_grant(r, plcf, &fpr);
}


/* Issue a session cookie and redirect back to the clean URL (302). */
static ngx_int_t
ngx_http_pgp_grant(ngx_http_request_t *r, ngx_http_pgp_auth_loc_conf_t *plcf,
    ngx_str_t *fpr)
{
    time_t            exp;
    u_char           *payload;
    size_t            plen;
    ngx_str_t         mac, name;
    ngx_table_elt_t  *set_cookie, *location;

    exp = (plcf->session_timeout == 0) ? 0 : ngx_time() + plcf->session_timeout;

    /* payload = "<exp>|<fpr>" */
    payload = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 1 + fpr->len);
    if (payload == NULL) {
        return NGX_ERROR;
    }
    plen = ngx_sprintf(payload, "%T|%V", exp, fpr) - payload;

    if (ngx_http_pgp_hmac_hex(r, plcf, payload, plen, &mac) != NGX_OK) {
        return NGX_ERROR;
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }
    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");

    ngx_http_pgp_cookie_name(plcf, &name);

    /*
     * Secure flag from pgp_session_cookie_secure (default on); cookie name may
     * carry the __Host- prefix. __Host- requires Secure + Path=/ + no Domain,
     * all of which hold whenever the prefixed name is chosen.
     */
    set_cookie->value.data = ngx_pnalloc(r->pool,
        name.len + 1 + plen + 1 + mac.len
        + sizeof("; Path=/; HttpOnly; SameSite=Strict; Secure") - 1);
    if (set_cookie->value.data == NULL) {
        return NGX_ERROR;
    }
    set_cookie->value.len = ngx_sprintf(set_cookie->value.data,
        "%V=%*s|%V; Path=/; HttpOnly; SameSite=%s%s",
        &name, plen, payload, &mac,
        ngx_http_pgp_samesite[plcf->cookie_samesite],
        plcf->cookie_secure ? "; Secure" : "")
        - set_cookie->value.data;

    /*
     * Redirect to the same path without the auth query argument.
     *
     * Emit a RELATIVE Location (just the path) as a plain header rather than via
     * r->headers_out.location -- the latter is rewritten to an absolute URL
     * using nginx's own scheme/host/listen-port, which is wrong behind a proxy
     * or TLS terminator (the browser would be sent to nginx's internal port).
     * A relative Location is resolved by the browser against the URL it actually
     * connected to, so it works behind any front end.
     */
    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_ERROR;
    }
    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    location->value = r->uri;

    /* 303 See Other: the correct Post/Redirect/Get response -- the client
     * re-fetches the target with GET, not by repeating the POST. We send the
     * (bodyless) response ourselves so nginx does not absolutize the Location. */
    r->headers_out.status = NGX_HTTP_SEE_OTHER;
    r->headers_out.content_length_n = 0;
    return NGX_HTTP_SEE_OTHER;
}


static const u_char ngx_http_pgp_page_head[] =
"<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
"<title>PGP authentication</title><style>"
"body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;"
"padding:0 16px;color:#222}textarea{width:100%;box-sizing:border-box;"
"font-family:monospace;font-size:13px}code{background:#f4f4f4;padding:2px 4px}"
".err{color:#b00;font-weight:bold}.box{background:#f7f7f7;border:1px solid #ddd;"
"padding:8px;border-radius:6px}</style></head><body>"
"<h2>PGP authentication required</h2>";


/* Build and send the challenge page (HTTP 200). */
static ngx_int_t
ngx_http_pgp_send_challenge(ngx_http_request_t *r,
    ngx_http_pgp_auth_loc_conf_t *plcf, ngx_uint_t failed)
{
    time_t        exp;
    u_char        nonce[NGX_HTTP_PGP_NONCE_LEN];
    u_char        nonce_hex[NGX_HTTP_PGP_NONCE_LEN * 2];
    u_char       *payload, *challenge, *body, *end;
    size_t        plen, clen, size;
    ngx_int_t     rc;
    ngx_str_t     mac;
    ngx_buf_t    *b;
    ngx_chain_t   out;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_hex_dump(nonce_hex, nonce, sizeof(nonce));

    exp = ngx_time() + plcf->challenge_timeout;

    /* payload = "v1|<exp>|<nonce_hex>" */
    payload = ngx_pnalloc(r->pool, sizeof("v1|") - 1 + NGX_TIME_T_LEN + 1
                                   + sizeof(nonce_hex));
    if (payload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    plen = ngx_sprintf(payload, "v1|%T|%*s", exp,
                       sizeof(nonce_hex), nonce_hex) - payload;

    if (ngx_http_pgp_hmac_hex(r, plcf, payload, plen, &mac)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* challenge = payload|<mac> */
    challenge = ngx_pnalloc(r->pool, plen + 1 + mac.len);
    if (challenge == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    clen = ngx_sprintf(challenge, "%*s|%V", plen, payload, &mac) - challenge;

    size = sizeof(ngx_http_pgp_page_head) - 1 + clen + 1024;
    body = ngx_pnalloc(r->pool, size);
    if (body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    end = ngx_cpymem(body, ngx_http_pgp_page_head,
                     sizeof(ngx_http_pgp_page_head) - 1);

    if (failed) {
        end = ngx_cpymem(end, "<p class=\"err\">Verification failed. "
                              "Please sign a fresh challenge below.</p>",
                         sizeof("<p class=\"err\">Verification failed. "
                              "Please sign a fresh challenge below.</p>") - 1);
    }

    end = ngx_sprintf(end,
        "<ol><li>Copy the challenge below.</li>"
        "<li>Sign it with your key (e.g. Kleopatra &rarr; Notepad &rarr; "
        "Sign).</li>"
        "<li>Paste the signed block back and submit.</li></ol>"
        "<p><b>Challenge:</b></p>"
        "<textarea class=\"box\" rows=\"2\" readonly "
        "onclick=\"this.select()\">%*s</textarea>"
        "<form method=\"POST\" action=\"?%s=1\">"
        "<p><b>Signed message:</b></p>"
        "<textarea name=\"%s\" rows=\"14\" "
        "placeholder=\"-----BEGIN PGP SIGNED MESSAGE-----\" required></textarea>"
        "<p><button type=\"submit\">Authenticate</button></p>"
        "</form></body></html>",
        clen, challenge, NGX_HTTP_PGP_AUTH_ARG, NGX_HTTP_PGP_FIELD);

    r->headers_out.status = failed ? NGX_HTTP_FORBIDDEN : NGX_HTTP_OK;
    r->headers_out.content_length_n = end - body;
    ngx_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = body;
    b->last = end;
    b->memory = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


/* Collect the (in-memory or buffered) request body into one buffer. */
static ngx_int_t
ngx_http_pgp_read_body(ngx_http_request_t *r, ngx_str_t *body, size_t max)
{
    size_t        len;
    u_char       *p;
    ngx_buf_t    *buf;
    ngx_chain_t  *cl;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_DECLINED;
    }

    len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        if (buf->in_file) {
            /* keep it simple: require the body to fit in memory */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "pgp_auth: request body buffered to disk; raise "
                          "client_body_buffer_size");
            return NGX_ERROR;
        }
        len += buf->last - buf->pos;
    }

    /* backstop for bodies whose length was unknown up front (e.g. HTTP/2) */
    if (len > max) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: auth body too large (%uz > %uz)", len, max);
        return NGX_ERROR;
    }

    body->data = ngx_pnalloc(r->pool, len + 1);
    if (body->data == NULL) {
        return NGX_ERROR;
    }

    p = body->data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }
    *p = '\0';
    body->len = len;

    return NGX_OK;
}


/*
 * Decode the "signed=..." field from an application/x-www-form-urlencoded
 * body in place. '+' becomes space, %XX becomes its byte. Returns the
 * decoded value through `out`.
 */
static ngx_int_t
ngx_http_pgp_form_field(ngx_str_t *body, ngx_str_t *out)
{
    u_char  *src, *dst, *last;

    if (body->len < sizeof(NGX_HTTP_PGP_FIELD "=") - 1
        || ngx_strncmp(body->data, NGX_HTTP_PGP_FIELD "=",
                       sizeof(NGX_HTTP_PGP_FIELD "=") - 1) != 0)
    {
        return NGX_DECLINED;
    }

    src = body->data + sizeof(NGX_HTTP_PGP_FIELD "=") - 1;
    last = body->data + body->len;

    /* stop at a following field, if any */
    out->data = src;
    dst = src;

    while (src < last && *src != '&') {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else if (*src == '%' && src + 2 < last) {
            ngx_int_t hi = ngx_hextoi(src + 1, 1);
            ngx_int_t lo = ngx_hextoi(src + 2, 1);
            if (hi == NGX_ERROR || lo == NGX_ERROR) {
                *dst++ = *src++;
            } else {
                *dst++ = (u_char) ((hi << 4) + lo);
                src += 3;
            }
        } else {
            *dst++ = *src++;
        }
    }

    out->len = dst - out->data;
    return NGX_OK;
}


/* Body post-handler: verify the submitted signature and finalize. */
static void
ngx_http_pgp_auth_submit(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_str_t                       body, signed_msg;
    ngx_http_pgp_auth_loc_conf_t   *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pgp_auth_module);

    /*
     * Don't keep this connection alive after answering the POST. Producing the
     * response (challenge re-render or the 302) from a body post-handler in the
     * access phase leaves the keepalive connection in a state where the
     * client's next request on it stalls -- which is exactly what a browser
     * does when it reuses the connection to follow the redirect. Closing the
     * connection makes the browser open a fresh one for the next request.
     */
    r->keepalive = 0;

    if (ngx_http_pgp_read_body(r, &body, plcf->max_body_size) != NGX_OK) {
        ngx_http_finalize_request(r,
            ngx_http_pgp_send_challenge(r, plcf, 1));
        return;
    }

    if (ngx_http_pgp_form_field(&body, &signed_msg) != NGX_OK) {
        signed_msg = body;     /* allow a raw (text/plain) clear-signed body */
    }

    rc = ngx_http_pgp_verify_challenge(r, plcf, signed_msg.data,
                                       signed_msg.len);

    if (rc == NGX_HTTP_SEE_OTHER) {
        /*
         * Send the 303 ourselves (status + Set-Cookie + relative Location, no
         * body). Going through nginx's special-response path instead would
         * rewrite the Location to an absolute URL with nginx's own port.
         */
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK) {
            ngx_http_finalize_request(r, rc);
            return;
        }
        ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* verification failed: re-serve the challenge with an error notice */
    ngx_http_finalize_request(r, ngx_http_pgp_send_challenge(r, plcf, 1));
}


static ngx_int_t
ngx_http_pgp_auth_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_str_t                       arg;
    ngx_http_pgp_auth_loc_conf_t   *plcf;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_pgp_auth_module);

    if (!plcf->enable) {
        return NGX_DECLINED;
    }

    /* already authenticated -> let the request proceed */
    if (ngx_http_pgp_check_session(r, plcf) == NGX_OK) {
        return NGX_DECLINED;
    }

    ngx_str_set(&arg, NGX_HTTP_PGP_AUTH_ARG);

    if (r->method == NGX_HTTP_POST
        && r->args.len
        && ngx_http_arg(r, arg.data, arg.len, &arg) == NGX_OK)
    {
        /*
         * Reject an oversized auth body before reading it. A signed challenge
         * is a few hundred bytes; capping this bounds the work an
         * unauthenticated client can make a worker do.
         *
         * Reject up front when the length is known and over the cap, and also
         * for an HTTP/1.1 *chunked* body (content_length_n == -1) -- which would
         * otherwise be buffered to disk before we could refuse it. We do NOT
         * blanket-reject every unknown length: an HTTP/2 client may legitimately
         * stream a body without declaring a length, so those fall through and
         * are capped by size in the body handler below.
         */
        if (r->headers_in.content_length_n > (off_t) plcf->max_body_size
            || (r->headers_in.content_length_n < 0 && r->headers_in.chunked))
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "pgp_auth: auth body too large/unbounded (len=%O, cap=%uz)",
                          r->headers_in.content_length_n, plcf->max_body_size);
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        }

        rc = ngx_http_read_client_request_body(r, ngx_http_pgp_auth_submit);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    /* unauthenticated GET (or non-submit) -> serve the challenge */
    rc = ngx_http_pgp_send_challenge(r, plcf, 0);
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}


static void *
ngx_http_pgp_auth_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_pgp_auth_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pgp_auth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->challenge_timeout = NGX_CONF_UNSET;
    conf->session_timeout = NGX_CONF_UNSET;
    conf->cookie_secure = NGX_CONF_UNSET;
    conf->cookie_host_prefix = NGX_CONF_UNSET;
    conf->cookie_samesite = NGX_CONF_UNSET_UINT;
    conf->bind_ip = NGX_CONF_UNSET;
    conf->bind_ua = NGX_CONF_UNSET;
    conf->nonce_storage = NGX_CONF_UNSET_UINT;
    conf->revoc_fail_open = NGX_CONF_UNSET;
    conf->gpg_timeout = NGX_CONF_UNSET_MSEC;
    conf->max_body_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


/* Read a secret from a file, trimming trailing whitespace. */
static ngx_int_t
ngx_http_pgp_load_secret(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *out)
{
    u_char           *buf;
    ssize_t           n;
    ngx_fd_t          fd;
    ngx_file_info_t   fi;

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "pgp_auth: cannot open secret file \"%V\"", path);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR || ngx_file_size(&fi) <= 0) {
        ngx_close_file(fd);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pgp_auth: secret file \"%V\" is empty", path);
        return NGX_ERROR;
    }

    /*
     * The secret forges both sessions and challenges, so a leak is a full auth
     * bypass. Warn (like sshd does for private keys) if the file is readable by
     * group or others -- config-time only, no hot-path cost.
     */
    if (ngx_file_access(&fi) & 0077) {
        ngx_uint_t  m = (ngx_uint_t) (ngx_file_access(&fi) & 0777);

        /* nginx's printf has no %o, so render the octal digits ourselves */
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "pgp_auth: secret file \"%V\" is group/world-accessible "
            "(mode 0%ui%ui%ui); restrict it to the nginx user (chmod 600)",
            path, (m >> 6) & 7, (m >> 3) & 7, m & 7);
    }

    buf = ngx_pnalloc(cf->pool, (size_t) ngx_file_size(&fi));
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, (size_t) ngx_file_size(&fi));
    ngx_close_file(fd);
    if (n <= 0) {
        return NGX_ERROR;
    }

    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'
                     || buf[n - 1] == ' ' || buf[n - 1] == '\t'))
    {
        n--;
    }
    if (n <= 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pgp_auth: secret file \"%V\" has no content", path);
        return NGX_ERROR;
    }

    out->data = buf;
    out->len = (size_t) n;
    return NGX_OK;
}


static char *
ngx_http_pgp_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pgp_auth_loc_conf_t  *prev = parent;
    ngx_http_pgp_auth_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->keyring, prev->keyring,
                             "/etc/nginx/pubkeys.gpg");
    /* Shorter defaults shrink the replay window and session blast radius; both
     * remain fully configurable. */
    ngx_conf_merge_sec_value(conf->challenge_timeout, prev->challenge_timeout,
                             120);
    ngx_conf_merge_sec_value(conf->session_timeout, prev->session_timeout,
                             3600);
    ngx_conf_merge_value(conf->cookie_secure, prev->cookie_secure, 1);
    ngx_conf_merge_value(conf->cookie_host_prefix, prev->cookie_host_prefix, 1);
    ngx_conf_merge_uint_value(conf->cookie_samesite, prev->cookie_samesite,
                              NGX_HTTP_PGP_SAMESITE_LAX);
    ngx_conf_merge_value(conf->bind_ip, prev->bind_ip, 1);
    ngx_conf_merge_value(conf->bind_ua, prev->bind_ua, 1);
    ngx_conf_merge_uint_value(conf->nonce_storage, prev->nonce_storage,
                              NGX_HTTP_PGP_NONCE_MEMORY);
    ngx_conf_merge_str_value(conf->nonce_addr, prev->nonce_addr, "");
    ngx_conf_merge_str_value(conf->revocation_list, prev->revocation_list, "");
    /* revocation fails CLOSED by default: an unreadable list denies access */
    ngx_conf_merge_value(conf->revoc_fail_open, prev->revoc_fail_open, 0);
    ngx_conf_merge_msec_value(conf->gpg_timeout, prev->gpg_timeout, 2000);
    ngx_conf_merge_size_value(conf->max_body_size, prev->max_body_size, 16384);
    ngx_conf_merge_str_value(conf->secret_file, prev->secret_file, "");

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    /*
     * The cookie spec requires a __Host- cookie to be Secure; a browser drops a
     * __Host- cookie sent without it, which would break login entirely. So when
     * Secure is off the prefix is not applied (see ngx_http_pgp_cookie_name) --
     * warn that it was dropped rather than emit an unusable cookie.
     */
    if (conf->cookie_host_prefix && !conf->cookie_secure) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "pgp_auth: pgp_session_cookie_host_prefix is ignored because "
            "pgp_session_cookie_secure is off (the __Host- prefix requires "
            "Secure); using the unprefixed cookie name");
    }

    /* SameSite=None also requires Secure, or browsers drop the cookie. */
    if (conf->cookie_samesite == NGX_HTTP_PGP_SAMESITE_NONE
        && !conf->cookie_secure)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "pgp_auth: pgp_session_cookie_samesite None requires "
            "pgp_session_cookie_secure on; browsers reject a SameSite=None "
            "cookie without Secure");
    }

    /* an absolute keyring path is required for gpg */
    if (conf->keyring.len == 0 || conf->keyring.data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pgp_auth: pgp_keyring must be an absolute path");
        return NGX_CONF_ERROR;
    }

    if (conf->nonce_storage == NGX_HTTP_PGP_NONCE_MEMORY) {
        conf->nonce_zone = prev->nonce_zone
            ? prev->nonce_zone
            : ngx_http_pgp_nonce_add_zone(cf, NGX_HTTP_PGP_NONCE_ZONE_SIZE);
        if (conf->nonce_zone == NULL) {
            return NGX_CONF_ERROR;
        }

    } else if (conf->nonce_storage == NGX_HTTP_PGP_NONCE_REDIS
               && conf->nonce_addr.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "pgp_auth: pgp_auth_nonce_storage_address is required for redis");
        return NGX_CONF_ERROR;
    }

    /* inherit an already-loaded secret from the parent if possible */
    if (conf->secret_file.len == prev->secret_file.len
        && prev->secret.len
        && ngx_strncmp(conf->secret_file.data, prev->secret_file.data,
                       conf->secret_file.len) == 0)
    {
        conf->secret = prev->secret;
        return NGX_CONF_OK;
    }

    if (conf->secret_file.len) {
        if (ngx_conf_full_name(cf->cycle, &conf->secret_file, 1) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        if (ngx_http_pgp_load_secret(cf, &conf->secret_file, &conf->secret)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    } else {
        /*
         * No secret configured: generate a random one. This is fine for a
         * single instance, but sessions won't survive a reload and won't be
         * shared across containers. Multi-instance deployments must set
         * pgp_session_secret.
         */
        conf->secret.data = ngx_pnalloc(cf->pool, 32);
        if (conf->secret.data == NULL) {
            return NGX_CONF_ERROR;
        }
        if (RAND_bytes(conf->secret.data, 32) != 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "pgp_auth: RAND_bytes() failed");
            return NGX_CONF_ERROR;
        }
        conf->secret.len = 32;

        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "pgp_auth: no pgp_session_secret set; using a random per-process "
            "secret (sessions reset on reload and are not shared across "
            "instances)");
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_pgp_auth_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /*
     * PRECONTENT phase -- deliberately after the ACCESS phase. nginx copies a
     * phase's handlers into the engine in reverse registration order, so a
     * dynamically-loaded module in the ACCESS phase would run *before* the core
     * access modules. Running in PRECONTENT (which is after PREACCESS, ACCESS
     * and POST_ACCESS) puts this module after both limit_req (PREACCESS) and
     * auth_basic / auth_request (ACCESS): a request can be rate-limited or
     * rejected by basic auth before any gpg verification is forked, and PGP auth
     * layers on top of them.
     */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_pgp_auth_handler;

    return NGX_OK;
}
