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


#define NGX_HTTP_PGP_COOKIE       "pgp_session"
#define NGX_HTTP_PGP_AUTH_ARG     "__pgp_auth"
#define NGX_HTTP_PGP_FIELD        "signed"
#define NGX_HTTP_PGP_NONCE_LEN    16          /* raw bytes -> 32 hex chars */


typedef struct {
    ngx_flag_t   enable;
    ngx_str_t    keyring;
    time_t       challenge_timeout;   /* seconds a challenge stays valid    */
    time_t       session_timeout;     /* seconds; 0 == unlimited            */
    ngx_flag_t   cookie_secure;       /* add "; Secure" to the cookie       */
    ngx_str_t    secret_file;
    ngx_str_t    secret;              /* loaded HMAC secret bytes           */
} ngx_http_pgp_auth_loc_conf_t;


static ngx_int_t ngx_http_pgp_auth_handler(ngx_http_request_t *r);
static void ngx_http_pgp_auth_submit(ngx_http_request_t *r);

static ngx_int_t ngx_http_pgp_hmac_hex(ngx_http_request_t *r,
    ngx_str_t *secret, u_char *data, size_t len, ngx_str_t *out);
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


/* HMAC-SHA256(secret, data) hex-encoded into out (allocated from r->pool). */
static ngx_int_t
ngx_http_pgp_hmac_hex(ngx_http_request_t *r, ngx_str_t *secret,
    u_char *data, size_t len, ngx_str_t *out)
{
    unsigned int   mdlen;
    unsigned char  md[EVP_MAX_MD_SIZE];

    if (HMAC(EVP_sha256(), secret->data, (int) secret->len, data, len,
             md, &mdlen) == NULL)
    {
        return NGX_ERROR;
    }

    out->data = ngx_pnalloc(r->pool, mdlen * 2);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(out->data, md, mdlen);
    out->len = mdlen * 2;

    return NGX_OK;
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

    ngx_str_set(&name, NGX_HTTP_PGP_COOKIE);

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

    if (ngx_http_pgp_hmac_hex(r, &plcf->secret, payload.data, payload.len,
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
    if (ngx_http_pgp_gpg_verify(r->connection->log, &plcf->keyring, msg, len,
                                &vr) != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (!vr.valid) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "pgp_auth: signature not from a keyring key");
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

    if (ngx_http_pgp_hmac_hex(r, &plcf->secret, payload.data, payload.len,
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
    ngx_str_t         mac;
    ngx_table_elt_t  *set_cookie;

    exp = (plcf->session_timeout == 0) ? 0 : ngx_time() + plcf->session_timeout;

    /* payload = "<exp>|<fpr>" */
    payload = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 1 + fpr->len);
    if (payload == NULL) {
        return NGX_ERROR;
    }
    plen = ngx_sprintf(payload, "%T|%V", exp, fpr) - payload;

    if (ngx_http_pgp_hmac_hex(r, &plcf->secret, payload, plen, &mac) != NGX_OK) {
        return NGX_ERROR;
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }
    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");

    /* Secure flag controlled by pgp_session_cookie_secure (default on). */
    set_cookie->value.data = ngx_pnalloc(r->pool,
        sizeof(NGX_HTTP_PGP_COOKIE "=") - 1 + plen + 1 + mac.len
        + sizeof("; Path=/; HttpOnly; SameSite=Lax; Secure") - 1);
    if (set_cookie->value.data == NULL) {
        return NGX_ERROR;
    }
    set_cookie->value.len = ngx_sprintf(set_cookie->value.data,
        "%s=%*s|%V; Path=/; HttpOnly; SameSite=Lax%s",
        NGX_HTTP_PGP_COOKIE, plen, payload, &mac,
        plcf->cookie_secure ? "; Secure" : "")
        - set_cookie->value.data;

    /* redirect to the same URI without the auth query argument */
    ngx_http_clear_location(r);
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }
    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value = r->uri;

    /* 303 See Other: the correct Post/Redirect/Get response -- the client
     * re-fetches the target with GET, not by repeating the POST. */
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

    if (ngx_http_pgp_hmac_hex(r, &plcf->secret, payload, plen, &mac)
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
ngx_http_pgp_read_body(ngx_http_request_t *r, ngx_str_t *body)
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

    if (ngx_http_pgp_read_body(r, &body) != NGX_OK) {
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
         * Cookie + Location are already set on headers_out; let nginx's
         * special-response machinery build the redirect (it preserves our
         * Set-Cookie header). Finalizing with the 3xx code is what triggers
         * that, so we must NOT have sent a header ourselves first.
         */
        ngx_http_finalize_request(r, NGX_HTTP_SEE_OTHER);
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
    ngx_conf_merge_str_value(conf->secret_file, prev->secret_file, "");

    if (!conf->enable) {
        return NGX_CONF_OK;
    }

    /* an absolute keyring path is required for gpg */
    if (conf->keyring.len == 0 || conf->keyring.data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pgp_auth: pgp_keyring must be an absolute path");
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
     * ACCESS phase (like auth_basic), not PREACCESS: this keeps the module
     * *after* limit_req, so operators can rate-limit login attempts before a
     * gpg verification is ever forked.
     */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_pgp_auth_handler;

    return NGX_OK;
}
