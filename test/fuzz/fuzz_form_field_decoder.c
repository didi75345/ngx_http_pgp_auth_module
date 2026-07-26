/*
 * fuzz_form_field_decoder.c
 *
 * Fuzzes the logic mirroring ngx_http_pgp_form_field() in
 * src/ngx_http_pgp_auth_module.c: locating "signed=" in a fully
 * attacker-controlled application/x-www-form-urlencoded POST body and
 * percent/'+'-decoding it IN PLACE. This is the first parser attacker input
 * reaches on every request, before gpg is ever invoked, so it is the
 * highest-value fuzz target in the module: a crash here would be reachable
 * pre-authentication by anyone who can send a POST.
 *
 * Same caveat as fuzz_gpg_status_parser.c: this is a logic mirror (the real
 * function operates on ngx_str_t and is called from deep inside the request
 * body read callback), reproducing the exact decode algorithm -- the '+' and
 * '%XX' handling and the src/dst overlap direction -- so keep the two in
 * sync if the real decoder changes.
 *
 * Build:  clang -g -fsanitize=fuzzer,address,undefined \
 *             test/fuzz/fuzz_form_field_decoder.c -o fuzz_form_field_decoder
 * Run:    ./fuzz_form_field_decoder -max_len=65536 -timeout=5
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define FIELD_PREFIX  "signed="

/* Minimal mirror of ngx_hextoi(): parse exactly one hex digit, -1 if not hex. */
static int
fz_hexdigit(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/*
 * Mirrors ngx_http_pgp_form_field() body-scanning loop exactly: decodes in
 * place between [src, last) into dst, stopping at an unescaped '&'. Returns
 * the decoded length, or (size_t) -1 if the "signed=" prefix isn't present
 * (mirroring NGX_DECLINED).
 */
static size_t
form_field_decode(unsigned char *body, size_t body_len)
{
    unsigned char *src, *dst, *last;
    size_t         prefix_len = sizeof(FIELD_PREFIX) - 1;

    if (body_len < prefix_len
        || memcmp(body, FIELD_PREFIX, prefix_len) != 0)
    {
        return (size_t) -1;
    }

    src = body + prefix_len;
    last = body + body_len;
    dst = src;

    while (src < last && *src != '&') {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else if (*src == '%' && src + 2 < last) {
            int hi = fz_hexdigit(src[1]);
            int lo = fz_hexdigit(src[2]);
            if (hi < 0 || lo < 0) {
                *dst++ = *src++;
            } else {
                *dst++ = (unsigned char) ((hi << 4) + lo);
                src += 3;
            }
        } else {
            *dst++ = *src++;
        }
    }

    return (size_t) (dst - (body + prefix_len));
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    unsigned char *body;
    size_t         decoded_len;

    if (size == 0) {
        return 0;
    }

    /* Own, heap-allocated, ASan-guarded copy: an in-place decoder that ever
     * wrote past its own input (dst running ahead of src, or past `last`)
     * would be caught immediately by the redzone rather than silently
     * corrupting adjacent fuzzer-harness memory. */
    body = malloc(size);
    if (body == NULL) {
        return 0;
    }
    memcpy(body, data, size);

    decoded_len = form_field_decode(body, size);

    /* Invariant: decoding never grows the field (both '+'->' ' and '%XX'
     * decode to <= the bytes they consumed), so it must never exceed the
     * original buffer bounds. */
    if (decoded_len != (size_t) -1 && decoded_len > size) {
        __builtin_trap();
    }

    free(body);
    return 0;
}
