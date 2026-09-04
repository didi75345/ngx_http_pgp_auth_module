/*
 * fuzz_gpg_status_parser.c
 *
 * Fuzzes the parsing logic used on gpg's --status-fd output in
 * src/ngx_http_pgp_auth_gpg.c (the VALIDSIG / REVKEYSIG / EXPKEYSIG /
 * EXPSIG / BADSIG / ERRSIG scan, and the "last whitespace-separated token is
 * the primary-key fingerprint" extraction within a VALIDSIG line).
 *
 * IMPORTANT — this is a LOGIC MIRROR, not the linked module code:
 * ngx_http_pgp_gpg_verify() in the real module is deeply coupled to nginx
 * types (ngx_log_t, the surrounding fork/exec/pipe machinery) and cannot be
 * fed a byte buffer directly without a much larger nginx-runtime test
 * harness. The function below (ngx_pgp_fuzz_parse_status) reproduces the
 * exact algorithm from ngx_http_pgp_auth_gpg.c line-for-line -- same
 * tokenizing approach, same bounds, same fingerprint validation -- so that
 * a memory-safety bug in the algorithm itself would reproduce here too.
 * A change to the real parser should be mirrored here as well; the two are
 * expected to be kept in lockstep by whoever next touches either.
 *
 * This still has real value: the manual pointer-walking token scanner in
 * the VALIDSIG branch (searching for the LAST space-separated field) is
 * exactly the kind of hand-rolled parsing where an off-by-one is easy to
 * introduce during a future edit, and this harness will catch that the
 * moment it's kept in sync, well before it ever reaches a real gpg output
 * stream.
 *
 * Build:  clang -g -fsanitize=fuzzer,address,undefined \
 *             test/fuzz/fuzz_gpg_status_parser.c -o fuzz_gpg_status_parser
 * Run:    ./fuzz_gpg_status_parser -max_len=8200 -timeout=5
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUZZ_FPR_MAX   80
#define FUZZ_BUF_MAX   8192

typedef struct {
    int    valid;
    char   fpr[FUZZ_FPR_MAX];
    size_t fpr_len;
} fuzz_result_t;

/* Minimal local strncmp-by-len helper, mirroring ngx_strncmp's usage here. */
static int
fz_strncmp(const char *a, const char *b, size_t n)
{
    return strncmp(a, b, n);
}

/*
 * Mirrors the loop body of ngx_http_pgp_gpg_verify() from
 * "good = 0; bad = 0;" through "res->valid = ...". `buf` need not be
 * NUL-terminated by the caller -- LLVMFuzzerTestOneInput below copies the
 * fuzzer's input into a NUL-terminated local buffer first, exactly like the
 * real function does with parsebuf/out.
 */
/* mirror of ngx_http_pgp_fpr_is_hex() in src/ngx_http_pgp_auth_gpg.c */
static int
fz_fpr_is_hex(const char *s, size_t len)
{
    size_t i;

    if (len < 32) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char) s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
              || (c >= 'A' && c <= 'F')))
        {
            return 0;
        }
    }
    return 1;
}


static void
ngx_pgp_fuzz_parse_status(char *buf, fuzz_result_t *res)
{
    char  *line, *save, *p;
    int    good = 0, bad = 0;

    res->valid = 0;
    res->fpr_len = 0;

    for (line = strtok_r(buf, "\n", &save);
         line != NULL;
         line = strtok_r(NULL, "\n", &save))
    {
        if (fz_strncmp(line, "[GNUPG:] ", 9) != 0) {
            continue;
        }
        p = line + 9;

        if (fz_strncmp(p, "VALIDSIG ", 9) == 0) {
            char    *q, *tok;
            size_t   n;

            p += 9;

            tok = p;
            for (q = p; ; ) {
                while (*q == ' ') { q++; }
                if (*q == '\0') { break; }
                tok = q;
                while (*q != '\0' && *q != ' ') { q++; }
            }

            n = 0;
            while (tok[n] != '\0' && tok[n] != ' '
                   && n < sizeof(res->fpr) - 1)
            {
                res->fpr[n] = tok[n];
                n++;
            }
            res->fpr[n] = '\0';

            if (fz_fpr_is_hex(res->fpr, n)) {
                res->fpr_len = n;
                good = 1;
            } else {
                n = 0;
                while (p[n] != '\0' && p[n] != ' '
                       && n < sizeof(res->fpr) - 1)
                {
                    res->fpr[n] = p[n];
                    n++;
                }
                res->fpr[n] = '\0';

                if (fz_fpr_is_hex(res->fpr, n)) {
                    res->fpr_len = n;
                    good = 1;
                } else {
                    res->fpr_len = 0;
                }
            }

        } else if (fz_strncmp(p, "REVKEYSIG", 9) == 0
                   || fz_strncmp(p, "EXPKEYSIG", 9) == 0
                   || fz_strncmp(p, "EXPSIG", 6) == 0
                   || fz_strncmp(p, "BADSIG", 6) == 0
                   || fz_strncmp(p, "ERRSIG", 6) == 0)
        {
            bad = 1;
        }
    }

    res->valid = (good && !bad) ? 1 : 0;
    if (!res->valid) {
        res->fpr_len = 0;
    }
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static char    buf[FUZZ_BUF_MAX];
    fuzz_result_t  res;
    size_t         n;

    if (size == 0) {
        return 0;
    }

    /* Same ceiling as the real out[]/parsebuf[8192]; anything longer is
     * exactly the "truncated" case the real code handles by rejecting
     * outright without ever reaching this parse step, so it's out of scope
     * for this harness by construction. */
    n = size < sizeof(buf) - 1 ? size : sizeof(buf) - 1;
    memcpy(buf, data, n);
    buf[n] = '\0';

    ngx_pgp_fuzz_parse_status(buf, &res);

    /* Invariants that must never be violated, regardless of input: */
    if (res.fpr_len >= sizeof(res.fpr)) {
        __builtin_trap();          /* would mean we wrote past res->fpr    */
    }
    if (!res.valid && res.fpr_len != 0) {
        __builtin_trap();          /* invalid result must not carry a fpr  */
    }

    return 0;
}
