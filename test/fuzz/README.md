# Fuzz harnesses

Two libFuzzer targets for the two parsers in this module that handle the
most adversarial input:

| Harness | Mirrors | Why it's the highest-value target |
|---|---|---|
| `fuzz_gpg_status_parser.c` | The `VALIDSIG`/`REVKEYSIG`/`EXPKEYSIG`/`EXPSIG`/`BADSIG`/`ERRSIG` scan and primary-key-fingerprint extraction in `ngx_http_pgp_gpg_verify()` (`src/ngx_http_pgp_auth_gpg.c`) | Hand-rolled pointer-walking tokenizer (finds the *last* whitespace-separated field on a `VALIDSIG` line) — exactly the kind of code where a future edit could introduce an off-by-one |
| `fuzz_form_field_decoder.c` | The `%XX`/`+` in-place decoder in `ngx_http_pgp_form_field()` (`src/ngx_http_pgp_auth_module.c`) | The **first** parser fully attacker-controlled bytes reach on every request, pre-authentication, before gpg is ever invoked |

## Why these are logic mirrors, not the linked module

Both real functions are woven into nginx's request/subprocess lifecycle
(`ngx_http_request_t`, `ngx_log_t`, fork/exec/pipe setup) and can't be handed
a raw byte buffer without a much larger nginx-runtime fuzzing rig. Each
harness instead reproduces its target's algorithm line-for-line — same
tokenizing, same bounds checks, same overlap direction for the in-place
decode — so a memory-safety bug in the *algorithm* reproduces here too.

**This means the two copies must be kept in sync.** If you change the
parsing logic in `ngx_http_pgp_auth_gpg.c` or the form-field decoder in
`ngx_http_pgp_auth_module.c`, update the matching harness in the same change.
A comment at the top of each harness says so.

The natural follow-up (not done here, to keep this change's footprint to
"add fuzzing coverage" rather than "restructure the parsers") is to extract
each real parser into a small nginx-independent pure function that both the
module and the fuzz harness call directly, so there is only one copy of the
logic to keep in sync. Worth doing in a future pass.

## Build and run

```sh
sh test/fuzz/build.sh
./test/fuzz/fuzz_gpg_status_parser  -max_len=8200  test/fuzz/seeds/
./test/fuzz/fuzz_form_field_decoder -max_len=65536 test/fuzz/seeds/
```

Each harness also defines an explicit invariant check (`__builtin_trap()` on
violation) beyond what ASan/UBSan catch on their own — e.g. the status
parser harness traps if it ever produces a fingerprint length that doesn't
fit `res->fpr`, or a "valid" result with no fingerprint attached.

At the time this was added, both harnesses were run for several million
executions each (`fuzz_gpg_status_parser`: ~2.7M, `fuzz_form_field_decoder`:
~7.8M) with zero crashes and zero sanitizer reports. For CI, a bounded run
(e.g. `-max_total_time=120`) is a reasonable regression check; for deeper
coverage, run continuously against an accumulating corpus.
