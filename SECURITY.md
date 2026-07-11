# Security notes

The full white-box security audit — all review rounds, every finding with its
remediation, and the tool results — is in
[SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md).


This module is written in C and runs inside every nginx worker, so memory
safety and input handling are the primary concerns. This document records the
threat model, the defensive choices, and how they are verified.

## Threat model

Untrusted input reaches the module from two places:

1. The **session cookie** on every request to a protected location.
2. The **POST body** (the pasted, clear-signed block) on a login submission.

Everything else (the keyring, the secret) is operator-controlled.

## Defensive design

- **No secrets on the server.** Only public keys live in the keyring; a server
  compromise leaks nothing that lets an attacker authenticate. Users' private
  keys never reach the server. The one sensitive file, `pgp_session_secret`
  (it can forge both sessions and challenges), is checked at start-up: the
  module logs a `warn` if it is group- or world-accessible (`mode & 077`),
  the way sshd does for private keys.
- **Stateless, HMAC-signed tokens.** Both the challenge and the session are
  authenticated with HMAC-SHA256 over a server secret. A client cannot forge a
  challenge the server did not issue, or a session it was not granted.
- **Constant-time MAC comparison** (`CRYPTO_memcmp`) so cookie/challenge
  validation does not leak via timing.
- **Bounded parsing.** Buffers are sized before writing and use length-checked
  copies; the gpg output parser reads into a fixed buffer with explicit bounds.
- **No shell.** gpg is launched with `execlp` and an explicit argument vector,
  never via a shell, so keyring paths and message content can't be interpreted
  as commands.
- **Pool-allocated memory.** All per-request allocations come from nginx's
  request pool and are released when the request ends, so there is no manual
  free path to get wrong (no use-after-free / double-free by construction).
- **Subprocess isolation + timeout.** Each verification runs gpg in a throwaway
  `GNUPGHOME` that is wiped afterwards, with `--no-autostart` (no gpg-agent),
  under a hard timeout that SIGKILLs a stuck gpg so a worker can never hang.
- **SIGCHLD-safe.** The gpg child is reaped by the module without racing
  nginx's own SIGCHLD handling.
- **Secure cookies over TLS.** The session cookie is set with `HttpOnly` and
  `SameSite=Lax` always, and `Secure` whenever the login arrived over TLS.
- **Rate-limitable logins.** Each login attempt forks a gpg verification, so
  submissions should be capped with nginx's own `limit_req` keyed on the
  `__pgp_auth` argument — see `examples/nginx.conf` for the exact pattern.
  Combined with the 5s gpg timeout this bounds the work an attacker can cause.

## Hardening from the security review

- **Challenge bound to the signed plaintext.** gpg is run with `--output` and
  the challenge is checked *only* inside the bytes gpg actually verified, so a
  real signature over other text with a challenge appended/prepended outside
  the signature is rejected.
- **Hardened gpg status parse.** Status is read on a pipe separate from stderr;
  only lines with the exact `[GNUPG:] ` prefix are trusted; short fingerprints
  are rejected; and `REVKEYSIG` / `EXPKEYSIG` / `EXPSIG` / `BADSIG` / `ERRSIG`
  fail the verification.
- **Single-use challenges** (`pgp_auth_nonce_storage`): a shared-memory or Redis
  seen-nonce store closes the replay-within-validity window. Fails closed.
- **Client binding** (`pgp_auth_bind_client_ip`, `pgp_auth_bind_user_agent`,
  both on): the client IP and User-Agent are folded into the token, so a stolen
  challenge or session cookie will not validate from another client.
- **Secure cookie** (`pgp_session_cookie_secure`, on) with an independent
  `__Host-` name prefix option (`pgp_session_cookie_host_prefix`, on). For a
  plain-HTTP deployment, turn `pgp_session_cookie_secure` off (and the prefix,
  since `__Host-` requires Secure — nginx warns if it's left on). Shorter default
  challenge/session lifetimes shrink the replay window and blast radius.
- **Revocation** (`pgp_revocation_list`): a fingerprint file that revokes a key
  and all of its live sessions without rotating the secret or reloading nginx.
  An unreadable list **fails closed** (denies) by default
  (`pgp_revocation_fail_open off`).
- **DoS resistance on the login endpoint** (unauthenticated): a body larger than
  `pgp_auth_max_body_size` (16k) is rejected before it is read; an HTTP/1.1
  *chunked* body (no declared length, which would otherwise be buffered to disk)
  is rejected up front, while a normal HTTP/2 submission is unaffected and is
  size-capped once read; a submission that is not a clear-signed block is
  rejected *before* gpg is forked; and each gpg verification is bounded by
  `pgp_gpg_timeout` (2s). Deployments should also put `limit_req` in front of the
  login submission (see `examples/nginx.conf`).
- **No trust in truncated gpg output**: if gpg's status or output overflows the
  read buffer it is treated as a failure, so a later `BADSIG`/`REVKEYSIG` marker
  cannot be lost past a `VALIDSIG`.

## Verification

The module compiles with `-Wall -Werror` (zero warnings) on Debian Bookworm
(nginx 1.22) and Trixie (1.26).

**Functional + attack suite** (`test/run-tests.sh`, run in CI on both Debian
releases): the full login flow, redirect-following login, and rejection of a
forged cookie, an unknown-key signature, a forged challenge (bad HMAC), an
expired challenge, and garbage/non-PGP bodies.

**Sanitizers** (`test/sanitize.sh`): the module is rebuilt with
AddressSanitizer + UndefinedBehaviorSanitizer and every request path is
exercised — valid login, garbage, empty, malformed percent-encoding, forged
cookie, and an oversized (200 KB) body — to catch buffer overflows,
use-after-free, and bad memory access. The module reports **no faults** on any
input. (Run `sh test/sanitize.sh`; it builds, exercises, and checks the
sanitizer output, exiting non-zero on any fault in the module.)

**Static analysis**: GCC's `-fanalyzer` (`test/analyze.sh`) and `cppcheck
--enable=all` — **no error/warning-level findings** in the module sources.

**Valgrind** (`test/memcheck.sh`): the module is exercised under Valgrind
memcheck — **no invalid read/write, no use of uninitialised memory, and no
leaks** originating in the module (only nginx's own framework allocations
appear, which it manages itself).

### Memory-safety coverage

Every class is checked by at least two independent tools that have been run
against the code:

| Class | Verified by |
|-------|-------------|
| Buffer overflow, out-of-bounds read/write | ASan + cppcheck + `-fanalyzer` |
| Use-after-free | ASan + Valgrind + `-Wanalyzer-use-after-free` |
| Double free | ASan + `-Wanalyzer-double-free` |
| Null-pointer dereference | ASan/UBSan + cppcheck + `-Wanalyzer-null-dereference` |
| Integer overflow | UBSan + cppcheck |
| Stack overflow (stack-buffer-overflow) | ASan |
| Memory leak | ASan leak check + Valgrind + `-Wanalyzer-malloc-leak` |
| Uninitialized memory | Valgrind memcheck + `-fanalyzer` |
| Format-string | `-Wformat` under `-Werror` + cppcheck |

## Reporting

Please report security issues privately to the maintainer rather than via a
public issue.
