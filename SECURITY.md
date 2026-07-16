# Security notes

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
- **Secure cookies over TLS.** The session cookie is set with `HttpOnly`,
  `SameSite` (`Lax` by default, `Strict`/`None` via `pgp_session_cookie_samesite`),
  and `Secure` when `pgp_session_cookie_secure` is on.
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
- **Secure cookie** (`pgp_session_cookie_secure`, on) with a `__Host-` name
  prefix option (`pgp_session_cookie_host_prefix`, on) and a configurable
  `SameSite` (`pgp_session_cookie_samesite`, default `Lax`). For a plain-HTTP
  deployment, turn `pgp_session_cookie_secure` off; the `__Host-` prefix is
  then dropped automatically (it requires Secure), so the cookie stays usable.
  Shorter default challenge/session lifetimes shrink the replay window.
- **Revocation** (`pgp_revocation_list`): a fingerprint file that revokes a key
  and all of its live sessions without rotating the secret or reloading nginx.
  An unreadable list **fails closed** (denies) by default
  (`pgp_revocation_fail_open off`). A signer is identified by its **primary key
  fingerprint** (gpg's `VALIDSIG` reports the signing-key fpr first and the
  primary-key fpr last; the module keys identity and revocation off the primary),
  which closes a bypass where a key that signs with a subkey would not be caught
  by a revocation entry for its primary fingerprint, and keeps identity stable
  across subkey rotation. List entries are matched ignoring whitespace and case,
  so a fingerprint pasted in `gpg --fingerprint` form can't silently fail to
  match.
- **DoS resistance on the login endpoint** (unauthenticated): a body larger than
  `pgp_auth_max_body_size` (16k) is rejected before it is read; an HTTP/1.1
  *chunked* body (no declared length, which would otherwise be buffered to disk)
  is rejected up front, while a normal HTTP/2 submission is unaffected and is
  size-capped once read; a submission that is not a clear-signed block is
  rejected *before* gpg is forked; and each gpg verification is bounded by
  `pgp_gpg_timeout` (2s). Deployments should also put `limit_req` in front of the
  login submission (see `examples/nginx.conf`). The module runs in the
  PRECONTENT phase, i.e. *after* `limit_req` (PREACCESS) and `auth_basic` /
  `auth_request` (ACCESS), so those can rate-limit or reject a request before
  any gpg work happens, and PGP auth layers on top of them.
- **Relative redirect.** The post-login redirect uses a relative `Location` so
  it resolves against the URL the browser actually used -- correct behind a
  reverse proxy or TLS terminator, where nginx's own scheme/host/port differ.
- **No trust in truncated gpg output**: if gpg's status or output overflows the
  read buffer it is treated as a failure, so a later `BADSIG`/`REVKEYSIG` marker
  cannot be lost past a `VALIDSIG`.
- **No `$PATH` search, no inherited environment for the gpg child.** The child
  is launched with `execve()` on the operator-configured absolute path
  (`pgp_gpg_path`, validated at config time to start with `/`) and an empty
  `envp`, not `execlp("gpg", ...)`. `execlp` resolves the binary by searching
  `$PATH`, so anything placed earlier on the worker's `$PATH` -- or a `$PATH`
  set via a poisoned environment -- would run in place of the real `gpg`.
  Clearing the environment also removes `LD_PRELOAD`/`LD_LIBRARY_PATH`-style
  injection via inherited variables. This closes off the one place in the
  module where "no shell" alone would not have been enough.
- **No fd leakage into the gpg child beyond a hardcoded bound.** The child
  closes every inherited descriptor from 3 upward using `close_range()`
  (Linux 5.9+) with a `sysconf(_SC_OPEN_MAX)`-based fallback, instead of a
  fixed `< 1024` loop -- `worker_rlimit_nofile` is routinely raised well past
  1024, and a fixed bound would leave higher-numbered fds (other client
  connections, listening sockets, log fds) reachable to the gpg subprocess.
- **Security headers on the login page.** `X-Frame-Options: DENY`,
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and
  `Referrer-Policy: no-referrer` are set on the challenge/login response, so
  it can't be framed for clickjacking, MIME-sniffed, or cached.
- **Redis `AUTH`** (`pgp_auth_nonce_storage_password`, optional): sent
  immediately after connecting; the nonce `SET` is never issued unless `AUTH`
  returns `+OK`, so a misconfigured or rejected password fails closed rather
  than silently falling back to an unauthenticated write. Recommended for
  any Redis instance reachable over a network rather than strictly local.
- **Configurable nonce zone size** (`pgp_auth_nonce_zone_size`, default `8m`):
  the `memory` nonce backend fails closed when full, so deployments expecting
  many concurrent logins should size this up front rather than discover the
  default under load. This sizes one shared-memory segment for the entire
  nginx config (the zone is identified by name, not per-location), so set it
  once -- at `http` or `server` level -- rather than differently per
  location; nginx will refuse to start (`nginx -t` fails) if it sees the
  same zone declared with two different sizes.
- **Log output stripped of control characters**, not just newlines, before a
  gpg failure message is logged -- gpg's own text can no longer inject escape
  sequences into whatever reads the error log. The full message is preserved
  (parsing is done on a copy), so an operator sees all of gpg's output, not
  just its first line.
- **MAC domain separation.** Every MAC input is prefixed with a context label
  (`chal` for a challenge, `sess` for a session cookie), so the two token types
  can never produce the same MAC regardless of how their pipe-delimited layouts
  or parsers later evolve. This makes "a challenge can't be presented as a
  session cookie" a cryptographic invariant rather than a property of the
  current parser field counts.
- **Bounded gpg output** (`--max-output`). `--decrypt` also inflates compressed
  OpenPGP packets, so a small but highly compressed body could otherwise make
  gpg write a huge file to the temp dir (a data-amplification DoS, worst on the
  small tmpfs `/tmp` in containers). gpg is capped with `--max-output`, and the
  clear-sign pre-check now requires the header at the very *start* of the body
  (not merely somewhere inside it), so a compressed packet can't be prepended
  ahead of a real header.
- **No blocking DNS on the login path.** The Redis nonce client resolves its
  address with no DNS lookup (numeric `ip:port` only); a hostname with a slow or
  unreachable resolver would otherwise hang the worker for the system resolver's
  timeout, uncovered by the client's own per-operation deadlines.
- **Redis errors are not mistaken for replays.** A Redis error reply (`-NOAUTH`,
  `-LOADING`, `-OOM`, ...) is treated as an operational failure -- logged and
  denied deliberately (fail closed) -- not silently labelled "challenge already
  used", so a Redis outage is diagnosable instead of looking like a flood of
  replays.
- **Weak-secret warning.** The secret loader warns at start-up if the HMAC
  secret is shorter than 16 bytes; it keys every token MAC, so a guessable
  secret is a full bypass. `$TMPDIR` is honoured for the throwaway keyring dir,
  matching the documented "system temp dir".

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
