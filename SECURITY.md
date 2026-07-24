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
- **No shell.** gpg is launched with `execve` on a config-validated absolute
  path (`pgp_gpg_path`), an explicit argument vector, and an empty environment —
  never via a shell, and never resolved through `$PATH`. Keyring paths and
  message content cannot be interpreted as commands, and neither a hostile
  `$PATH` nor an inherited `LD_PRELOAD` can influence which binary runs.
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

## Login endpoint: cost, thread pool, and `limit_req`

Verifying a signature means forking `gpg` and waiting for it. By default that
work runs on an nginx **thread pool** (`pgp_gpg_thread_pool`, default `default`,
auto-created), so the worker hands the blocking gpg call to a pool thread and
returns to its event loop immediately — it keeps serving other requests while
verification runs. This uses only nginx's own thread-pool API (present in any
build compiled `--with-threads`, no external dependency).

On an nginx built **without** thread support, or with `pgp_gpg_thread_pool off`,
verification is **synchronous** in the worker instead: the module forks `gpg`,
waits, and completes the request, so while a verification runs that worker is
busy. The two modes are otherwise identical; only *where* gpg runs differs.

Measured on one worker (`worker_processes 1`) on Debian's threaded nginx, with a
deliberately slowed gpg so the effect is visible: with the pool on (default),
while a **2-second** verification is in flight an ordinary request to that same
worker still completes in **~0.8 ms** — the worker is not blocked. With
`pgp_gpg_thread_pool off`, that same ordinary request waits behind the
verification. The two modes are sized differently — see the arithmetic below.

### What a request actually costs

Measured against the module (single worker; treat these as orders of magnitude,
not exact figures):

| Request | Worker time | Forks gpg? |
|---------|-------------|------------|
| Challenge page | ~1 ms | no |
| Body that is not a clear-signed message | ~1 ms | no — rejected by the pre-check |
| Body over `pgp_auth_max_body_size` | ~1 ms | no — rejected before it is read |
| Authenticated request (valid session cookie) | ~1 ms | no |
| **Genuine login (full signature verification)** | **~17 ms** | yes |
| **Crafted body that forces gpg to run and fail** | **~25 ms** | yes |

So the blocking window is **tens of milliseconds**, not seconds.
`pgp_gpg_timeout` (2s) is a safety ceiling for pathological input, not the
normal cost. Traffic that isn't a plausible clear-signed message never forks
anything, so the cheap flood is already handled.

### The arithmetic

What bounds concurrency, and whether it can starve anything else nginx serves,
depends on which mode gpg runs in.

**With the thread pool (the default).** The worker never blocks: it posts the
gpg verification to the pool and returns to its event loop. So verifications do
**not** tie up workers — the ceiling is the pool's thread count:

```
concurrent verifications  ~=  thread_pool "threads=" (default 32)
```

Excess logins queue for a pool thread rather than occupying a worker, and the
worker keeps serving everything else — a co-hosted public site is unaffected by
a login flood because no worker is ever blocked on gpg. The thing to size is the
pool (`thread_pool name threads=N`) and the number of concurrent `gpg`
*processes* it implies (one per busy thread).

> **The single-use nonce check runs on the pool thread too (Pentest CCS
> F-001).** Right after gpg, the same thread validates the challenge MAC/expiry
> and consumes the nonce, so a blocking `pgp_auth_nonce_storage redis` round-trip
> — connect → (TLS handshake →) `SET NX` — happens off the worker as well, not
> just gpg. The worker is never blocked on the nonce store in either backend
> (`memory` is a lock-guarded in-process lookup anyway). The Redis client is
> still bounded by its 500 ms poll timeouts and fails closed. Keep the global
> `limit_req` in place: it now bounds *pool-thread* occupancy (busy threads →
> stalled logins, and one open Redis socket + `gpg` process per busy thread)
> rather than worker blocking.

**Synchronous mode (`pgp_gpg_thread_pool off`, or an nginx built without
`--with-threads`).** Here a verification does occupy the worker for its
duration, so the number of workers tied up at any moment is bounded by:

```
workers busy  ~=  rate x pgp_gpg_timeout  +  burst
```

Keep that below `worker_processes` and there is always a free worker for
everything else. One worker sustains roughly **40 forced verifications per
second**; with a global `limit_req` of 1 r/s, occupancy is around 2.5% of a
single worker.

### Rate limiting: still worth it, for different reasons in each mode

The wording "keep workers forking gpg" only describes the **synchronous** mode.
With the thread pool the worker is never blocked, so the emphasis shifts from
"protect other sites from worker starvation" to "bound resource use." A
globally-keyed `limit_req` is worth having in both modes:

- **Thread-pool mode (default): recommended.** A flood cannot starve co-hosted
  sites — the worker stays on its event loop — but without a limit an attacker
  can still keep all pool threads busy (so *logins* stall), spawn up to that many
  concurrent `gpg` processes, grow the pool's task queue, and hold connections
  and per-request memory. `limit_req` caps all of that. It is no longer the only
  thing standing between an attacker and worker exhaustion — the pool is — but it
  keeps the login endpoint and the box's resource use bounded.

- **Synchronous mode: required if this nginx serves anything else.** With no
  thread pool a verification blocks a worker, and workers are a shared pool, so
  login contention degrades every other site the instance serves. A
  globally-keyed `limit_req` is then not optional. If the instance serves only
  the protected location, it is recommended rather than required — the worst case
  is the admin itself being slow during a flood, with nothing else at stake.

Where a limit is used, **key it globally** — one bucket for the whole login
endpoint. A per-IP limit is optional, is not a substitute, and a deployment
should never be sized on it. `examples/nginx.conf` ships the global zone enabled
and the per-IP zone commented out.

Two things matter when configuring it:

1. **The global limit is the protection. A per-IP limit is not.** Use a constant
   key — one bucket for the entire login endpoint — because that is the only
   thing that actually bounds how many verifications can be in flight, and
   therefore the only thing that protects anything else this nginx serves.

   A per-IP limit (`$binary_remote_addr`) should be treated as fairness, not
   defence. It gives every source address its own allowance, and an attacker's
   supply of addresses is cheap: a few dollars of cloud capacity is thousands of
   IPs. It is also ineffective or actively misleading in exactly the deployments
   this module suits:

   - **Tor onion services** — every request reaches nginx from the local Tor
     daemon, so *all* users share one apparent address. A per-IP limit then
     throttles your legitimate users collectively while isolating no attacker at
     all.
   - **Behind a CDN or reverse proxy** — `$binary_remote_addr` is the proxy's
     address unless `ngx_http_realip_module` is configured, so again everyone
     lands in one bucket.
   - **Distributed sources** — a per-IP limit simply doesn't bound the total.

   Keep a per-IP zone if you want to stop one noisy client from consuming the
   global allowance, but size the deployment on the global limit alone and treat
   anything the per-IP zone catches as a bonus.
2. **Prefer a paced `burst` over `nodelay`** on the global zone, so excess
   logins are spread out rather than released at once into concurrent
   verifications. Note the trade-off: without `nodelay` an over-limit client
   *waits* (the connection is held, but nothing is forked) instead of getting an
   immediate `503`. Paced is gentler on legitimate users retrying a login and
   keeps concurrency smooth; add `nodelay` if you would rather shed load fast
   and not hold connections. Either bounds gpg work — only the failure mode
   differs.

Measured against `examples/nginx.conf`: under a burst of login submissions the
excess is throttled as configured, while ordinary requests to the same server
continue to be served in under a millisecond — the protected endpoint absorbs
the limit without the rest of the site noticing.

`examples/nginx.conf` shows both zones wired up, with the key restricted to
login submissions so ordinary traffic is never rate-limited. The module runs in
the PRECONTENT phase — *after* `limit_req` (PREACCESS) — so a rejected request
never reaches the verification path and never forks `gpg`.

## Residual risks and operational guidance

Things that are inherent to the design rather than defects, and what an
operator should do about them.

- **The HMAC secret lives in worker memory.** It has to: every challenge and
  session MAC is computed from it. It is therefore readable by anything that
  can read the worker's address space, and would appear in a core dump. Disable
  core dumps for workers (`ulimit -c 0` / `worker_rlimit_core 0`), keep the
  secret file `chmod 600` and owned by the worker user, and treat the ability to
  read worker memory as equivalent to holding the secret — it allows forging
  both sessions and challenges.

- **Redis traffic is cleartext unless TLS is enabled.** By default the nonce
  client speaks plain RESP over TCP, so the `AUTH` password and nonce values
  cross the network in clear — fine on localhost, not across a shared network.
  Set `pgp_auth_nonce_storage_tls on` to have the module negotiate TLS itself
  (OpenSSL, already linked by nginx — no extra dependency). The handshake
  completes before any data is sent, so `AUTH` is never exposed. The
  certificate is verified by default (`pgp_auth_nonce_storage_tls_verify on`);
  supply `pgp_auth_nonce_storage_tls_ca` for a private CA. Because the address
  must be a numeric IP, either the certificate carries an `iPAddress` SAN or
  you name the expected identity with `pgp_auth_nonce_storage_tls_name`, which
  is also sent as SNI. Verification failure fails the login closed rather than
  falling back to cleartext.

  Setting `pgp_auth_nonce_storage_tls_verify off` selects `SSL_VERIFY_NONE` — an
  encrypted but **unauthenticated** channel, open to a man-in-the-middle who can
  then answer the single-use `SET NX` and silently defeat replay protection.
  Verification is on by default and should be turned off only in controlled test
  environments, never in production. (Pentest CCS F-004.)

- **The Redis address must be a numeric `ip:port`.** Resolution is done with no
  DNS lookup (see above), so hostnames are rejected. IPv4 is the tested form;
  an IPv6 literal must be bracketed (`[::1]:6379`) — an unbracketed IPv6
  address is misparsed, and fails closed at connect time rather than being
  silently misdirected.

- **The revocation list is read on the request path.** Each request to a
  protected location `stat()`s the file to check its mtime, and re-reads and
  linearly scans it when it has changed. That keeps revocation effective within
  seconds without a reload, at the cost of a syscall per request and a scan
  proportional to the list's size. Keep the list on local disk rather than a
  network filesystem, and keep it to a sane number of entries; a very large list
  adds latency to every authenticated request.

- **The `memory` nonce backend is per-node and bounded.** It fails closed: when
  the zone is full and nothing in it has genuinely expired, logins are denied
  rather than a live nonce being evicted to make room — evicting one would let
  that challenge be replayed. Size `pgp_auth_nonce_zone_size` for your expected
  concurrent logins, or use the `redis` backend where single-use must hold
  across nodes and under sustained load.

- **`pgp_revocation_fail_open on` weakens revocation by design.** With it set, an
  unreadable revocation list admits keys instead of denying them. The module
  warns about this at start-up. Leave it off unless you have a specific
  availability reason.

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
