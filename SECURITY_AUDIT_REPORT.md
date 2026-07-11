# Security Source-Code Audit — `ngx_http_pgp_auth_module`

**Target:** nginx HTTP module `ngx_http_pgp_auth_module` (C, ~2,015 LOC)
**Scope:** `src/ngx_http_pgp_auth_module.c`, `src/ngx_http_pgp_auth_gpg.c`, `src/ngx_http_pgp_auth_nonce.c` and headers
**Method:** Manual white-box source review with a specific focus on memory-safety bug classes (buffer overflow, use-after-free, NULL-pointer dereference, integer overflow, format-string, out-of-bounds read/write, double free, stack overflow, memory leak, uninitialized memory), plus authentication-logic and availability review.
**Build reviewed:** commit `b457ff0` (§1–§5); re-tested at commit `80178df` (§6).

> **Re-test note (§6):** After the first pass the maintainer landed commit
> `80178df` ("Second pentest: DoS hardening, fail-closed revocation, reject
> truncated gpg"), which fixes **PGP-01, PGP-02 and PGP-03**. Section 6 records a
> full re-test of that commit — dynamic and static gates re-run, fixes verified
> empirically, and one **new residual finding (PGP-10)** identified. Read §6
> alongside §1–§5; where they differ, §6 is current.

---

## 1. Executive summary

This is a defensively written module. Every attacker-reachable parse path I
traced uses length-bounded copies into pre-sized buffers, per-request memory
comes from the nginx request pool (so there is no hand-rolled free path to
mis-order), and the one long-lived manual allocation (the revocation cache) is
freed-before-replace under a single-threaded worker. **I found no exploitable
memory-corruption defect** in any of the ten classes requested. That negative
result is meaningful here because it was reached by reading each bounded copy by
hand, and it is consistent with the project's own ASan/UBSan, Valgrind, cppcheck
and `-fanalyzer` runs.

The findings that remain are **not memory-corruption bugs** — they are
availability, fail-open, and information-exposure issues in the surrounding
design. The most important one (**PGP-01**) is that an unauthenticated request
can force a synchronous `fork()` + `gpg` execution that blocks the whole worker
for up to 5 seconds; this is rate-limitable but is not throttled by default.

| ID | Severity | Class | Summary |
|----|----------|-------|---------|
| PGP-01 | **Medium** | Availability | Unauthenticated POST forces a blocking `gpg` fork (≤5 s) inside the worker event loop; DoS unless `limit_req` is configured |
| PGP-02 | **Medium** | Access control | Revocation list **fails open** on any stat/open/read error — a temporarily unreadable file silently disables revocation |
| PGP-03 | Low | Robustness | Silent 8 KiB truncation of `gpg` `--status-fd` and `--output`; large signed messages fail, and a multi-signature status stream could have a rejection marker truncated away |
| PGP-04 | Low | Replay | `nonce_storage none`, and the per-node `memory` backend in a multi-node deployment, permit challenge replay within the challenge window (config-dependent, documented) |
| PGP-05 | Low | Info exposure | Raw `gpg` status output is echoed into the nginx error log on failure |
| PGP-06 | Low | Availability | Large stack frames (~8 KiB result struct + ~20 KiB in the verify call chain); fine on default nginx, relevant only on constrained stacks |
| PGP-07 | Info | Robustness | Revocation reload keyed only on `mtime`; in-place edits preserving `mtime` are missed. Blocking file I/O runs in the event loop |
| PGP-08 | Info | Access control | `bind_client_ip` behind a proxy without `realip` binds to the proxy IP, silently weakening cross-client binding |
| PGP-09 | Info | Robustness | Form parser only decodes a `signed=`-first body; otherwise the entire body is treated as the clear-signed blob |

---

## 2. Memory-safety analysis (the requested classes)

Each class below was checked by reading the actual bounds, not by trusting the
comments. Verdict per class, with the reasoning.

### 2.1 Buffer overflow / out-of-bounds write — **No defect found**

Every write path is pre-sized:

- **Challenge/cookie construction** (`ngx_http_pgp_send_challenge`,
  `ngx_http_pgp_grant`): each `ngx_pnalloc` is computed from the exact component
  lengths (`plen + 1 + mac.len`, etc.) before the `ngx_sprintf`, and the page
  body reserves `head + clen + 1024` where the static template measures ~0.5 KiB
  — comfortably within the slack. `module.c:657`, `module.c:735`, `module.c:741`.
- **`gpg` status read** (`gpg.c:224`): `read(pfd[0], out + off, sizeof(out) - 1 - off)`
  with a loop invariant that `off ≤ sizeof(out) - 1`, so the reserved `out[off] = '\0'`
  at `gpg.c:240` is always in bounds.
- **Plaintext capture** (`gpg.c:254`): `read(fd, res->plaintext + off, sizeof(res->plaintext) - off)`,
  breaking as soon as `off >= sizeof(res->plaintext)`; the buffer is used strictly
  via `plaintext_len`, never as a C string, so the absence of a terminator is safe.
- **Fingerprint copy** (`gpg.c:295`): the `VALIDSIG` scan is bounded by
  `(size_t) n < sizeof(res->fpr) - 1` and NUL-terminates.

### 2.2 Out-of-bounds read — **No defect found**

The challenge search in the verified plaintext (`module.c:536`) is gated by
`p + 3 <= last`, and every field split uses `ngx_strlchr(p, last/line_end, '|')`
which cannot walk past the supplied end pointer. The percent-decoder
(`module.c:871`) guards the two-hex-digit read with `src + 2 < last` — correct,
since both `src+1` and `src+2` must be valid indices.

Note the correct use of `%*s` (width-bounded) rather than `%s` for the
non-NUL-terminated `nonce_hex` and `payload` buffers at `module.c:725`,
`module.c:739` — a plain `%s` there would have over-read. This is right.

### 2.3 Use-after-free / double free — **No defect found**

Per-request data is pool-allocated and never manually freed. The only manual
allocation is the per-worker revocation cache (`module.c:326` `ngx_alloc`), and
the reload path frees the previous buffer *before* overwriting the pointer
(`module.c:339-343`). Because an nginx worker processes the event loop
single-threaded and `ngx_http_pgp_is_revoked` is fully synchronous (blocking
`read`), there is no re-entrancy that could double-free or read a freed buffer.

### 2.4 NULL-pointer dereference — **No defect found**

`r->headers_in.user_agent` is NULL-checked before dereference (`module.c:247`).
The secret is always populated by `merge_loc_conf` (loaded from file, inherited,
or randomly generated) before any handler that dereferences `plcf->secret.data`
can run, and the handler early-returns when `enable` is off. `zone == NULL` is
handled in the memory backend (`nonce.c:151`).

### 2.5 Integer overflow — **No defect found**

The only arithmetic on attacker-influenced lengths is
`total = len + 1 + ip.len + 1 + ua.len` (`module.c:259`); all operands are
small (payload, a ~45-byte IP text, a header-bounded UA), nowhere near `size_t`
wraparound. TTL/size math in the redis and nonce paths is likewise bounded.

### 2.6 Format-string — **No defect found**

I specifically checked every `ngx_log_error` / `ngx_sprintf` call for
attacker-controlled format arguments. The one place raw `gpg` output is logged
(`gpg.c:337`) correctly passes it as a `%s` *argument*, not as the format
string. No user-controlled data reaches a format specifier.

### 2.7 Stack overflow — see **PGP-06** (Low, not a corruption)

No unbounded recursion or VLAs. The concern is only the *size* of fixed frames
(a ~8 KiB `ngx_http_pgp_verify_result_t` plus ~16–20 KiB of buffers across the
verify call chain), which is safe on nginx's default worker stack.

### 2.8 Memory leak — **No defect found**

Pool allocations are released at request end. The revocation cache is
intentionally long-lived and is freed-before-replace; it is released at worker
exit by process teardown.

### 2.9 Uninitialized memory — **No defect found**

`ngx_http_pgp_verify_result_t vr` is declared without initialization at
`module.c:507`, but `ngx_http_pgp_gpg_verify` sets `valid`, `fpr_len` and
`plaintext_len` to 0 as its first action (`gpg.c:86-88`), and every subsequent
read of `fpr`/`plaintext` is gated by those lengths. There is no path that reads
uninitialized bytes out of the struct.

**Bottom line for Section 2:** the memory-safety posture is strong and matches
the project's sanitizer/analyzer evidence. The remaining findings are design and
availability issues, below.

---

## 3. Findings

### PGP-01 — Unauthenticated request forces a blocking `gpg` fork (Medium, Availability)

**Location:** `module.c:964-972` (handler) → `ngx_http_pgp_auth_submit` →
`ngx_http_pgp_gpg_verify` (`gpg.c:68`).

Any client can `POST …?__pgp_auth=1` with a body and, with no prior
authentication, drive the worker into `fork()` + `execlp("gpg", …)` followed by
a **blocking** `poll()`/`read()`/`waitpid()` loop that runs up to
`NGX_HTTP_PGP_GPG_TIMEOUT_MS` = 5,000 ms (`gpg.c:27`, `gpg.c:198-247`). This
work happens on the nginx event-loop thread, so for its duration that worker
serves no other connection. With `W` workers, `W` concurrent slow submissions
stall the entire server. A ~1 MB armored blob (default `client_max_body_size`
is 1 MB) that `gpg` chews on until the 5 s cap makes each request maximally
expensive.

The module is deliberately placed in the ACCESS phase *after* `limit_req`
(`module.c:1164-1174`) precisely so this can be throttled — but nothing in the
module *enforces* a limit, and a default install has none.

**Recommendation:**
- Document a **mandatory** `limit_req` (keyed on the `__pgp_auth` arg or client
  address) and `limit_conn` as part of the supported configuration, and ship it
  as the default in `examples/nginx.conf` rather than as an optional note.
- Consider a hard cap on the accepted body size for the auth POST (reject
  oversized bodies before writing them out for `gpg`), independent of the
  server-wide `client_max_body_size`.
- Lower the default `gpg` timeout (5 s is generous for a legitimate verify that
  normally completes in single-digit milliseconds).

### PGP-02 — Revocation list fails open (Medium, Access control)

**Location:** `ngx_http_pgp_is_revoked`, `module.c:309-336`.

If `ngx_file_info` (stat) fails the function returns `0` = *not revoked*
(`module.c:313`, explicitly commented "fail open"). The same happens if
`ngx_open_file` fails (`module.c:322-324`) or the read returns an error
(`module.c:333-335`). Consequently, any condition that makes the revocation file
transiently unreadable — a permissions slip, the file living on a flaky network
mount, momentary FD exhaustion, or an operator mistake — **silently disables
revocation** for both new logins and existing sessions, with only a log line.
For a control whose entire purpose is emergency key revocation, fail-open is the
wrong default.

**Recommendation:** make the failure mode configurable and default to
**fail-closed** (a configured-but-unreadable revocation list should deny, not
allow). At minimum, treat "list configured but stat/open failed" differently
from "no list configured," and raise the log level so the operator is alerted.

### PGP-03 — Silent 8 KiB truncation of `gpg` output (Low, Robustness)

**Location:** `gpg.c:224-240` (status), `gpg.c:253-268` (plaintext);
`NGX_HTTP_PGP_PLAINTEXT_MAX` = 8192 (`gpg.h:16`).

Both the `--status-fd` stream and the verified plaintext are read into fixed
8 KiB buffers and the read loop simply **stops** when full — no error is raised.
Two consequences:

1. A legitimately large signed message (> 8 KiB of signed content, e.g. the user
   pasted extra text around the challenge) is truncated; if the challenge line
   falls beyond the boundary it will not be found and the login fails with a
   confusing "no challenge inside the signed content."
2. With a **multi-signature** message the status stream carries one block of
   status lines per signature. Truncation drops later lines; a `REVKEYSIG` /
   `BADSIG` marker on a later signature could be cut off while an earlier
   `VALIDSIG` survives, and `res->valid = good && !bad` would then read `valid`.
   This is **not** a privilege escalation on its own — producing a `VALIDSIG`
   still requires a genuine signature from a key already in the keyring, i.e. an
   already-authorized signer — but it is an unnecessary sharp edge in the trust
   decision.

**Recommendation:** treat "output buffer filled" as a hard verification failure
rather than proceeding on a truncated stream, and either raise
`NGX_HTTP_PGP_PLAINTEXT_MAX` or explicitly reject oversized signed content with
a clear message.

### PGP-04 — Replay window with `none` / single-node `memory` (Low, Replay)

**Location:** `nonce.c` backends; default is `memory` (`module.c:1076`).

With `pgp_auth_nonce_storage none` a valid challenge can be replayed until it
expires (default 120 s). With the `memory` backend the seen-nonce set is
per-node, so in a multi-node deployment the same challenge can be replayed
against a *different* node inside the window. This is documented and the secure
defaults (memory backend, 120 s challenge, client binding) mitigate it, but it
should remain an explicit operational warning: multi-node deployments need the
`redis` backend for cross-node single-use enforcement.

### PGP-05 — `gpg` status echoed to the error log (Low, Info exposure)

**Location:** `gpg.c:337-340`.

On any failed verification the raw `gpg` status/stderr capture is logged at
`WARN`, including fingerprints / key IDs and other metadata about the submitted
signature. An unauthenticated attacker can therefore write chosen content into
the server logs and cause key-related metadata to be recorded. Low impact, but
worth scrubbing to the essentials (exit code + a short reason) in production.

### PGP-06 — Large stack frames in the verify path (Low, Availability)

**Location:** `vr` at `module.c:507` (~8.3 KiB); `gpg.c` locals — `out[8192]`
plus three `PATH_MAX` (4096) buffers (`gpg.c:76-81`).

The verification call chain consumes on the order of 20–25 KiB of stack. This is
safe on nginx's default worker stack, but is worth keeping in mind for
unusual/constrained builds. Moving the large buffers to pool/heap allocation
would remove the concern entirely.

### PGP-07 — `mtime`-only revocation reload + blocking I/O (Info)

The revocation cache reloads only when the file's `mtime` changes
(`module.c:317-318`). An in-place edit that preserves `mtime` (e.g. some
copy/restore tools) would not be picked up. Separately, the reload does blocking
file I/O on the event-loop thread; small file, low frequency, but it is
synchronous work in the worker.

### PGP-08 — `bind_client_ip` behind a proxy (Info)

`bind_ip` folds `r->connection->addr_text` into the MAC (`module.c:244-246`).
Behind a reverse proxy without `ngx_http_realip_module`, that value is the
proxy's address for every client, so the cross-client binding degrades to
"same proxy" — i.e. no binding among users sharing the proxy. This is called out
in `SECURITY.md`; flag it prominently in the deployment guide since the failure
is silent.

### PGP-09 — Form parser decodes only a `signed=`-first body (Info)

`ngx_http_pgp_form_field` (`module.c:848`) requires the body to *start* with
`signed=`; otherwise the caller falls back to treating the **entire** raw body
as the clear-signed blob (`module.c:916-918`). Functionally fine (the PGP block
markers still gate `gpg`), but a body like `x=1&signed=…` would not be parsed as
intended. Robustness only.

---

## 4. Positive controls confirmed

These were reviewed and found sound — worth stating explicitly for the client:

- **No command injection.** `gpg` is launched via `execlp` with a fixed argument
  vector; message content goes to a file, never to `argv`, and no shell is
  involved (`gpg.c:175-185`).
- **Challenge is bound to the signed bytes.** The signature is verified first and
  the challenge is searched **only** inside `vr.plaintext` (the `--output` bytes
  gpg actually verified), defeating append/prepend-outside-the-signature attacks
  (`module.c:509-545`).
- **Status parsing is hardened.** Only exact `[GNUPG:] ` lines are trusted,
  status is on a separate pipe from stderr, short fingerprints are rejected, and
  `REVKEYSIG`/`EXPKEYSIG`/`EXPSIG`/`BADSIG`/`ERRSIG` fail closed (`gpg.c:283-317`).
- **Constant-time MAC comparison** via `CRYPTO_memcmp` (`module.c:381`).
- **SIGCHLD race handled** around fork/wait (`gpg.c:138-247`); stuck `gpg` is
  SIGKILLed on a monotonic-clock deadline.
- **Nonce store fails closed** — a backend error rejects the login rather than
  silently disabling replay defence (`module.c:606-610`).
- **RESP redis command is length-prefixed** (`$%uz` bulk strings), so a nonce
  cannot inject a second command even in principle; and the nonce is
  HMAC-authenticated as our own 32-hex value before it reaches the store
  (`nonce.c:348-352`).
- **Throwaway `GNUPGHOME`** created with `mkdtemp` (0700) and wiped after each
  verify (`gpg.c:40-65`, `gpg.c:98`).

---

## 5. Prioritized remediation

1. **PGP-01** — ship and document mandatory `limit_req`/`limit_conn` for the auth
   endpoint; cap the auth-POST body size; reduce the default gpg timeout.
2. **PGP-02** — add a fail-closed revocation mode and make it the default.
3. **PGP-03** — reject truncated/oversized gpg output instead of proceeding.
4. **PGP-05 / PGP-06 / PGP-07 / PGP-08** — log scrubbing, move large buffers off
   the stack, harden the revocation reload trigger, document the proxy/realip
   requirement prominently.

**Overall assessment:** memory-safe and carefully engineered against its stated
threat model. No memory-corruption vulnerability was found. The residual risk is
concentrated in availability (PGP-01) and a fail-open revocation default
(PGP-02), both fixable with configuration/policy changes rather than rewrites.

---

## 6. Re-test at commit `80178df`

The maintainer hardened the code after §1–§5. This section re-verifies the whole
module at the new HEAD, on Ubuntu 24.04 / gcc 13.3 / nginx 1.26.3.

### 6.1 What the fix commit changed (diff `b457ff0..80178df`, verified by reading)

- **PGP-01 (DoS) — addressed.** New `pgp_auth_max_body_size` (default 16384)
  rejects an oversized auth body with **413 before** the body is read or gpg is
  forked; new `pgp_gpg_timeout` makes the kill-deadline configurable and lowers
  the default from 5000 ms to **2000 ms**; and a cheap pre-filter now requires
  the marker `-----BEGIN PGP SIGNED MESSAGE-----` in the body (`ngx_strnstr`,
  length-bounded — checked for over-read, safe) so garbage submissions are
  rejected **before** any `fork()`.
- **PGP-02 (fail-open revocation) — addressed.** New `pgp_revocation_fail_open`
  flag, default **0 = fail closed**; every stat/open/alloc/read error path in
  `ngx_http_pgp_is_revoked` now returns `deny` instead of `0`.
- **PGP-03 (silent truncation) — addressed.** A filled status *or* plaintext
  buffer now sets `truncated`, SIGKILLs gpg, and forces
  `res->valid = good && !bad && !truncated`, so a truncated verification can
  never authenticate.

### 6.2 Automated gates — all clean on current source

| Gate | Tool | Result |
|------|------|--------|
| Static analysis | `gcc -fanalyzer -Wall -Wextra` (all 3 `.c`) | **clean** — no `-Wanalyzer` findings |
| Static analysis | `cppcheck --enable=warning,performance,portability` | **clean** — no findings |
| Compile | nginx build, `-Werror` | **clean** — no warnings, all 3 sources incl. `nonce.c` |
| ASan + UBSan | `test/sanitize.sh` (valid/garbage/empty/bad-%/forged-cookie/oversized) | **clean** — no faults in the module |
| Valgrind memcheck | `test/memcheck.sh` (`--track-origins=yes`) | **clean** — no invalid read/write, uninit, or leak in the module |
| Functional + attack | `test/run-tests.sh` | **16 passed, 0 failed** |

The 16 functional cases include the three new hardening assertions:
`unreadable revocation list fails closed`, `oversized auth body rejected (413)`,
and `non-PGP body rejected pre-fork` — all pass.

### 6.3 Independent verification of the fixes (my own probes, outside the suite)

- **PGP-03 confirmed empirically.** A message **validly signed by a keyring key**
  carrying a **genuine unexpired challenge as its first line**, but with the
  signed plaintext padded to 12,112 bytes (> the 8 KiB buffer), was **rejected
  (403, no cookie)**. The byte-identical flow with a small plaintext succeeded
  (303 + cookie). Same key, same challenge format — so the rejection is the
  truncation gate, not any other check. Pre-fix, this would have authenticated.
- **PGP-02 / PGP-01 confirmed** via the suite's fail-closed and 413 cases plus a
  direct 500 KB `Content-Length` POST → **413** before gpg.

### 6.4 New residual finding

#### PGP-10 — Body-size cap is bypassable with `Transfer-Encoding: chunked` (Low, Availability)

**Location:** `ngx_http_pgp_auth_handler`, the 413 pre-check
(`r->headers_in.content_length_n > (off_t) plcf->max_body_size`).

The cap is enforced only against `Content-Length`. A **chunked** request carries
`content_length_n == -1`, so the check (`-1 > 16384` is false) is skipped and the
body is accepted past the cap. Reproduced live:

| Request | Result |
|---------|--------|
| 500 KB body, `Content-Length` | **413** (capped, as intended) |
| 500 KB body, `Transfer-Encoding: chunked` | **403** — cap skipped, body read, then rejected |

Impact is **bounded and does not reach gpg**: because a >16 KB body also exceeds
`client_body_buffer_size` (16 KB), nginx spills it to a **temp file on disk**,
and `ngx_http_pgp_read_body` refuses disk-buffered bodies (`buf->in_file` →
`NGX_ERROR` → 403) *before* gpg is forked. So the residual exposure is
attacker-driven **disk writes of up to `client_max_body_size` (default 1 MB) per
unauthenticated request** to the client-body temp dir — I/O churn, not gpg-CPU
amplification, and not a memory-safety issue. Confirmed in the error log:
`a client request body is buffered to a temporary file … pgp_auth: request body
buffered to disk`, with **no** "auth body too large" line for the chunked case.

**Recommendation:** also enforce the cap when the length is unknown — e.g. reject
the auth POST when `content_length_n < 0` (chunked/unknown length is never
legitimate for a few-hundred-byte signed challenge), or re-check the accumulated
size inside `ngx_http_pgp_read_body`. Operationally, keep `client_max_body_size`
small on the protected location and keep the mandatory `limit_req`/`limit_conn`
from PGP-01.

**Status: RESOLVED.** The maintainer refined the fix to avoid the HTTP/2
false-positive I flagged: only an **HTTP/1.1 chunked** body is rejected up front
(closing the disk-buffering path), while any other unknown-length body —
including a legitimate **HTTP/2** stream — is read and **size-capped in the body
handler** instead. A chunked 500 KB now returns **413** like the Content-Length
case, and a normal HTTP/2 login is unaffected. Both behaviours are locked in by
new regression tests (chunked-413 and an HTTP/2 login built against
`ssl + http/2`), bringing the suite to **18/18** on both Debian targets, still
clean under gcc `-fanalyzer`, cppcheck, ASan/UBSan and Valgrind.

### 6.5 Re-test verdict

**PGP-01, PGP-02, PGP-03 fixed and verified; PGP-10 (found during the re-test)
subsequently fixed.** Memory-safety across all ten requested classes remains
**clean** under `-fanalyzer`, cppcheck, ASan/UBSan, and Valgrind on every
exercised path. As of the final push the automated suite is **18/18** on both
Debian targets. **No High/Critical issues remain, and no memory-corruption
defect was found in either round.** The only open items are the documented
by-design trade-offs (PGP-04..09), accepted for the current deployment model.
