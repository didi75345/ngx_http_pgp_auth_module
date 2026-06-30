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
  keys never reach the server.
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

## Reporting

Please report security issues privately to the maintainer rather than via a
public issue.
