# ngx_http_pgp_auth

A native nginx module that authenticates users by **PGP signature** — a drop-in
alternative to HTTP basic auth for protecting reverse-proxied apps and internal
tools.

A protected location shows a one-time challenge. The user signs it with their
own key (e.g. **Kleopatra → Notepad → Sign**), pastes the signed block back, and
the module verifies it against a public keyring before granting a session. No
passwords, and the user's private key never leaves their machine.

## State model

The **authentication tokens themselves are stateless**. Both the challenge and
the session are HMAC-signed, not server-side records:

```
challenge = v1|<exp>|<nonce>|<mac>     mac = HMAC(secret, "v1|<exp>|<nonce>")
session   = <exp>|<fpr>|<mac>          mac = HMAC(secret, "<exp>|<fpr>")
```

The server recognises its own tokens by re-deriving the MAC with
`pgp_session_secret`, so a session or challenge needs nothing stored or
replicated — every node that shares the secret accepts the same tokens.

The one optional piece of state is **single-use challenge enforcement**
(`pgp_auth_nonce_storage`), which remembers spent challenges so a captured,
already-signed challenge can't be replayed inside its validity window:

- `memory` (default) — a per-node shared-memory zone. Cheap and dependency-free,
  but the seen-nonce set is local to each nginx instance and is cleared on
  restart, so it does not span multiple nodes.
- `redis` — a shared store, so single-use holds across every node pointed at the
  same Redis. Use this for a multi-node deployment that needs strict replay
  protection.
- `none` — no nonce state at all; fully stateless. A signed challenge may then be
  replayed until it expires, so keep `pgp_challenge_timeout` short and serve over
  HTTPS.

So out of the box it is stateless apart from a local single-use cache; pick
`redis` for shared single-use across nodes, or `none` for no server state at all.

## Directives

| Directive | Default | Meaning |
|-----------|---------|---------|
| `pgp_auth` | `off` | Enable PGP auth for this location. |
| `pgp_keyring` | `/etc/nginx/pubkeys.gpg` | Public keyring of allowed signers (absolute path). |
| `pgp_session_secret` | *(random)* | File with the HMAC secret. **Set this** for multi-node / restart-stable sessions. |
| `pgp_challenge_timeout` | `120s` | How long an issued challenge stays valid. |
| `pgp_session_timeout` | `1h` | Re-challenge interval. `0` = unlimited (the cookie never expires — a leaked/captured cookie then only ends via `pgp_revocation_list` or rotating the secret; keep a finite value unless you have a specific reason not to). |
| `pgp_session_cookie_secure` | `on` | Add `; Secure` to the session cookie. Set `off` for a plain-HTTP deployment (e.g. one already behind an encrypted transport). |
| `pgp_session_cookie_host_prefix` | `on` | Use the `__Host-` cookie name prefix. The prefix requires Secure, so it is applied only when `pgp_session_cookie_secure` is on; with Secure off it is dropped (nginx warns) so the cookie stays usable. |
| `pgp_session_cookie_samesite` | `Lax` | `SameSite` attribute on the session cookie: `Lax`, `Strict`, or `None`. `None` requires `pgp_session_cookie_secure` on. |
| `pgp_auth_bind_client_ip` | `on` | Fold the client IP into the token, blocking cross-IP replay. Behind a proxy, configure `ngx_http_realip_module`. Note this adds nothing where every client shares one apparent address — a Tor onion service, or a proxy without realip — since the bound value is then the same for everyone. |
| `pgp_auth_bind_user_agent` | `on` | Fold the User-Agent into the token, blocking cross-client replay. |
| `pgp_auth_nonce_storage` | `memory` | Single-use challenges: `memory` (shared zone), `redis`, or `none`. |
| `pgp_auth_nonce_storage_address` | — | `ip:port` of the Redis server (required for `redis`). Must be a **numeric IP**, not a hostname: resolution is done with no DNS lookup, so a slow/unreachable resolver can't block the worker on the login path. |
| `pgp_auth_nonce_storage_password` | — | Redis `AUTH` password (optional, `redis` only). Sent immediately after connecting; the `SET` is never issued if `AUTH` doesn't return `+OK`. |
| `pgp_auth_nonce_zone_size` | `8m` | Size of the shared-memory zone for the `memory` nonce backend. Raise this for deployments with many concurrent logins; the zone fails closed (denies) when full rather than silently dropping replay protection. **This backs one shared-memory segment for the whole nginx config** (zones are identified by name, not per-location), so set it once -- e.g. at the `http` or `server` level -- rather than per-location; declaring different sizes for different locations makes `nginx -t` fail with a `"conflicts with already declared size"` error. |
| `pgp_revocation_list` | — | File of revoked **primary** key fingerprints (one per line; `#` comments allowed). Spacing and case are ignored, so a fingerprint pasted straight from `gpg --fingerprint` works. Revokes the key and its live sessions; re-read on change, no reload. |
| `pgp_revocation_fail_open` | `off` | Only applies when `pgp_revocation_list` is set: if that file can't be read, `off` denies access (fail closed), `on` allows. With no list configured, revocation is simply not in use and access is allowed. |
| `pgp_gpg_path` | `/usr/bin/gpg` | Absolute path to the `gpg` binary. Must be absolute; the module `execve()`s it directly (no `$PATH` search, no inherited environment). |
| `pgp_gpg_timeout` | `2s` | Max time for one gpg verification before it is killed. |
| `pgp_auth_max_body_size` | `16k` | Reject a login body larger than this before reading it or spawning gpg. |

All directives are valid at `http`, `server`, and `location` scope.

The login endpoint is unauthenticated and a submission forks a gpg verification,
which occupies a worker for ~17–25 ms. **Rate-limiting it with `limit_req` is
required, not optional**, and it must be keyed **globally** — one bucket for the
whole endpoint. That global limit is the protection; a per-IP limit is fairness
at best, since source addresses are cheap to obtain and everyone shares one
apparent address behind a Tor onion service or an unconfigured proxy.
`examples/nginx.conf` shows the full pattern; [SECURITY.md](SECURITY.md) has the
measured per-request costs and the sizing arithmetic. Also set
`client_max_body_size` on the protected location to match the module's
`pgp_auth_max_body_size` cap (16k), so an HTTP/2 request with no declared length
can't be buffered larger than intended before the module's own cap applies.

```nginx
location / {
    pgp_auth              on;
    pgp_keyring           /etc/nginx/pubkeys.gpg;
    pgp_session_secret    /etc/nginx/pgp_secret.key;
    pgp_challenge_timeout 300s;
    pgp_session_timeout   24h;
    proxy_pass            http://127.0.0.1:8080;
}
```

## Build

The module needs the system `gpg` binary at runtime and OpenSSL at build time
(already an nginx dependency). Verification shells out to `gpg`, so there is no
extra crypto library to install.

**Dynamic module** (recommended):

```sh
./configure --with-compat --add-dynamic-module=/path/to/nginx-pgp-auth
make modules
cp objs/ngx_http_pgp_auth_module.so /etc/nginx/modules/
# then: load_module modules/ngx_http_pgp_auth_module.so;
```

**Static** (compiled into nginx):

```sh
./configure --add-module=/path/to/nginx-pgp-auth
make
```

Tested against Debian's nginx (Bookworm 1.22, Trixie 1.26.3). On Debian/Ubuntu
you also need `libssl-dev` and the matching `nginx-dev` headers.

## Setup

```sh
# 1. allowed signers
scripts/build-keyring.sh alice.asc bob.asc > /etc/nginx/pubkeys.gpg

# 2. shared HMAC secret (same file on every node)
scripts/gen-secret.sh > /etc/nginx/pgp_secret.key
chown nginx /etc/nginx/pgp_secret.key   # the worker user
chmod 600 /etc/nginx/pgp_secret.key
```

The secret can forge both sessions and challenges, so keep it readable only by
the nginx worker user (`chmod 600`). The module logs a `warn` at start-up if the
file is group- or world-accessible.

The **nginx worker user** (e.g. `www-data`/`nginx`) must be able to read both
the keyring and the secret, and to write a throwaway directory under the system
temp dir while verifying. The defaults under `/etc/nginx` cover this. If
verification fails, nginx logs the exact gpg exit code and message at `warn`
level — an "exit 2 / cannot open keyring" there means a permissions problem, not
a bad signature.

## Security model

- A session is granted only for a signature from a key **in the keyring** over a
  challenge **the server issued and has not expired**.
- The challenge MAC binds it to this server: a valid key holder still cannot
  authenticate with a challenge we never issued.
- Sessions are stateless. To revoke everyone, rotate `pgp_session_secret`. A key
  removed from the keyring is rejected at the next re-challenge.
- **Single-use across nodes:** with `pgp_auth_nonce_storage none` — or `memory`,
  whose seen-nonce cache is per-node — a captured, already-signed challenge can
  be replayed within `pgp_challenge_timeout`, so keep it short and serve over
  HTTPS. For strict single-use across every node, use `pgp_auth_nonce_storage
  redis` (a shared store); the default `memory` gives per-node enforcement with
  no extra dependency.

For the threat model, defensive design, and how memory safety is verified
(ASan/UBSan + the attack suite), see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
