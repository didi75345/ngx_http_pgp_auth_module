# ngx_http_pgp_auth

A native nginx module that authenticates users by **PGP signature** — a drop-in
alternative to HTTP basic auth for protecting reverse-proxied apps and internal
tools.

A protected location shows a one-time challenge. The user signs it with their
own key (e.g. **Kleopatra → Notepad → Sign**), pastes the signed block back, and
the module verifies it against a public keyring before granting a session. No
passwords, and the user's private key never leaves their machine.

## Why it's stateless

Both the challenge and the session are **HMAC-signed tokens**, not server-side
records:

```
challenge = v1|<exp>|<nonce>|<mac>     mac = HMAC(secret, "v1|<exp>|<nonce>")
session   = <exp>|<fpr>|<mac>          mac = HMAC(secret, "<exp>|<fpr>")
```

The server recognises its own tokens by re-deriving the MAC, so there is nothing
to store and nothing to replicate. Run as many nginx containers as you like —
they only need to share one secret (`pgp_session_secret`).

## Directives

| Directive | Default | Meaning |
|-----------|---------|---------|
| `pgp_auth` | `off` | Enable PGP auth for this location. |
| `pgp_keyring` | `/etc/nginx/pubkeys.gpg` | Public keyring of allowed signers (absolute path). |
| `pgp_session_secret` | *(random)* | File with the HMAC secret. **Set this** for multi-node / restart-stable sessions. |
| `pgp_challenge_timeout` | `120s` | How long an issued challenge stays valid. |
| `pgp_session_timeout` | `1h` | Re-challenge interval. `0` = unlimited. |
| `pgp_session_cookie_secure` | `on` | Add `; Secure` to the session cookie (set `off` for plain-HTTP, e.g. a Tor hidden service where the transport is already encrypted). |
| `pgp_session_cookie_host_prefix` | `on` | Use the `__Host-` cookie name prefix (auto-dropped when the cookie is not Secure). |
| `pgp_auth_bind_client_ip` | `on` | Fold the client IP into the token, blocking cross-IP replay. Behind a proxy, configure `ngx_http_realip_module`. |
| `pgp_auth_bind_user_agent` | `on` | Fold the User-Agent into the token, blocking cross-client replay. |
| `pgp_auth_nonce_storage` | `memory` | Single-use challenges: `memory` (shared zone), `redis`, or `none`. |
| `pgp_auth_nonce_storage_address` | — | `host:port` of the Redis server (required for `redis`). |
| `pgp_revocation_list` | — | File of revoked key fingerprints (one per line). Revokes the key and its live sessions; re-read on change, no reload. |
| `pgp_revocation_fail_open` | `off` | If the revocation list can't be read, `off` denies access (fail closed); `on` allows. |
| `pgp_gpg_timeout` | `2s` | Max time for one gpg verification before it is killed. |
| `pgp_auth_max_body_size` | `16k` | Reject a login body larger than this before reading it or spawning gpg. |

All directives are valid at `http`, `server`, and `location` scope.

Because the login endpoint is unauthenticated and each attempt spawns gpg,
**rate-limit it** with nginx's `limit_req` — see `examples/nginx.conf`.

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
- **Trade-off:** without shared state, single-use cannot be strictly enforced
  across nodes — within `pgp_challenge_timeout` a captured, already-signed
  challenge could be replayed. Keep the timeout short and serve over HTTPS.
  Strict single-use would require a shared store (e.g. Redis); deliberately left
  out to avoid the dependency.

For the threat model, defensive design, and how memory safety is verified
(ASan/UBSan + the attack suite), see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
