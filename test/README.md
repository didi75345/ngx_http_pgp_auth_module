# Testing

Two ways to verify the module: locally, or reproducibly on real Debian via
Docker. Both run the same suite (`run-tests.sh`): the full PGP login flow plus
attack cases that must all be rejected.

## On real Debian (recommended for review)

```sh
# Trixie (nginx 1.26.3)
docker build -f test/Dockerfile --build-arg DEBIAN_RELEASE=trixie \
             --build-arg NGINX_VERSION=1.26.3 -t pgpauth:trixie .
docker run --rm pgpauth:trixie

# Bookworm (nginx 1.22.1)
docker build -f test/Dockerfile --build-arg DEBIAN_RELEASE=bookworm \
             --build-arg NGINX_VERSION=1.22.1 -t pgpauth:bookworm .
docker run --rm pgpauth:bookworm
```

The image build compiles the module with `-Wall -Werror`, so a warning fails
the build. The container run prints each check and exits non-zero on any
failure.

## Locally

Needs `nginx`, `gpg`, `curl`. Optional: `redis-server` on `PATH` to also
exercise the Redis nonce backend + `AUTH` (skipped otherwise). Point the
script at your nginx and the built module:

```sh
NGINX_BIN=/usr/sbin/nginx \
MODULE_SO=/path/to/ngx_http_pgp_auth_module.so \
sh test/run-tests.sh
```

## What is checked

Positive flow:
- unauthenticated GET returns a challenge page
- a valid signature over the issued challenge returns `302` + session cookie
- the session cookie grants access

Attack cases (each must be rejected):
- forged / random session cookie
- signature from a key not in the keyring
- valid signature over a challenge the server never issued (bad HMAC)
- expired challenge
- garbage / non-PGP body

Hardening added in the latest round (always run unless noted):
- login page carries `X-Frame-Options`, `Content-Security-Policy`,
  `X-Content-Type-Options`, `Cache-Control`, `Referrer-Policy`
- `pgp_gpg_path` rejects a relative value at config time (`nginx -t` fails)
- `pgp_gpg_path` pointing at a real absolute `gpg` still logs in (execve
  regression check)
- `pgp_gpg_path` pointing at a nonexistent binary fails *safely*: login is
  rejected and nginx keeps running, rather than crashing or falling back to
  a `$PATH` search
- `pgp_auth_nonce_zone_size` parses and a small custom zone still grants
  login and enforces single-use
- Redis nonce backend + `pgp_auth_nonce_storage_password`: correct password
  logs in and enforces replay via Redis; a wrong password fails closed
  (login denied, no unauthenticated `SET`) -- **only runs if `redis-server`
  is on `PATH`**, otherwise this block is skipped with a `SKIP` line

Expected output ends with `RESULT: N passed, 0 failed`. `N` varies with your
environment: the HTTP/2 and Redis checks add a few more passes when
`nginx -V` reports `http_v2` / `redis-server` is installed, and are skipped
(without affecting the pass/fail count) otherwise. Any `FAIL` line, or a
nonzero exit code, means something regressed.
