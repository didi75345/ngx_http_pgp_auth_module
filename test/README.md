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

Needs `nginx`, `gpg`, `curl`. Point the script at your nginx and the built
module:

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

Expected output ends with `RESULT: 8 passed, 0 failed`.
