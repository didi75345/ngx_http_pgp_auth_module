#!/bin/sh
# Static analysis of the module sources with GCC's built-in analyzer
# (-fanalyzer, GCC >= 10). Catches null-deref, use-after-free, double-free,
# memory leaks, and use of uninitialized values. Fails on any finding in the
# module sources. Needs only the nginx source tree for headers.
#
#   NGINX_VERSION=1.26.3 sh test/analyze.sh
set -eu

NGINX_VERSION="${NGINX_VERSION:-1.26.3}"
HERE="$(CDPATH= cd "$(dirname "$0")/.." && pwd)"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

cd "$BUILD"
curl -fsSL -o nginx.tgz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar xzf nginx.tgz
cd "nginx-${NGINX_VERSION}"
# configure only to generate objs/ngx_auto_config.h etc. (headers for the addon)
./configure --with-compat --add-dynamic-module="$HERE" \
    --without-http_rewrite_module --without-http_gzip_module >/dev/null

INCS="-I src/core -I src/event -I src/event/modules -I src/os/unix -I objs
      -I src/http -I src/http/modules"
# newer nginx keeps QUIC event headers in a subdir; include if present
[ -d src/event/quic ] && INCS="$INCS -I src/event/quic"

rc=0
for f in ngx_http_pgp_auth_module ngx_http_pgp_auth_gpg ngx_http_pgp_auth_nonce; do
    echo "== analyzing src/$f.c =="
    out="$BUILD/$f.analyzer"
    gcc -fanalyzer -Wall -c -fPIC -O1 -g $INCS \
        "$HERE/src/$f.c" -o /dev/null 2>"$out" || rc=1
    # analyzer findings are warnings; treat any as a failure
    if grep -q '\-Wanalyzer' "$out"; then
        grep -E 'warning:|note:' "$out"
        rc=1
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "RESULT: clean -- no analyzer findings in the module sources"
else
    echo "RESULT: FAIL -- see analyzer output above"
fi
exit "$rc"
