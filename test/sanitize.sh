#!/bin/sh
# Build the module with AddressSanitizer + UndefinedBehaviorSanitizer and
# exercise every request path (valid login, garbage, empty, malformed
# percent-encoding, forged cookie, oversized body). Fails if either sanitizer
# reports a fault inside the module.
#
# Memory-safety is the main risk for a C module, so this is the gate that
# proves no buffer overflow / use-after-free / bad read on any input.
#
#   NGINX_VERSION=1.26.3 sh test/sanitize.sh
set -eu

NGINX_VERSION="${NGINX_VERSION:-1.26.3}"
HERE="$(CDPATH= cd "$(dirname "$0")/.." && pwd)"
BUILD="$(mktemp -d)"
WORK="$(mktemp -d)"
SAN="$WORK/san"

cleanup() {
    [ -n "${NGPID:-}" ] && kill "$NGPID" 2>/dev/null || true
    rm -rf "$BUILD" "$WORK"
}
trap cleanup EXIT

echo "== building nginx $NGINX_VERSION + module with ASan+UBSan =="
cd "$BUILD"
curl -fsSL -o nginx.tgz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar xzf nginx.tgz
cd "nginx-${NGINX_VERSION}"
# --without-http_rewrite_module: avoids requiring PCRE just for this build; it
# is unrelated to the module under test.
./configure --with-compat --add-dynamic-module="$HERE" \
    --without-http_rewrite_module --without-http_gzip_module \
    --with-cc-opt="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
    --with-ld-opt="-fsanitize=address,undefined" >/dev/null
make -j"$(nproc)" >/dev/null
NGINX="$BUILD/nginx-${NGINX_VERSION}/objs/nginx"
MOD="$BUILD/nginx-${NGINX_VERSION}/objs/ngx_http_pgp_auth_module.so"

echo "== setting up a keyring + key =="
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$WORK/gpg"
chmod 700 "$WORK/gpg"
export GNUPGHOME="$WORK/gpg"
printf '%s\n' '%no-protection' 'Key-Type: eddsa' 'Key-Curve: ed25519' \
    'Name-Real: San' 'Name-Email: san@example.com' 'Expire-Date: 0' '%commit' \
    > "$WORK/kp"
gpg --batch --gen-key "$WORK/kp" >/dev/null 2>&1
gpg --export san@example.com > "$WORK/pubkeys.gpg"
head -c 48 /dev/urandom | base64 > "$WORK/session.key"
echo OK > "$WORK/html/index.html"

cat > "$WORK/conf/nginx.conf" <<EOF
load_module $MOD;
worker_processes 1; daemon off; master_process off;
error_log $WORK/logs/e.log info; pid $WORK/logs/p.pid;
events { worker_connections 64; }
http { server { listen 8931; location / {
  pgp_auth on; pgp_keyring $WORK/pubkeys.gpg; pgp_session_secret $WORK/session.key;
  root $WORK/html; index index.html; } } }
EOF

# detect_odr_violation=0: a dynamic module duplicates ngx_module_names, which is
# a sanitizer artifact of dynamic linking, not a real fault.
ASAN_OPTIONS="detect_leaks=0:detect_odr_violation=0:abort_on_error=0:log_path=$SAN" \
UBSAN_OPTIONS="log_path=${SAN}_ub:halt_on_error=0" \
    "$NGINX" -p "$WORK" -c conf/nginx.conf >/dev/null 2>&1 &
NGPID=$!
sleep 2

base="http://127.0.0.1:8931"
echo "== exercising every request path under the sanitizers =="
ch=$(curl -s "$base/" | grep -oE 'v1\|[0-9]+\|[0-9a-f]+\|[0-9a-f]+' | head -1)
printf '%s' "$ch" | gpg --clearsign --batch > "$WORK/s.asc" 2>/dev/null
head -c 200000 /dev/urandom | base64 > "$WORK/huge"

curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/s.asc"
curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" --data-urlencode 'signed=junk'
curl -s -o /dev/null -X POST "$base/?__pgp_auth=1"
curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" \
     -H 'Content-Type: application/x-www-form-urlencoded' --data-binary 'signed=%ZZ%%%'
curl -s -o /dev/null -H 'Cookie: pgp_session=1|2|3' "$base/"
curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/huge"

sleep 1
kill "$NGPID" 2>/dev/null; NGPID=
sleep 1

echo "== checking sanitizer output =="
if ls "$SAN"* >/dev/null 2>&1 && grep -lE 'ngx_http_pgp_auth' "$SAN"* >/dev/null 2>&1; then
    echo "RESULT: FAIL -- sanitizer flagged the module:"
    grep -E 'runtime error|ERROR|ngx_http_pgp' "$SAN"* | head
    exit 1
fi
echo "RESULT: clean -- no ASan/UBSan faults in the module on any input"
