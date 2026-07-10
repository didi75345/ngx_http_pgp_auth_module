#!/bin/sh
# Run the module under Valgrind memcheck (dynamic) and fail if any memory error
# -- invalid read/write, use of uninitialised value, or a leak -- originates in
# the module. nginx's own framework allocations are ignored (they don't carry
# an ngx_http_pgp_ frame). Complements ASan by catching uninitialised reads.
#
#   NGINX_BIN=/usr/sbin/nginx MODULE_SO=/path/module.so sh test/memcheck.sh
set -eu

NGINX_BIN="${NGINX_BIN:-nginx}"
MODULE_SO="${MODULE_SO:-}"
PORT="${PORT:-8998}"
WORK="$(mktemp -d)"
trap 'kill "$VG" 2>/dev/null || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$WORK/gpg"
chmod 700 "$WORK/gpg"
export GNUPGHOME="$WORK/gpg"
printf '%s\n' '%no-protection' 'Key-Type: eddsa' 'Key-Curve: ed25519' \
    'Name-Real: Vg' 'Name-Email: vg@example.com' 'Expire-Date: 0' '%commit' \
    > "$WORK/kp"
gpg --batch --gen-key "$WORK/kp" >/dev/null 2>&1
gpg --export vg@example.com > "$WORK/pubkeys.gpg"
gpg --list-keys --with-colons vg@example.com \
    | awk -F: '/^fpr:/{print $10; exit}' > "$WORK/revoked.txt"
head -c 48 /dev/urandom | base64 > "$WORK/session.key"
echo OK > "$WORK/html/index.html"

{
    [ -n "$MODULE_SO" ] && echo "load_module $MODULE_SO;"
    cat <<EOF
worker_processes 1; daemon off; master_process off;
error_log $WORK/logs/e.log crit; pid $WORK/logs/p.pid;
events { worker_connections 64; }
http { server { listen $PORT; location / {
  pgp_auth on; pgp_keyring $WORK/pubkeys.gpg; pgp_session_secret $WORK/session.key;
  pgp_session_cookie_secure off; pgp_revocation_list $WORK/revoked.txt;
  root $WORK/html; index index.html; } } }
EOF
} > "$WORK/conf/nginx.conf"

valgrind --tool=memcheck --leak-check=full --track-origins=yes \
    --log-file="$WORK/vg.log" --child-silent-after-fork=yes \
    "$NGINX_BIN" -p "$WORK" -c conf/nginx.conf >/dev/null 2>&1 &
VG=$!
sleep 8

base="http://127.0.0.1:$PORT"
ch=$(curl -s -A UA "$base/" | grep -oE 'v1\|[0-9]+\|[0-9a-f]+\|[0-9a-f]+' | head -1)
printf '%s' "$ch" | gpg --clearsign --batch > "$WORK/s.asc" 2>/dev/null
curl -s -A UA -o /dev/null -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/s.asc"
curl -s -A UA -o /dev/null -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/s.asc"
curl -s -A UA -o /dev/null -X POST "$base/?__pgp_auth=1" --data-urlencode 'signed=junk'
curl -s -A UA -o /dev/null -H 'Cookie: pgp_session=1|2|3' "$base/"

sleep 1
kill "$VG" 2>/dev/null; VG=
sleep 4                                   # let memcheck flush its summary

echo "== memcheck findings that reference the module =="
if grep -q 'ngx_http_pgp' "$WORK/vg.log"; then
    grep -B2 -A8 -E 'Invalid|uninitialised|lost' "$WORK/vg.log" \
        | grep -A8 -B2 'ngx_http_pgp'
    echo "RESULT: FAIL -- memcheck flagged the module"
    exit 1
fi
echo "RESULT: clean -- no memcheck errors reference the module"
