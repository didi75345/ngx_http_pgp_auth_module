#!/bin/sh
# Optional concurrency stress test.
#
# Fires N logins at once. Each one forks gpg inside an nginx worker, which is
# what exposes any race with nginx's own SIGCHLD reaping (a single sequential
# login can win the race by luck and hide such a bug). Challenges are fetched
# and signed sequentially first, so only the server-side verify path runs
# concurrently. Kept separate from run-tests.sh because spawning many gpg
# processes at once is sensitive to the host's gpg-agent setup.
#
#   NGINX_BIN=/usr/sbin/nginx MODULE_SO=/path/module.so N=8 sh test/stress.sh
set -eu

NGINX_BIN="${NGINX_BIN:-nginx}"
MODULE_SO="${MODULE_SO:-}"
PORT="${PORT:-8911}"
N="${N:-8}"
WORK="$(mktemp -d)"

cleanup() {
    [ -f "$WORK/logs/nginx.pid" ] && kill "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$WORK/gpg"
chmod 700 "$WORK/gpg"
export GNUPGHOME="$WORK/gpg"

cat > "$WORK/kp" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Stress Test
Name-Email: stress@example.com
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/kp" >/dev/null 2>&1
gpg --export stress@example.com > "$WORK/pubkeys.gpg"
head -c 48 /dev/urandom | base64 > "$WORK/session.key"
echo "OK" > "$WORK/html/index.html"

{
    [ -n "$MODULE_SO" ] && echo "load_module $MODULE_SO;"
    [ "$(id -u)" = 0 ] && echo "user root;"
    cat <<EOF
worker_processes 1;
daemon off;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    server {
        listen $PORT;
        location / {
            pgp_auth on;
            pgp_keyring $WORK/pubkeys.gpg;
            pgp_session_secret $WORK/session.key;
            root $WORK/html;
            index index.html;
        }
    }
}
EOF
} > "$WORK/conf/nginx.conf"

"$NGINX_BIN" -p "$WORK" -c conf/nginx.conf &
sleep 1
base="http://127.0.0.1:$PORT"

# fetch + sign N challenges sequentially
i=1
while [ "$i" -le "$N" ]; do
    curl -s --max-time 15 "$base/" -o "$WORK/cp_$i"
    c=$(grep -oE 'v1\|[0-9]+\|[0-9a-f]+\|[0-9a-f]+' "$WORK/cp_$i" | head -1)
    printf '%s' "$c" | gpg --clearsign --batch > "$WORK/cs_$i.asc" 2>/dev/null
    i=$((i + 1))
done

# submit all N at once
i=1
while [ "$i" -le "$N" ]; do
    curl -s --max-time 30 -o /dev/null -X POST "$base/?__pgp_auth=1" \
         --data-urlencode "signed@$WORK/cs_$i.asc" -w '%{http_code}' \
         > "$WORK/cc_$i" &
    i=$((i + 1))
done
wait

fail=0
i=1
while [ "$i" -le "$N" ]; do
    code=$(cat "$WORK/cc_$i")
    [ "$code" = 302 ] || { fail=$((fail + 1)); echo "  login $i -> $code (expected 302)"; }
    i=$((i + 1))
done

if [ "$fail" -eq 0 ]; then
    echo "RESULT: all $N concurrent logins succeeded"
else
    echo "RESULT: $fail/$N concurrent logins FAILED"
fi
[ "$fail" -eq 0 ]
