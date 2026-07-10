#!/bin/sh
# End-to-end test suite for ngx_http_pgp_auth.
#
# Drives a real nginx instance through the full PGP login flow and a set of
# attack cases. Exits non-zero on any failure, so it doubles as the CI gate.
#
# Requires on PATH: nginx, gpg, curl. Override the binary/module if needed:
#   NGINX_BIN=/usr/sbin/nginx  MODULE_SO=/path/ngx_http_pgp_auth_module.so
set -eu

NGINX_BIN="${NGINX_BIN:-nginx}"
MODULE_SO="${MODULE_SO:-}"
PORT="${PORT:-8899}"
WORK="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
    [ -f "$WORK/logs/nginx.pid" ] && kill "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$1"; }

mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html" "$WORK/gpg"
chmod 700 "$WORK/gpg"
export GNUPGHOME="$WORK/gpg"

# --- test key + keyring (the allowed signer) ---------------------------------
cat > "$WORK/keyparams" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: PGP Auth Test
Name-Email: test@example.com
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/keyparams" >/dev/null 2>&1
gpg --export test@example.com > "$WORK/pubkeys.gpg"

# a second key that is NOT in the keyring (the attacker)
export GNUPGHOME="$WORK/gpg2"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
cat > "$WORK/kp2" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: Attacker
Name-Email: evil@example.com
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$WORK/kp2" >/dev/null 2>&1
export GNUPGHOME="$WORK/gpg"

head -c 48 /dev/urandom | base64 > "$WORK/session.key"; chmod 600 "$WORK/session.key"
echo "<h1>SECRET-OK</h1>" > "$WORK/html/index.html"

# revocation list containing the test key's fingerprint (for the /revoc/ test)
gpg --list-keys --with-colons test@example.com \
    | awk -F: '/^fpr:/{print $10; exit}' > "$WORK/revoked.txt"

# --- nginx config ------------------------------------------------------------
{
    [ -n "$MODULE_SO" ] && echo "load_module $MODULE_SO;"
    # When running as root (CI/Docker), keep the worker as root so it can read
    # the keyring under a 0700 temp dir. In production the worker user simply
    # needs read access to the keyring.
    [ "$(id -u)" = 0 ] && echo "user root;"
    cat <<EOF
worker_processes 1;
daemon off;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 64; }
http {
    server {
        listen $PORT;
        location / {
            pgp_auth on;
            pgp_keyring $WORK/pubkeys.gpg;
            pgp_session_secret $WORK/session.key;
            pgp_challenge_timeout 300s;
            pgp_session_timeout 24h;
            root $WORK/html;
            index index.html;
        }
        location /short/ {
            pgp_auth on;
            pgp_keyring $WORK/pubkeys.gpg;
            pgp_session_secret $WORK/session.key;
            pgp_challenge_timeout 1s;
            root $WORK/html;
        }
        location /revoc/ {
            pgp_auth on;
            pgp_keyring $WORK/pubkeys.gpg;
            pgp_session_secret $WORK/session.key;
            pgp_revocation_list $WORK/revoked.txt;
            root $WORK/html;
        }
        location /failclosed/ {
            pgp_auth on;
            pgp_keyring $WORK/pubkeys.gpg;
            pgp_session_secret $WORK/session.key;
            pgp_revocation_list $WORK/does-not-exist.txt;
            root $WORK/html;
        }
    }
}
EOF
} > "$WORK/conf/nginx.conf"

"$NGINX_BIN" -p "$WORK" -c conf/nginx.conf -t
"$NGINX_BIN" -p "$WORK" -c conf/nginx.conf &
sleep 1

base="http://127.0.0.1:$PORT"
challenge() { grep -oE 'v1\|[0-9]+\|[0-9a-f]+\|[0-9a-f]+' "$1" | head -1; }

echo "== positive flow =="

curl -s "$base/" -o "$WORK/p1" -w '%{http_code}' > "$WORK/c1"
[ "$(cat "$WORK/c1")" = 200 ] && grep -q 'v1|' "$WORK/p1" \
    && ok "unauth GET returns challenge page" || bad "challenge page"

CH="$(challenge "$WORK/p1")"
printf '%s' "$CH" | gpg --clearsign --batch > "$WORK/s.asc" 2>/dev/null

curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/s.asc" \
     -D "$WORK/h1" -o /dev/null -w '%{http_code}' > "$WORK/c2"
[ "$(cat "$WORK/c2")" = 303 ] && grep -qi 'set-cookie:.*pgp_session=' "$WORK/h1" \
    && ok "valid signature returns 303 + session cookie" || bad "valid sign-in"

CK="$(grep -i '^set-cookie:' "$WORK/h1" | sed 's/[Ss]et-[Cc]ookie: //;s/;.*//' | tr -d '\r')"
curl -s -b "$CK" "$base/" -o "$WORK/p2" -w '%{http_code}' > "$WORK/c3"
[ "$(cat "$WORK/c3")" = 200 ] && grep -q 'SECRET-OK' "$WORK/p2" \
    && ok "session cookie grants access" || bad "session access"

# Full browser flow on one connection: POST login, follow the redirect, land on
# the protected page -- with --max-time so a keepalive/redirect stall fails
# loudly instead of hanging. (A real browser reuses the connection to follow
# the redirect, which a plain non-following POST never exercises.)
curl -s "$base/" -o "$WORK/lp" >/dev/null
LCH="$(challenge "$WORK/lp")"
printf '%s' "$LCH" | gpg --clearsign --batch > "$WORK/ls.asc" 2>/dev/null
curl -s -L --max-time 15 -c "$WORK/lj" -b "$WORK/lj" "$base/?__pgp_auth=1" \
     --data-urlencode "signed@$WORK/ls.asc" -o "$WORK/lf" -w '%{http_code}' \
     > "$WORK/lc" 2>/dev/null
[ "$(cat "$WORK/lc")" = 200 ] && grep -q 'SECRET-OK' "$WORK/lf" \
    && ok "login + follow redirect reaches protected page" \
    || bad "redirect-follow login (got $(cat "$WORK/lc"))"

echo "== attack cases (all must be rejected) =="

curl -s -H 'Cookie: pgp_session=9999999999|DEADBEEF|ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
     "$base/" -o "$WORK/n1" >/dev/null
grep -q 'SECRET-OK' "$WORK/n1" && bad "forged cookie blocked" || ok "forged cookie blocked"

export GNUPGHOME="$WORK/gpg2"
printf '%s' "$CH" | gpg --clearsign --batch > "$WORK/evil.asc" 2>/dev/null
export GNUPGHOME="$WORK/gpg"
curl -s "$base/" -o "$WORK/np" >/dev/null
CH2="$(challenge "$WORK/np")"
export GNUPGHOME="$WORK/gpg2"
printf '%s' "$CH2" | gpg --clearsign --batch > "$WORK/evil.asc" 2>/dev/null
export GNUPGHOME="$WORK/gpg"
curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/evil.asc" \
     -D "$WORK/h2" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/h2" && bad "unknown-key signature rejected" \
    || ok "unknown-key signature rejected"

FAKE="v1|9999999999|00000000000000000000000000000000|0000000000000000000000000000000000000000000000000000000000000000"
printf '%s' "$FAKE" | gpg --clearsign --batch > "$WORK/fake.asc" 2>/dev/null
curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/fake.asc" \
     -D "$WORK/h3" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/h3" && bad "forged challenge (bad HMAC) rejected" \
    || ok "forged challenge (bad HMAC) rejected"

# Challenge-binding: a real signature (by a keyring key) over unrelated text,
# with a genuine unexpired challenge placed OUTSIDE the signed region. Must be
# rejected -- the challenge only counts if it is inside what gpg verified.
printf 'unrelated text' | gpg --clearsign --batch > "$WORK/unrel.asc" 2>/dev/null
curl -s "$base/" -o "$WORK/bp" >/dev/null
BCH="$(challenge "$WORK/bp")"
{ cat "$WORK/unrel.asc"; printf '\n%s\n' "$BCH"; } > "$WORK/append.txt"
curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/append.txt" \
     -D "$WORK/h3b" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/h3b" && bad "challenge appended outside signature rejected" \
    || ok "challenge appended outside signature rejected"

curl -s "$base/" -o "$WORK/bp2" >/dev/null
BCH2="$(challenge "$WORK/bp2")"
{ printf '%s\n' "$BCH2"; cat "$WORK/unrel.asc"; } > "$WORK/prepend.txt"
curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/prepend.txt" \
     -D "$WORK/h3c" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/h3c" && bad "challenge prepended outside signature rejected" \
    || ok "challenge prepended outside signature rejected"

# Single-use: the same signed challenge must not work twice (default memory
# nonce store). First submit succeeds; the replay must be rejected.
curl -s "$base/" -o "$WORK/rp" >/dev/null
RCH="$(challenge "$WORK/rp")"
printf '%s' "$RCH" | gpg --clearsign --batch > "$WORK/replay.asc" 2>/dev/null
R1=$(curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" \
         --data-urlencode "signed@$WORK/replay.asc" -w '%{http_code}')
curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode "signed@$WORK/replay.asc" \
     -D "$WORK/hr" -o /dev/null >/dev/null
{ [ "$R1" = 303 ] && ! grep -qi '^set-cookie:' "$WORK/hr"; } \
    && ok "replay of a used challenge rejected (single-use)" \
    || bad "replay rejected (first=$R1)"

# Revocation: the /revoc/ location lists the test key's fingerprint as revoked,
# so a valid login there must be rejected.
curl -s "$base/revoc/" -o "$WORK/vp" >/dev/null
VCH="$(challenge "$WORK/vp")"
printf '%s' "$VCH" | gpg --clearsign --batch > "$WORK/vs.asc" 2>/dev/null
curl -s -X POST "$base/revoc/?__pgp_auth=1" --data-urlencode "signed@$WORK/vs.asc" \
     -D "$WORK/hv" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/hv" && bad "revoked key rejected" \
    || ok "revoked key rejected"

# Fail-closed revocation: an unreadable list must deny, not silently allow.
curl -s "$base/failclosed/" -o "$WORK/fc" >/dev/null
FCH="$(challenge "$WORK/fc")"
printf '%s' "$FCH" | gpg --clearsign --batch > "$WORK/fs.asc" 2>/dev/null
curl -s -X POST "$base/failclosed/?__pgp_auth=1" --data-urlencode "signed@$WORK/fs.asc" \
     -D "$WORK/hfc" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/hfc" && bad "unreadable revocation list fails closed" \
    || ok "unreadable revocation list fails closed"

# Oversized auth body is rejected (413) before gpg is forked.
head -c 40000 /dev/urandom | base64 > "$WORK/big"
BC=$(curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" \
         --data-urlencode "signed@$WORK/big" -w '%{http_code}')
[ "$BC" = 413 ] && ok "oversized auth body rejected (413)" \
    || bad "oversized body rejected (got $BC)"

# The cap must also apply to a chunked (unknown-length) body, not just
# Content-Length -- otherwise the size check is bypassed.
CC=$(curl -s -o /dev/null -X POST "$base/?__pgp_auth=1" \
         -H 'Content-Type: application/x-www-form-urlencoded' \
         -H 'Transfer-Encoding: chunked' --data-binary "@$WORK/big" -w '%{http_code}')
[ "$CC" = 413 ] && ok "oversized chunked body rejected (413)" \
    || bad "chunked body cap (got $CC)"

# A non-PGP body is rejected without spawning gpg.
curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode 'signed=plain junk, no armor' \
     -D "$WORK/hj" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/hj" && bad "non-PGP body rejected pre-fork" \
    || ok "non-PGP body rejected pre-fork"

curl -s "$base/short/" -o "$WORK/sp" >/dev/null
CHS="$(challenge "$WORK/sp")"
printf '%s' "$CHS" | gpg --clearsign --batch > "$WORK/se.asc" 2>/dev/null
sleep 2
curl -s -X POST "$base/short/?__pgp_auth=1" --data-urlencode "signed@$WORK/se.asc" \
     -D "$WORK/h4" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/h4" && bad "expired challenge rejected" \
    || ok "expired challenge rejected"

curl -s -X POST "$base/?__pgp_auth=1" --data-urlencode 'signed=not a pgp message' \
     -D "$WORK/h5" -o /dev/null >/dev/null
grep -qi '^set-cookie:' "$WORK/h5" && bad "garbage body rejected" \
    || ok "garbage body rejected"

# HTTP/2 login must still work: the body-size hardening keys on chunked
# (HTTP/1.1) bodies, and must NOT reject a normal HTTP/2 submission (which
# carries a Content-Length). Only runs if this nginx has http_v2 + we have
# openssl and a curl with HTTP/2.
if "$NGINX_BIN" -V 2>&1 | grep -q http_v2 \
   && command -v openssl >/dev/null 2>&1 \
   && curl --version | grep -qi HTTP2
then
    openssl req -x509 -newkey ed25519 -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
        -days 2 -nodes -subj "/CN=localhost" >/dev/null 2>&1
    HP=$((PORT + 1))
    {
        echo "load_module $MODULE_SO;"
        [ "$(id -u)" = 0 ] && echo "user root;"
        cat <<EOF
worker_processes 1; daemon off; error_log $WORK/logs/h2.log crit;
pid $WORK/logs/h2.pid;
events { worker_connections 64; }
http { server {
    listen $HP ssl http2;
    ssl_certificate $WORK/c.pem; ssl_certificate_key $WORK/k.pem;
    location / {
        pgp_auth on; pgp_keyring $WORK/pubkeys.gpg;
        pgp_session_secret $WORK/session.key; pgp_auth_nonce_storage none;
        root $WORK/html; index index.html;
    }
} }
EOF
    } > "$WORK/conf/h2.conf"
    "$NGINX_BIN" -p "$WORK" -c conf/h2.conf & sleep 1
    hb="https://127.0.0.1:$HP"
    curl -sk --http2 "$hb/" -o "$WORK/h2p"
    hch="$(challenge "$WORK/h2p")"
    printf '%s' "$hch" | gpg --clearsign --batch > "$WORK/h2s.asc" 2>/dev/null
    hcode=$(curl -sk --http2 -o /dev/null -X POST "$hb/?__pgp_auth=1" \
            --data-urlencode "signed@$WORK/h2s.asc" -w '%{http_version} %{http_code}')
    [ "$hcode" = "2 303" ] && ok "HTTP/2 login succeeds (no chunked-cap regression)" \
        || bad "HTTP/2 login (got '$hcode')"
    [ -f "$WORK/logs/h2.pid" ] && kill "$(cat "$WORK/logs/h2.pid")" 2>/dev/null
else
    echo "  SKIP  HTTP/2 login (nginx http_v2 / openssl / curl-h2 unavailable)"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
