#!/bin/sh
# Build /etc/nginx/pubkeys.gpg from one or more exported public keys.
# Anyone whose public key is in this file may authenticate.
#
#   ./build-keyring.sh alice.asc bob.asc > pubkeys.gpg
#
# Add a key later:
#   gpg --no-default-keyring --keyring /etc/nginx/pubkeys.gpg --import carol.asc
set -eu

ring="$(mktemp)"
for key in "$@"; do
    gpg --no-default-keyring --keyring "$ring" --import "$key" >/dev/null 2>&1
done
cat "$ring"
rm -f "$ring" "$ring~" 2>/dev/null || true
