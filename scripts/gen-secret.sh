#!/bin/sh
# Generate the HMAC secret used to sign challenges and sessions.
# Use the SAME file on every nginx node so sessions are valid fleet-wide.
#
#   ./gen-secret.sh > /etc/nginx/pgp_secret.key
#   chown root:www-data /etc/nginx/pgp_secret.key && chmod 640 ...
set -eu
head -c 48 /dev/urandom | base64
