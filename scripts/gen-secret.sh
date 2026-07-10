#!/bin/sh
# Generate the HMAC secret used to sign challenges and sessions.
# Use the SAME file on every nginx node so sessions are valid fleet-wide.
#
# Keep it readable only by the nginx worker user -- it can forge sessions and
# challenges. The module warns at start-up if it is group/world-accessible.
#   ./gen-secret.sh > /etc/nginx/pgp_secret.key
#   chown nginx /etc/nginx/pgp_secret.key && chmod 600 /etc/nginx/pgp_secret.key
set -eu
head -c 48 /dev/urandom | base64
