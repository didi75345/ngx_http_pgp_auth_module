#!/bin/sh
# Install a built .deb in a clean container of the target release and run the
# module's own end-to-end suite against the INSTALLED module.
#
#   packaging/install-test.sh [bookworm|trixie] [debdir]
set -eu
RELEASE="${1:-trixie}"
DEBDIR="${2:-$(pwd)/dist/$RELEASE}"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

docker run --rm \
    -v "$SRCDIR":/src:ro -v "$DEBDIR":/pkg:ro \
    "debian:$RELEASE-slim" bash -eu -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            nginx gnupg curl ca-certificates redis-server procps python3-minimal >/dev/null

        echo "=== installing the package ==="
        apt-get install -y -qq /pkg/libnginx-mod-http-pgp-auth_*.deb
        echo "--- enabled module symlink ---"; ls -l /etc/nginx/modules-enabled/
        test -f /usr/lib/nginx/modules/ngx_http_pgp_auth_module.so

        echo "=== the packaged nginx accepts the config with the module loaded ==="
        nginx -t

        echo "=== end-to-end suite against the INSTALLED module ==="
        cp -a /src /work && cd /work
        NGINX_BIN=/usr/sbin/nginx \
        MODULE_SO=/usr/lib/nginx/modules/ngx_http_pgp_auth_module.so \
            sh test/run-tests.sh

        echo "=== package removes cleanly ==="
        apt-get remove -y -qq libnginx-mod-http-pgp-auth
        test ! -e /etc/nginx/modules-enabled/50-mod-http-pgp-auth.conf
        nginx -t
        echo "REMOVAL-OK"
    '
