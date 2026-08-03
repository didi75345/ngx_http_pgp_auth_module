#!/bin/sh
# Build the .deb for one Debian release, in a container for that release.
#
#   packaging/build-deb.sh [bookworm|trixie] [outdir]
#
# The package is built against the target release's own nginx (via nginx-dev),
# so the result is only valid for that release -- which is exactly what the
# nginx-abi dependency in the package enforces at install time.
set -eu

RELEASE="${1:-trixie}"
OUTDIR="${2:-$(pwd)/dist/$RELEASE}"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$OUTDIR"

docker run --rm \
    -v "$SRCDIR":/src:ro \
    -v "$OUTDIR":/out \
    -e "RELEASE=$RELEASE" \
    "debian:$RELEASE-slim" \
    bash -eu -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            build-essential debhelper devscripts dpkg-dev \
            nginx-dev libssl-dev libpcre2-dev zlib1g-dev lintian >/dev/null

        cp -a /src /build
        cd /build
        # dch would otherwise stamp the entry with root@<container-id>, which
        # lintian rightly flags as a bogus maintainer address.
        export DEBEMAIL="${DEBEMAIL:-didi75345@users.noreply.github.com}"
        export DEBFULLNAME="${DEBFULLNAME:-didi75345}"
        # Version the package per release so one apt repo can serve both.
        NGXVER=$(dpkg-query -W -f="\${Version}" nginx-dev 2>/dev/null | sed "s/[-+].*//")
        BASEVER=$(dpkg-parsechangelog -S Version | sed "s/~.*//")
        dch --local "~${RELEASE}" --distribution "$RELEASE" \
            "Build for Debian ${RELEASE} (nginx ${NGXVER})." >/dev/null 2>&1 || true

        dpkg-buildpackage -us -uc -b
        cp -v ../*.deb /out/
        echo "=== lintian ==="
        lintian --no-tag-display-limit /out/*.deb || true
    '
echo "built into: $OUTDIR"
ls -1 "$OUTDIR"
