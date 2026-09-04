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

# Pin the base image by immutable digest, not by the mutable "$RELEASE-slim"
# tag: a tag is a pointer anyone with push access upstream can repoint, and the
# next build would silently pull different content with nothing in this repo
# changing. Re-pin deliberately, on a schedule -- resolving the tag afresh each
# build would just move the trust problem rather than close it.
case "$RELEASE" in
    trixie)   BASE="debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132" ;;
    bookworm) BASE="debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171" ;;
    *) echo "build-deb.sh: no pinned base image for release '$RELEASE'." >&2
       echo "  Add its digest here before building it." >&2
       exit 2 ;;
esac

mkdir -p "$OUTDIR"

docker run --rm \
    -v "$SRCDIR":/src:ro \
    -v "$OUTDIR":/out \
    -e "RELEASE=$RELEASE" \
    "$BASE" \
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
        dch --local "~${RELEASE}" --distribution "$RELEASE" \
            "Build for Debian ${RELEASE} (nginx ${NGXVER})." >/dev/null 2>&1 || true

        dpkg-buildpackage -us -uc -b
        cp -v ../*.deb /out/
        echo "=== lintian ==="
        # Enforced, not advisory -- CI does the same. An error here is a real
        # packaging regression, and `|| true` is how the published packages once
        # shipped with a bogus maintainer address without anyone noticing.
        lintian --tag-display-limit 0 --fail-on error /out/*.deb
    '
echo "built into: $OUTDIR"
ls -1 "$OUTDIR"
