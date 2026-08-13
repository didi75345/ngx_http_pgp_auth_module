#!/bin/sh
# Assemble a signed APT repository from packages built by build-deb.sh.
#
#   packaging/build-apt-repo.sh [distdir] [outdir]
#
#   distdir  directory holding one subdirectory per release, each with .debs
#            (the layout build-deb.sh produces: dist/bookworm, dist/trixie)
#   outdir   where the repository tree is written (default: ./public)
#
# Signing: if a private key is available the Release file is signed, producing
# InRelease (inline) and Release.gpg (detached), and the corresponding public
# key is exported next to the repo so clients can verify it. Provide the key
# either as an ASCII-armoured private key in $APT_GPG_PRIVATE_KEY, or by
# pointing $APT_GPG_KEY_ID at a key already present in the invoking user's
# keyring. Without a key the repo is still built but left unsigned, which apt
# will only accept with [trusted=yes] -- fine for a local smoke test, not for
# anything published.
set -eu

DISTDIR="${1:-$(pwd)/dist}"
OUTDIR="${2:-$(pwd)/public}"
ORIGIN="${APT_REPO_ORIGIN:-ngx_http_pgp_auth_module}"
LABEL="${APT_REPO_LABEL:-ngx_http_pgp_auth_module}"
ARCH="${APT_REPO_ARCH:-amd64}"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

[ -d "$DISTDIR" ] || { echo "no such dist dir: $DISTDIR" >&2; exit 1; }

mkdir -p "$OUTDIR"

# The private key and its passphrase are handed over as 0600 files on a private
# mount rather than in the container's environment: an environment variable is
# readable through `docker inspect` and /proc/<pid>/environ for the life of the
# container, and anything that can read one of the two can read the other.
KEYDIR=$(mktemp -d)
chmod 700 "$KEYDIR"
trap 'rm -rf "$KEYDIR"' EXIT INT TERM
if [ -n "${APT_GPG_PRIVATE_KEY:-}" ]; then
    printf '%s' "$APT_GPG_PRIVATE_KEY" > "$KEYDIR/private.asc"
    chmod 600 "$KEYDIR/private.asc"
fi
if [ -n "${APT_GPG_PASSPHRASE:-}" ]; then
    printf '%s' "$APT_GPG_PASSPHRASE" > "$KEYDIR/passphrase"
    chmod 600 "$KEYDIR/passphrase"
fi

docker run --rm \
    -v "$DISTDIR":/dist:ro \
    -v "$OUTDIR":/out \
    -v "$SRCDIR":/src:ro \
    -e "ORIGIN=$ORIGIN" -e "LABEL=$LABEL" -e "ARCH=$ARCH" \
    -v "$KEYDIR":/keys:ro \
    debian:trixie-slim \
    bash -eu -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends apt-utils gnupg >/dev/null

        cd /out

        # pool/ + per-release package indices
        for relpath in /dist/*; do
            [ -d "$relpath" ] || continue
            rel="${relpath#/dist/}"
            ls "/dist/$rel"/*.deb >/dev/null 2>&1 || continue

            mkdir -p "pool/$rel" "dists/$rel/main/binary-${ARCH}"
            cp -f /dist/$rel/*.deb "pool/$rel/"

            apt-ftparchive --arch "$ARCH" packages "pool/$rel" \
                > "dists/$rel/main/binary-${ARCH}/Packages"
            gzip -9cf "dists/$rel/main/binary-${ARCH}/Packages" \
                > "dists/$rel/main/binary-${ARCH}/Packages.gz"

            apt-ftparchive \
                -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
                -o "APT::FTPArchive::Release::Label=$LABEL" \
                -o "APT::FTPArchive::Release::Suite=$rel" \
                -o "APT::FTPArchive::Release::Codename=$rel" \
                -o "APT::FTPArchive::Release::Components=main" \
                -o "APT::FTPArchive::Release::Architectures=$ARCH" \
                release "dists/$rel" > "dists/$rel/Release"

            # Valid-Until bounds how long this signed metadata stays acceptable.
            # Without it a signed Release never expires, so anyone able to serve
            # an old copy (a stale mirror, a cache, a MITM on the transport) can
            # pin clients to an outdated package set indefinitely and apt has no
            # way to notice. Re-publish before it lapses.
            # It is written here rather than through apt-ftparchive because that
            # tool silently ignores its Release::Valid-Until option (verified:
            # the emitted file contained Date but no Valid-Until). The Release
            # checksums cover the Packages indices, not Release itself, and the
            # signature is made afterwards, so editing it here is safe.
            VALID_UNTIL=$(date -u -d "+${APT_REPO_VALID_DAYS:-30} days" \
                          "+%a, %d %b %Y %H:%M:%S UTC")
            sed -i "/^Date:/a Valid-Until: $VALID_UNTIL" "dists/$rel/Release"

            echo "indexed $rel: $(ls pool/$rel | tr "\n" " ")"
        done

        # sign, if a key was supplied
        if [ -s /keys/private.asc ]; then
            export GNUPGHOME=/tmp/gpg; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
            gpg --batch --import /keys/private.asc 2>/dev/null
            KEYID=$(gpg --list-secret-keys --with-colons | awk -F: "/^sec/{print \$5; exit}")
            [ -n "$KEYID" ] || { echo "no secret key imported" >&2; exit 1; }

            # The passphrase is written to a 0600 file inside the throwaway
            # GNUPGHOME and passed with --passphrase-file; it is never put on
            # the gpg command line. Two reasons: an argv passphrase is readable
            # in the process list, and the option string had to be expanded
            # UNQUOTED, so an ordinary passphrase containing a space word-split
            # and broke signing outright (gpg then saw --default-key/--clearsign
            # as passphrase words and refused with "no command supplied").
            if [ -f /keys/passphrase ]; then
                cp /keys/passphrase "$GNUPGHOME/passphrase"
                chmod 600 "$GNUPGHOME/passphrase"
            fi

            gpg_sign() {
                if [ -f "$GNUPGHOME/passphrase" ]; then
                    gpg --batch --yes --pinentry-mode loopback \
                        --passphrase-file "$GNUPGHOME/passphrase" \
                        --default-key "$KEYID" "$@"
                else
                    gpg --batch --yes --default-key "$KEYID" "$@"
                fi
            }

            for relpath in dists/*; do
                [ -d "$relpath" ] || continue
                rel="${relpath#dists/}"
                gpg_sign --clearsign -o "dists/$rel/InRelease" "dists/$rel/Release"
                gpg_sign -abs -o "dists/$rel/Release.gpg" "dists/$rel/Release"
            done

            # public key for clients (both armoured and dearmoured forms)
            gpg --armor --export "$KEYID" > pgp-auth-archive-keyring.asc
            gpg --export "$KEYID" > pgp-auth-archive-keyring.gpg
            echo "signed with $KEYID"
        else
            echo "WARNING: no signing key supplied -- repository is UNSIGNED"
        fi

        # a landing page with copy-pasteable install instructions
        cp -f /src/packaging/repo-index.html index.html 2>/dev/null || true
        chmod -R a+rX /out
    '

echo "repository written to: $OUTDIR"
find "$OUTDIR" -maxdepth 3 -type f | head -20
