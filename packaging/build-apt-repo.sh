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

docker run --rm \
    -v "$DISTDIR":/dist:ro \
    -v "$OUTDIR":/out \
    -v "$SRCDIR":/src:ro \
    -e "ORIGIN=$ORIGIN" -e "LABEL=$LABEL" -e "ARCH=$ARCH" \
    -e "APT_GPG_PRIVATE_KEY=${APT_GPG_PRIVATE_KEY:-}" \
    -e "APT_GPG_PASSPHRASE=${APT_GPG_PASSPHRASE:-}" \
    debian:trixie-slim \
    bash -eu -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends apt-utils gnupg >/dev/null

        cd /out

        # pool/ + per-release package indices
        for rel in $(ls /dist); do
            [ -d "/dist/$rel" ] || continue
            ls /dist/$rel/*.deb >/dev/null 2>&1 || continue

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

            echo "indexed $rel: $(ls pool/$rel | tr "\n" " ")"
        done

        # sign, if a key was supplied
        if [ -n "${APT_GPG_PRIVATE_KEY:-}" ]; then
            export GNUPGHOME=/tmp/gpg; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
            printf "%s" "$APT_GPG_PRIVATE_KEY" | gpg --batch --import 2>/dev/null
            KEYID=$(gpg --list-secret-keys --with-colons | awk -F: "/^sec/{print \$5; exit}")
            [ -n "$KEYID" ] || { echo "no secret key imported" >&2; exit 1; }

            PASS=""
            [ -n "${APT_GPG_PASSPHRASE:-}" ] && PASS="--pinentry-mode loopback --passphrase ${APT_GPG_PASSPHRASE}"

            for rel in $(ls dists 2>/dev/null); do
                gpg --batch --yes $PASS --default-key "$KEYID" \
                    --clearsign -o "dists/$rel/InRelease" "dists/$rel/Release"
                gpg --batch --yes $PASS --default-key "$KEYID" \
                    -abs -o "dists/$rel/Release.gpg" "dists/$rel/Release"
            done

            # public key for clients (both armoured and dearmoured forms)
            gpg --armor --export "$KEYID" > pgp-auth-archive-keyring.asc
            gpg --export "$KEYID" > pgp-auth-archive-keyring.gpg
            echo "signed with $KEYID"
        else
            echo "WARNING: no APT_GPG_PRIVATE_KEY -- repository is UNSIGNED"
        fi

        # a landing page with copy-pasteable install instructions
        cp -f /src/packaging/repo-index.html index.html 2>/dev/null || true
        chmod -R a+rX /out
    '

echo "repository written to: $OUTDIR"
find "$OUTDIR" -maxdepth 3 -type f | head -20
