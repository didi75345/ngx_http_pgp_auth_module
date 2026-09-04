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
# key is exported next to the repo so clients can verify it.
#
# The key is supplied ONE way: an ASCII-armoured private key in
# $APT_GPG_PRIVATE_KEY (in CI, a signing subkey -- see packaging/README.md).
# There is deliberately no "use a key already in the caller's keyring" mode: it
# would mean reaching into a developer's own keyring and exporting secret
# material out of it, and the earlier version of this comment advertised such a
# mode ($APT_GPG_KEY_ID) that was never implemented -- so a caller who followed
# it got an unsigned repository. Setting that variable is now a hard error
# rather than a surprise.
#
# Without a key the repo is still built but left unsigned, which apt will only
# accept with [trusted=yes] -- fine for a local smoke test, not for anything
# published.
set -eu

if [ -n "${APT_GPG_KEY_ID:-}" ]; then
    echo "build-apt-repo.sh: APT_GPG_KEY_ID is not supported." >&2
    echo "  Earlier documentation offered it; the script never implemented it, so" >&2
    echo "  setting it produced an UNSIGNED repository. Export the key instead:" >&2
    echo "    APT_GPG_PRIVATE_KEY=\"\$(gpg --armor --export-secret-subkeys <SUBKEY-ID>!)\"" >&2
    exit 2
fi

# An unsigned repository is a legitimate local smoke test and a disaster if it
# reaches users, and the two are told apart only by intent -- so intent has to be
# stated. Without a key the script used to print a warning and exit 0, which is
# easy to miss in a build log and leaves a publishable-looking tree behind.
if [ -z "${APT_GPG_PRIVATE_KEY:-}" ] && [ "${APT_REPO_ALLOW_UNSIGNED:-0}" != "1" ]; then
    echo "build-apt-repo.sh: no signing key in \$APT_GPG_PRIVATE_KEY." >&2
    echo "  Refusing to build an unsigned repository by accident." >&2
    echo "  For a local smoke test, ask for it explicitly:" >&2
    echo "    APT_REPO_ALLOW_UNSIGNED=1 sh packaging/build-apt-repo.sh" >&2
    echo "  apt will then only accept the result with [trusted=yes]." >&2
    exit 2
fi

DISTDIR="${1:-$(pwd)/dist}"
OUTDIR="${2:-$(pwd)/public}"
ORIGIN="${APT_REPO_ORIGIN:-ngx_http_pgp_auth_module}"
LABEL="${APT_REPO_LABEL:-ngx_http_pgp_auth_module}"
ARCH="${APT_REPO_ARCH:-amd64}"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

[ -d "$DISTDIR" ] || { echo "no such dist dir: $DISTDIR" >&2; exit 1; }

mkdir -p "$OUTDIR"

# The private key and its passphrase are handed over as 0600 files on a private
# mount rather than in any process's environment: an environment variable is
# readable through `docker inspect` and /proc/<pid>/environ for the life of the
# process, and anything that can read one of the two can read the other.
#
# Prefer /dev/shm, so the key never lands on a persistent filesystem: it is
# tmpfs, so the bytes live in memory and are freed with the directory, whereas
# an `rm` under a disk-backed $TMPDIR unlinks the name and leaves the blocks.
# Fall back to mktemp's own default where /dev/shm is absent (non-Linux) or not
# writable -- the 0600/0700 modes still apply there.
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    KEYDIR=$(TMPDIR=/dev/shm mktemp -d)
else
    KEYDIR=$(mktemp -d)
fi
chmod 700 "$KEYDIR"
# HUP and QUIT as well as the obvious three: HUP is what a dropped SSH session
# or a closed terminal sends, which is the most ordinary way a long build dies,
# and without it the key file would be left behind with nothing to sweep it up.
BUILDER_TAG="pgp-auth-aptrepo-builder:$$"
trap 'rm -rf "$KEYDIR"; docker image rm -f "$BUILDER_TAG" >/dev/null 2>&1 || true' EXIT INT TERM HUP QUIT
if [ -n "${APT_GPG_PRIVATE_KEY:-}" ]; then
    printf '%s' "$APT_GPG_PRIVATE_KEY" > "$KEYDIR/private.asc"
    chmod 600 "$KEYDIR/private.asc"
fi
if [ -n "${APT_GPG_PASSPHRASE:-}" ]; then
    printf '%s' "$APT_GPG_PASSPHRASE" > "$KEYDIR/passphrase"
    chmod 600 "$KEYDIR/passphrase"
fi

# Now that both are on the private mount, drop them from OUR environment before
# forking anything. The caller exports them (the release workflow sets them from
# repository secrets), so every child -- starting with the docker CLI below --
# would otherwise inherit the armoured secret key in its own /proc/<pid>/environ
# for the whole build. Passing the key by mount instead of `-e` moved it out of
# the container; this is what takes it out of the host side too.
unset APT_GPG_PRIVATE_KEY APT_GPG_PASSPHRASE

# Signing runs in two stages so the container holding the plaintext key never
# has a network. Stage 1 has network and NO key: it bakes apt-utils and gnupg
# into a throwaway image. Stage 2 mounts the key and runs --network none, so
# even a compromised apt-utils, gnupg or index cannot exfiltrate the key. The
# base is pinned by digest rather than by the mutable :trixie-slim tag, so the
# prep stage is not itself a reintroduced trust gap -- re-pin deliberately,
# never resolve the tag afresh on every build.
docker build -q -t "$BUILDER_TAG" - >/dev/null <<DOCKERFILE
FROM debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends apt-utils gnupg \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE

docker run --rm --network none \
    -v "$DISTDIR":/dist:ro \
    -v "$OUTDIR":/out \
    -v "$SRCDIR":/src:ro \
    -e "ORIGIN=$ORIGIN" -e "LABEL=$LABEL" -e "ARCH=$ARCH" \
    -e "APT_REPO_VALID_DAYS=${APT_REPO_VALID_DAYS:-30}" \
    -v "$KEYDIR":/keys:ro \
    "$BUILDER_TAG" \
    bash -eu -c '
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

            # The fingerprint is published as a file and rendered into the
            # landing page so a user can check the key they fetched instead of
            # importing it blind. It is served from the same origin as the key
            # itself, so this makes trust-on-first-use explicit rather than
            # eliminating it -- an out-of-band anchor is what actually closes it.
            # NOTE: no single quotes anywhere in here -- this whole block runs
            # inside a single-quoted `bash -c` string, so an awk or printf using
            # them would silently terminate it.
            FPR=$(gpg --list-keys --with-colons "$KEYID" \
                  | grep "^fpr:" | cut -d: -f10 | head -1)
            echo "$FPR" > pgp-auth-archive-keyring.fingerprint
            echo "signed with $KEYID (fingerprint $FPR)"
        else
            FPR="(repository is UNSIGNED -- no key)"
            echo "WARNING: no signing key supplied -- repository is UNSIGNED"
        fi

        # a landing page with copy-pasteable install instructions
        sed "s|@@FINGERPRINT@@|$FPR|g" /src/packaging/repo-index.html \
            > index.html 2>/dev/null \
            || cp -f /src/packaging/repo-index.html index.html 2>/dev/null || true
        chmod -R a+rX /out
    '

echo "repository written to: $OUTDIR"
find "$OUTDIR" -maxdepth 3 -type f | head -20
