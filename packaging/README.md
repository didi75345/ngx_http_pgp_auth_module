# Debian packaging and APT repository

This directory builds `libnginx-mod-http-pgp-auth` — the module packaged as a
Debian dynamic nginx module — and assembles a signed APT repository from the
resulting `.deb` files.

## What the package does

| | |
|---|---|
| Package name | `libnginx-mod-http-pgp-auth` |
| Module | `/usr/lib/nginx/modules/ngx_http_pgp_auth_module.so` |
| Load snippet | `/usr/share/nginx/modules-available/mod-http-pgp-auth.conf` |
| Enabled as | `/etc/nginx/modules-enabled/50-mod-http-pgp-auth.conf` (symlink, created on install) |
| Depends | `nginx-abi-<version>`, `gnupg`, plus the usual shlib deps |
| Suggests | `redis-server` (only needed for the `redis` nonce backend) |

Two properties matter more than the rest:

* **It is built the way the distro builds nginx.** The module is compiled
  against the nginx source shipped by `nginx-dev`, using that release's own
  configure flags (`/usr/share/nginx/src/conf_flags`) — which include
  `--with-compat`. A module built with a different flag set will not load.
* **It carries the ABI dependency.** `dh_nginx` generates a dependency on
  `nginx-abi-<upstream-version>-<rev>`, the virtual package the nginx package
  provides. If nginx is later upgraded to a release with a different module
  ABI, apt refuses to install/keep this module rather than leaving you with an
  nginx that won't start.

Because of that ABI tie, a package is only valid for the Debian release it was
built on — hence one build per release, and a repository that serves both.

## Building

```sh
packaging/build-deb.sh trixie              # -> dist/trixie/*.deb
packaging/build-deb.sh bookworm            # -> dist/bookworm/*.deb
```

Each runs inside a container of the target release, so no build dependencies
are needed on the host beyond Docker. The version is suffixed per release
(`1.0.0~trixie1`, `1.0.0~bookworm1`) so a single repository can serve both
without version collisions.

## Assembling the repository

```sh
packaging/build-apt-repo.sh dist public
```

This produces a standard flat repository tree:

```
public/
  dists/<codename>/Release, InRelease, Release.gpg
  dists/<codename>/main/binary-amd64/Packages{,.gz}
  pool/<codename>/*.deb
  pgp-auth-archive-keyring.{asc,gpg}
```

### Signing

Set `APT_GPG_PRIVATE_KEY` (ASCII-armoured private key) and, if the key is
protected, `APT_GPG_PASSPHRASE`. The script then writes `InRelease` and
`Release.gpg` and exports the public key alongside the repository. Without a
key the script refuses to run, so an unsigned tree is never produced by
accident. For a local smoke test, ask for it explicitly:

```sh
APT_REPO_ALLOW_UNSIGNED=1 sh packaging/build-apt-repo.sh
```

The result is **unsigned**, which apt only accepts with `[trusted=yes]` —
acceptable while testing, never for publication.

Generating a dedicated archive key. **What goes into CI is a signing subkey,
never the primary key** — see "Hardening the release path" below for why, and for
the revocation certificate that makes the subkey recoverable:

```sh
# 1. primary key -- stays offline, never leaves this machine
gpg --batch --quick-generate-key "ngx_http_pgp_auth archive" ed25519 cert never

# 2. a signing subkey, which is the only part CI ever sees
gpg --quick-add-key <PRIMARY-FPR> ed25519 sign 2y
gpg --export-secret-subkeys --armor <SUBKEY-ID>!   # -> APT_GPG_PRIVATE_KEY
```

Note the trailing `!` — without it gpg exports every subkey. Users anchor on the
**primary** fingerprint, which is what the repository publishes, so rotating the
signing subkey never asks a single user to re-import anything.

For a purely local smoke test a single key is fine; for anything published, use
the split above. Keep the private material out of the repository — in CI it is
read from the `APT_GPG_PRIVATE_KEY` / `APT_GPG_PASSPHRASE` GitHub Actions secrets.

## Publishing

`.github/workflows/packages.yml` builds both releases on every push, and on a
`v*` tag (or a manual run) publishes the signed repository to GitHub Pages,
which serves it at `https://<owner>.github.io/<repo>/`. Any static host works
equally well — the tree is plain files; copy `public/` to it.

## CI checks

The workflow does more than build:

1. **build** — package both releases; fail if the `nginx-abi-*` dependency is
   missing; run `lintian`.
2. **install-test** — in a clean container of each release: install the `.deb`,
   confirm `nginx -t` passes with the module loaded, then run the module's own
   end-to-end suite **against the installed module** (`MODULE_SO=/usr/lib/nginx/
   modules/...`). This is the check that matters: it proves the shipped package
   actually authenticates, not merely that the source compiles. It then removes
   the package and confirms nginx still starts and the symlink is gone.
3. **sign** — only on a `v*` tag, and only if a signing key is configured.
   Waits for the `release` environment's reviewer before it runs. Verifies each package's provenance attestation and its digest
   manifest, then builds and signs the repository. Holds the signing key; has no
   write access to the repository and runs no third-party action.
4. **deploy** — publishes what `sign` produced to GitHub Pages. Tag runs only. Holds the write
   token and the third-party Pages action, and no signing material.

## Hardening the release path

Everything below lives in repository settings or in how the signing key itself is
kept — none of it can be enforced from a file in this repository, so it is listed
here as the operator's checklist rather than silently assumed.

**1. The environment gate.** The `sign` job declares `environment: release`,
which is only a label until the environment itself carries rules. The expected
configuration, and the one this repository uses, is:

- **Required reviewers** on the `release` environment, so a run stops and waits
  for a human before the signing key is available.
- **Deployment tags limited to `v*`, with no branches allowed.** This is why
  `sign` and `deploy` run on tag pushes only: a `workflow_dispatch` run carries a
  branch ref, which the environment refuses, so offering it would just fail at
  release time. A release is a tag.
- **Signing secrets held by the environment, not the repository.** If a copy also
  exists at repository level, any job can read it without going through the gate,
  and the gate buys nothing — check *Settings → Secrets and variables → Actions*
  is empty of them.
- **Administrators not allowed to bypass protection rules.**

Two honest limits. With a single maintainer, "required reviewers" means approving
your own release — a deliberate confirmation step, not separation of duties.
`Prevent self-review` should stay off until there is a second trusted reviewer,
or releases become impossible. And the environment governs *deployment*, not tag
creation: adding a ruleset in *Settings → Rules* that restricts who may create
`v*` tags is still worth doing, though with the reviewer gate in place a tag
alone no longer publishes anything.

**2. Never put the primary key in CI.** Keep the primary key offline (hardware
token or an airgapped machine) and give CI only a **signing subkey**, with a
revocation certificate for that subkey generated in advance and stored offline.
Users then anchor on the primary's fingerprint, so a compromised CI costs a
revocable subkey rather than the identity every apt client already trusts:

```sh
gpg --quick-add-key <PRIMARY-FPR> rsa4096 sign 2y      # create the signing subkey
gpg --export-secret-subkeys --armor <SUBKEY-ID>!  > ci-subkey.asc   # note the '!'
gpg --output subkey-revocation.asc --gen-revoke <SUBKEY-ID>
```

Put `ci-subkey.asc` in `APT_GPG_PRIVATE_KEY`; keep the primary and the revocation
certificate off the machine that builds. Rotating the subkey then does not force
a single user to re-import anything.

**3. Give users an anchor you do not serve yourself.** The published fingerprint
(`pgp-auth-archive-keyring.fingerprint`, also rendered into the landing page)
comes from the same origin as the packages, so it makes trust-on-first-use
explicit — it does not remove it. If a domain is available whose DNS and hosting
are controlled independently of the GitHub account, publish the primary key over
WKD there; a keyserver is worth doing as redundancy, not as a replacement. If you
stop short of that, leave the install docs saying plainly that trust is
first-use only, as they do today.

**4. What the pipeline already does.** Actions and base images are pinned by
digest, the checkout token is not persisted into `.git/config`, the runner is a
pinned Ubuntu version, and `concurrency` puts every publish-capable run into one
group so two `v*` tags cannot sign and deploy at the same time. The `build` job
attests provenance for each `.deb`; the `sign` job verifies that attestation with
`gh attestation verify`, checks the packages against the digest manifest recorded
at build time, and fails if the artifact contains any package the manifest does
not list — all before the signing key is used.

**5. What none of it covers.** Provenance and the manifest bind the artifact to
the run that produced it; they say nothing about whether that run's own inputs
were trustworthy. A compromised build dependency pulled from Debian at build time
would be attested and signed exactly like a good one. Closing that requires
reproducible builds with independent rebuilders, which is out of proportion to a
project this size — it is named here so it is not mistaken for something the
controls above already handle.

## Rebuilding after a Debian or nginx update

The usual reason to rebuild is that Debian shipped a **new nginx**. The package
depends on the virtual package `nginx-abi-<version>`, so once the distribution's
nginx changes ABI, the published `.deb` no longer installs at all — apt refuses
it rather than letting nginx fail to start.

**Is a rebuild needed?** Compare what the published package requires with what
the distribution now provides:

```sh
# what the published package requires. Select the stanza by name: the index
# also contains the -dbgsym package, and it comes first, so a plain
# `grep -m1 '^Depends:'` reads the wrong one.
curl -fsSL https://didi75345.github.io/ngx_http_pgp_auth_module/dists/trixie/main/binary-amd64/Packages \
  | awk '/^Package: libnginx-mod-http-pgp-auth$/,/^$/' \
  | grep '^Depends:' | tr ',' '\n' | grep nginx-abi

# same thing from a locally built package, without the repository
dpkg-deb -f dist/trixie/libnginx-mod-http-pgp-auth_*.deb Depends \
  | tr ',' '\n' | grep nginx-abi

# what the distribution provides today
docker run --rm debian:trixie-slim sh -c \
  'apt-get update -qq && apt-cache show nginx | grep -m1 "^Provides:"'
```

At the time of writing those agree — `nginx-abi-1.26.3-1` on Trixie and
`nginx-abi-1.22.1-7` on Bookworm. When they stop agreeing, rebuild.

**A rebuild always needs a version bump.** The package version comes from
`debian/changelog` (with `~bookworm1` / `~trixie1` appended at build time), so
rebuilding the same commit produces a package that is byte-different but claims
the *same* version. apt only offers an upgrade when the version changes, so
without a bump the rebuild never reaches a single user — and the repository ends
up serving two different packages under one version, which caches and mirrors
handle badly. This is why a rebuild is a commit, not just a re-run.

**The steps:**

```sh
# 1. optional but recommended: confirm the build still passes before committing.
#    Actions -> packages -> Run workflow. This runs the build and the install
#    tests; it cannot publish (releases come from v* tags only).

# 2. bump the changelog -- one entry, saying why
dch -i "Rebuild for nginx ABI 1.28.0-1"      # 1.0.0 -> 1.0.1

# 3. commit and tag
git commit -am "Rebuild for the new nginx ABI"
git push
git tag v1.0.1
git push origin v1.0.1

# 4. approve the run when it pauses at the `release` environment
```

The tag push starts the release: build, install-test, then `sign` waits for the
environment's reviewer, and `deploy` publishes. Nothing else is needed — the
repository is rebuilt from that run's artifacts, so the superseded packages drop
out of `pool/` on their own.

Two practical notes. `dch -i` needs `DEBEMAIL` and `DEBFULLNAME` set, or it will
stamp the entry with whatever the local host thinks your address is — the same
trap that once put `root@<container-id>` into a published package. And release
tags are protected against deletion and moving, so check the tag points where you
intend before pushing it: a mistake is fixed by releasing `v1.0.2`, not by
rewriting `v1.0.1`.
