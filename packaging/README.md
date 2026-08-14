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
key the tree is still assembled but **unsigned**, which apt only accepts with
`[trusted=yes]` — acceptable for a local smoke test, not for publication.

Generating a dedicated archive key:

```sh
gpg --batch --quick-generate-key "ngx_http_pgp_auth archive" ed25519 sign never
gpg --armor --export-secret-keys <fpr>   # -> APT_GPG_PRIVATE_KEY secret
```

Keep the private key out of the repository. In CI it is read from the
`APT_GPG_PRIVATE_KEY` / `APT_GPG_PASSPHRASE` GitHub Actions secrets.

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
3. **publish** — only on a tag or manual run, and only if a signing key is
   configured.

## Hardening the release path

Everything below lives in repository settings or in how the signing key itself is
kept — none of it can be enforced from a file in this repository, so it is listed
here as the operator's checklist rather than silently assumed.

**1. Make the environment gate real.** The `publish` job declares
`environment: release`, but an environment with no rules is only a label. In
*Settings → Environments → release*, add required reviewers and scope
`APT_GPG_PRIVATE_KEY` / `APT_GPG_PASSPHRASE` to that environment instead of the
repository. In *Settings → Rules*, protect the `v*` tag pattern. Until both are
done, the authority to publish a signed package is exactly "repository write
access" — no separate compromise needed.

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
pinned Ubuntu version, `concurrency` keeps two publishes from interleaving, the
build job attests provenance for each `.deb`, and `publish` verifies the packages
against the digest manifest recorded at build time before signing anything.

**5. What none of it covers.** Provenance and the manifest bind the artifact to
the run that produced it; they say nothing about whether that run's own inputs
were trustworthy. A compromised build dependency pulled from Debian at build time
would be attested and signed exactly like a good one. Closing that requires
reproducible builds with independent rebuilders, which is out of proportion to a
project this size — it is named here so it is not mistaken for something the
controls above already handle.
