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
