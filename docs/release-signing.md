# Release signing and safe installs (#121)

## Signed SHA256SUMS (optional until a key is committed)

`release/get-mirage.sh` and `release/install.sh` verify the `.run`/`.deb`
files against the release's `SHA256SUMS`. A detached cosign signature over
that file, `SHA256SUMS.sig`, proves who made the release:

* **No `release/SHA256SUMS.pub` committed (today):** checksums only, and a
  warning says `SHA256SUMS is unsigned`.
* **`release/SHA256SUMS.pub` committed on the default branch:** get-mirage.sh
  fetches it, and a release without a valid `SHA256SUMS.sig` is refused
  (nothing is run with sudo). `cosign` must be installed on the sensor.
  `PM_SIGNING_PUBKEY=/path/key.pub` uses a local copy instead.
* `install.sh` run from a folder of .debs does the same when
  `SHA256SUMS.pub` and `SHA256SUMS.sig` sit next to it. Inside a `.run` it
  relies on get-mirage.sh having verified the signed outer `SHA256SUMS`.

Signatures are made with a private key, with no transparency log
(`--tlog-upload=false`), and verified with `--insecure-ignore-tlog=true`,
the same as the container images (docs/docker.md).

### Adding the key (one-off, by the repo owner)

Do this on a trusted machine. Never commit the private key.

```sh
cosign generate-key-pair            # asks for a password; writes cosign.key + cosign.pub
gh secret set SHA256SUMS_COSIGN_KEY      -R danieldejager/phantom-mirage < cosign.key
gh secret set SHA256SUMS_COSIGN_PASSWORD -R danieldejager/phantom-mirage   # paste the password
cp cosign.pub release/SHA256SUMS.pub     # commit this public key in a PR
# keep cosign.key offline (password manager / encrypted backup), then shred the working copy
```

Order matters: set the secrets and publish one signed release **before**
merging `release/SHA256SUMS.pub`, because once the public key is on the
default branch get-mirage.sh refuses releases without a signature.

### Release workflow

The ubuntu-26.04 workflow signs `run/SHA256SUMS` into `run/SHA256SUMS.sig`
only when the `SHA256SUMS_COSIGN_KEY` secret exists, and otherwise skips
with a notice. It fails if the secret does not match a committed
`release/SHA256SUMS.pub`. If you combine several SHA256SUMS into one
release file by hand, sign the final file locally and upload the signature
with it:

```sh
cosign sign-blob --key cosign.key --tlog-upload=false --output-signature SHA256SUMS.sig SHA256SUMS
gh release upload TAG SHA256SUMS SHA256SUMS.sig --clobber -R danieldejager/phantom-mirage
```

## Choosing the release channel

```sh
sh get-mirage.sh                 # default: newest published release by date, prereleases included
sh get-mirage.sh --prerelease    # the same, stated explicitly
sh get-mirage.sh --stable        # newest non-prerelease
sh get-mirage.sh --tag v1.7.0-4  # exactly this release
# piped: gh api ... | sh -s -- --stable -i eth0
```

## Install rollback

`install.sh` removes the old version before installing the new one. Before
removing anything it saves the old install in
`/var/backups/phantom-mirage.keep`: `debs/` (the previous packages, via
dpkg-repack, the apt cache or apt-get download) and `state.tar`
(`/etc/default/phantom-mirage`, `/etc/init.d/phantom-mirage`,
`/etc/phantom-mirage`, `/var/lib/phantom-mirage`, `/var/log/phantom-mirage`).
If the uninstall, `apt-get install` or `phantom-mirage-setup` fails, it
purges the half-installed new version, reinstalls `debs/*.deb` and unpacks
`state.tar`, then prints the backup location. To restore by hand:

```sh
sudo apt-get install -y --allow-downgrades /var/backups/phantom-mirage.keep/debs/*.deb
sudo tar -C / -xpf /var/backups/phantom-mirage.keep/state.tar
```

After a successful install the backup is removed. `ci/test_install_rollback.sh`
forces failed installs with mocked dpkg/apt-get and checks the rollback.
