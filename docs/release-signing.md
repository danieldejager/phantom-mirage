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

Signing is done **offline only**: the private key never leaves the repo
owner's trusted machine, and no workflow or Actions secret holds it, so
being able to run workflows here is not enough to sign a release.
Signatures use no transparency log (`--tlog-upload=false`) and are
verified with `--insecure-ignore-tlog=true`.

### Adding the key (one-off, by the repo owner)

On your own trusted machine (never in CI, never committed):

```sh
cosign generate-key-pair            # asks for a password; writes cosign.key + cosign.pub
cp cosign.pub release/SHA256SUMS.pub     # commit only the public key, in a PR
# keep cosign.key offline (encrypted backup / password manager)
```

### Signing each release

Download the release's final `SHA256SUMS` (after all .run/.deb assets are
uploaded), check it, sign it locally and upload the signature:

```sh
gh release download TAG -R danieldejager/phantom-mirage -p SHA256SUMS
cosign sign-blob --key cosign.key --tlog-upload=false --output-signature SHA256SUMS.sig SHA256SUMS
cosign verify-blob --key release/SHA256SUMS.pub --signature SHA256SUMS.sig --insecure-ignore-tlog=true SHA256SUMS
gh release upload TAG SHA256SUMS.sig -R danieldejager/phantom-mirage
```

Order matters: sign at least the newest release (and any you still want
installable with `--tag`) **before** merging `release/SHA256SUMS.pub`,
because once the public key is on the default branch get-mirage.sh refuses
releases without a valid signature. Re-sign if SHA256SUMS is ever replaced.

Until the public key is committed and releases are signed, #121 M1 is only
partly closed: the checksums prove integrity, not who made the release.

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

install.sh installs dpkg-repack with apt-get first if it is missing (the
package also Recommends it). Without a mirror it warns and the rollback
restores config and data only; reinstall the old version with
`get-mirage.sh --tag`.

After a successful install the backup is removed. `ci/test_install_rollback.sh`
forces failed installs with mocked dpkg/apt-get and checks the rollback.
