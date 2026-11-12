# Release assets: where each file comes from

Mark 1 installers are Ubuntu 26.04 only, amd64 and arm64. A Mark 1
prerelease has 9 assets. The packages come from one `ubuntu-26.04`
workflow run on the release commit (manual dispatch, or a pull request
labelled `full-ci` or `ci-ubuntu-26.04`). The scripts come from the repo.
SHA256SUMS is made locally over the other 8 files.

| Asset | Source | Artifact / path |
|---|---|---|
| `phantom-mirage_<ver>_ubuntu26.04_{amd64,arm64}.deb` | `ubuntu-26.04` | `phantom-mirage_ubuntu26.04_<arch>` |
| `phantom-mirage-common_<ver>_ubuntu26.04_all.deb` | `ubuntu-26.04` | `phantom-mirage_ubuntu26.04_<arch>` (same file for both arches; publish one copy) |
| `phantom-mirage_<ver>_ubuntu26.04_{amd64,arm64}.run` | `ubuntu-26.04` | `phantom-mirage-run-ubuntu26.04-<arch>` |
| `install.sh`, `get-mirage.sh` | repo | `release/` |
| `phantom-mirage-uninstall` | repo | `debian/scripts/` |
| `SHA256SUMS` | local | `sha256sum` over the other 8 files |

The .debs and .run files must come from a run on the release commit, and
`debian/changelog` must already carry `<ver>`.

`get-mirage.sh` is downloaded from the Latest release, not from a branch:

```sh
curl -fsSL https://github.com/danieldejager/phantom-mirage/releases/latest/download/get-mirage.sh | sudo bash
```

With no channel flag this selects GitHub's Latest release. `--stable` is
the same. A release with no files is skipped. `--prerelease` takes the
newest release that has files, including prereleases. `--tag` can still
name one. The script then downloads that release's `.run`, `SHA256SUMS`
and `SHA256SUMS.sig`.

Ubuntu 24.04 is not a Mark 1 installer. The heavy systemd jobs run on
Ubuntu 24.04 GitHub runners, which is the runner image, not a shipped
distro name. `install.sh` warns on anything other than `ubuntu26.04` or
`debian13`.

Debian packages and the container image are not Mark 1 assets. CI still
builds the Debian 13 amd64 `.deb` for development, and a `v*` tag still
starts `.github/workflows/publish.yml`. Neither belongs in the Mark 1
download set. A Mark 1 tag that is not `v*` does not start that workflow.
