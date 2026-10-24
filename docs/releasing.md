# Release assets: where each file comes from

A prerelease has 12 assets. Two workflow runs on the same master commit
produce all the packages: the automatic `build` push run and one manual
`ubuntu-26.04` run (workflow_dispatch). The scripts come from the repo.
SHA256SUMS is made locally over the other 11 files.

| Asset | Source | Artifact / path |
|---|---|---|
| `phantom-mirage_<ver>_debian13_amd64.deb` | `build` (push), job ".deb" | `phantom-mirage-deb`: `phantom-mirage_<ver>_amd64.deb`, renamed |
| `phantom-mirage-common_<ver>_debian13_all.deb` | `build` (push) | `phantom-mirage-deb`: `phantom-mirage-common_<ver>_all.deb`, renamed |
| `phantom-mirage_<ver>_debian13_amd64.run` | `build` (push) | `phantom-mirage-run-debian13` |
| `phantom-mirage_<ver>_ubuntu26.04_{amd64,arm64}.deb` | `ubuntu-26.04` (manual) | `phantom-mirage_ubuntu26.04_<arch>` |
| `phantom-mirage-common_<ver>_ubuntu26.04_all.deb` | `ubuntu-26.04` (manual) | `phantom-mirage_ubuntu26.04_<arch>` (same file for both arches) |
| `phantom-mirage_<ver>_ubuntu26.04_{amd64,arm64}.run` | `ubuntu-26.04` (manual) | `phantom-mirage-run-ubuntu26.04-<arch>` |
| `install.sh`, `get-mirage.sh` | repo | `release/` |
| `phantom-mirage-uninstall` | repo | `debian/scripts/` |
| `SHA256SUMS` | local | `sha256sum` over the other 11 files |

The .debs and .run files in a release must come from runs on the release
commit, and `debian/changelog` must already carry `<ver>`.
