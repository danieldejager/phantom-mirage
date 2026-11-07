# Release assets: where each file comes from

A prerelease has 19 assets. The packages come from runs on the release
commit. The scripts come from the repo. SHA256SUMS is made locally over
the other 18 files.

`build` on a push produces the Debian 13 packages (amd64 on the usual
runner, arm64 on a native arm64 runner in a Debian 13 container). The
Ubuntu 24.04 packages come from the heavy Ubuntu 24.04 systemd jobs in
that same workflow (schedule, `workflow_dispatch`, or a pull request
labelled `full-ci`). The Ubuntu 26.04 packages come from the manual
`ubuntu-26.04` workflow, or from that pull-request label.

| Asset | Source | Artifact / path |
|---|---|---|
| `phantom-mirage_<ver>_debian13_amd64.deb` | `build` (push), job ".deb" | `phantom-mirage-deb`: `phantom-mirage_<ver>_amd64.deb`, renamed |
| `phantom-mirage_<ver>_debian13_arm64.deb` | `build` (push), job "arm64 .deb" | `phantom-mirage-deb-arm64`: `phantom-mirage_<ver>_arm64.deb`, renamed |
| `phantom-mirage-common_<ver>_debian13_all.deb` | `build` (push) | `phantom-mirage-deb`: `phantom-mirage-common_<ver>_all.deb`, renamed. The arm64 job builds the same `Architecture: all` package; publish one copy |
| `phantom-mirage_<ver>_debian13_{amd64,arm64}.run` | `build` (push) | `phantom-mirage-run-debian13` and `phantom-mirage-run-debian13-arm64` |
| `phantom-mirage_<ver>_ubuntu24.04_{amd64,arm64}.deb` | `build` heavy systemd job | `phantom-mirage_ubuntu24.04_<arch>` |
| `phantom-mirage-common_<ver>_ubuntu24.04_all.deb` | `build` heavy systemd job | `phantom-mirage_ubuntu24.04_<arch>` (same file for both arches; publish one copy) |
| `phantom-mirage_<ver>_ubuntu24.04_{amd64,arm64}.run` | `build` heavy systemd job | `phantom-mirage-run-ubuntu24.04-<arch>` |
| `phantom-mirage_<ver>_ubuntu26.04_{amd64,arm64}.deb` | `ubuntu-26.04` | `phantom-mirage_ubuntu26.04_<arch>` |
| `phantom-mirage-common_<ver>_ubuntu26.04_all.deb` | `ubuntu-26.04` | `phantom-mirage_ubuntu26.04_<arch>` (same file for both arches) |
| `phantom-mirage_<ver>_ubuntu26.04_{amd64,arm64}.run` | `ubuntu-26.04` | `phantom-mirage-run-ubuntu26.04-<arch>` |
| `install.sh`, `get-mirage.sh` | repo | `release/` |
| `phantom-mirage-uninstall` | repo | `debian/scripts/` |
| `SHA256SUMS` | local | `sha256sum` over the other 18 files |

The .debs and .run files in a release must come from runs on the release
commit, and `debian/changelog` must already carry `<ver>`.

## What is supported

Release installers exist for these Linux systems, both as a `.deb` and as
a `.run` that refuses any other distro or processor:

| System | amd64 | arm64 | How it is tested |
|---|---|---|---|
| Debian 13 | yes | yes | Package build and install inside a Debian 13 container. amd64 runs on the usual runner. arm64 runs on a native arm64 runner, still in a container, so it is not a systemd-as-PID-1 host. The arm64 daemon's seccomp allowlist is the separate `--sandbox-daemon` job on that same runner |
| Ubuntu 24.04 | yes | yes | Real runner, systemd as PID 1: packaged unit, AppArmor, service scripts, then the `.run` fresh install, restart, reload, upgrade and uninstall |
| Ubuntu 26.04 | yes | yes | Real runner, systemd as PID 1, including upgrade from an older published `.run` |

`get-mirage.sh` selects the `.run` from `/etc/os-release` (`ID` +
`VERSION_ID`) and `dpkg --print-architecture`. Automatic selection skips
a release that has no files. `mark-1` is such a release: it is not a
prerelease and it is newer than `v1.7.0`, but it is not an install
target. `--tag` can still name it.

Native Windows and native macOS are not supported. A Mac is a supported
place to run one of the Linux systems above in a virtual machine, which
is how the Ubuntu 26.04 arm64 installer is used. Arch Linux has source
build instructions in the README only; there is no Arch package and no
`.run`.
