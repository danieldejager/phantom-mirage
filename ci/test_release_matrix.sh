#!/bin/sh
# The release installers the workflows actually build, and the distros
# install.sh treats as tested. A name that is only in one of those places
# is a package the release assembly would drop or a distro the installer
# would warn about.
set -eu
cd "$(dirname "$0")/.."
fail() { echo "release-matrix: $*" >&2; exit 1; }

grep -q 'ubuntu24.04|ubuntu26.04|debian13' release/install.sh || fail "install.sh tested-distro list"
grep -q 'make-run.sh debs debian13 "$(dpkg --print-architecture)" run' .github/workflows/build.yml || fail "debian13 amd64 .run step"
grep -q 'make-run.sh debs debian13 arm64 run' .github/workflows/build.yml || fail "debian13 arm64 .run step"
grep -q 'make-run.sh debs ubuntu24.04 ${{ matrix.arch }} run' .github/workflows/build.yml || fail "ubuntu24.04 .run step"
grep -q 'make-run.sh out ubuntu26.04 ${{ matrix.arch }} run' .github/workflows/ubuntu2604.yml || fail "ubuntu26.04 .run step"
grep -q 'phantom-mirage_<ver>_debian13_arm64.deb' docs/releasing.md || fail "releasing.md missing debian13 arm64 deb"
grep -q 'phantom-mirage-run-ubuntu24.04-<arch>' docs/releasing.md || fail "releasing.md missing ubuntu24.04 run"
grep -q 'Native Windows and native macOS are not supported' docs/releasing.md || fail "releasing.md missing the native-OS boundary"

# make-run names the new distro/arch pairs, and the header records them.
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/tree/release" "$t/tree/debian/scripts" "$t/debs" "$t/out"
cp release/make-run.sh "$t/tree/release/"
printf '#!/bin/sh\nexit 0\n' > "$t/tree/release/install.sh"
printf '#!/bin/sh\nexit 0\n' > "$t/tree/debian/scripts/phantom-mirage-uninstall"
chmod +x "$t/tree/release/install.sh" "$t/tree/debian/scripts/phantom-mirage-uninstall"
one() { # distro arch
	rm -rf "$t/debs" "$t/out"
	mkdir -p "$t/debs" "$t/out"
	echo main > "$t/debs/phantom-mirage_9.9.9-1_$1_$2.deb"
	echo common > "$t/debs/phantom-mirage-common_9.9.9-1_$1_all.deb"
	run=$(sh "$t/tree/release/make-run.sh" "$t/debs" "$1" "$2" "$t/out")
	base=$(basename "$run")
	[ "$base" = "phantom-mirage_9.9.9-1_$1_$2.run" ] || fail "name $base"
	grep -q "PM_DISTRO=$1" "$run" || fail "header distro $1"
	grep -q "PM_ARCH=$2" "$run" || fail "header arch $2"
}
one ubuntu24.04 amd64
one ubuntu24.04 arm64
one debian13 arm64
one ubuntu26.04 amd64
echo "release-matrix OK"
