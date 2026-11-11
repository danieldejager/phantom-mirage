#!/bin/sh
# Mark 1 installers are Ubuntu 26.04 amd64 and arm64 only.
set -eu
cd "$(dirname "$0")/.."
fail() { echo "release-matrix: $*" >&2; exit 1; }

grep -q 'ubuntu26.04|debian13' release/install.sh || fail "install.sh distro list changed"
! grep -q 'ubuntu24.04|' release/install.sh || fail "install.sh treats ubuntu24.04 as tested"
grep -q 'make-run.sh out ubuntu26.04 ${{ matrix.arch }} run' .github/workflows/ubuntu2604.yml || fail "ubuntu26.04 .run step missing"
! grep -q 'make-run.sh debs debian13 arm64 run' .github/workflows/build.yml || fail "debian13 arm64 .run was added"
! grep -q 'make-run.sh debs ubuntu24.04' .github/workflows/build.yml || fail "ubuntu24.04 .run was added"
grep -q 'Mark 1 installers are Ubuntu 26.04 only' docs/releasing.md || fail "releasing.md is not Ubuntu-only"
! grep -q 'debian13_arm64' docs/releasing.md || fail "releasing.md lists a Debian arm64 asset"
! grep -q 'ubuntu24.04_' docs/releasing.md || fail "releasing.md lists an Ubuntu 24.04 asset"

t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/tree/release" "$t/tree/debian/scripts" "$t/debs" "$t/out"
cp release/make-run.sh "$t/tree/release/"
printf '#!/bin/sh\nexit 0\n' > "$t/tree/release/install.sh"
printf '#!/bin/sh\nexit 0\n' > "$t/tree/debian/scripts/phantom-mirage-uninstall"
chmod +x "$t/tree/release/install.sh" "$t/tree/debian/scripts/phantom-mirage-uninstall"
for arch in amd64 arm64; do
	rm -rf "$t/debs" "$t/out"
	mkdir -p "$t/debs" "$t/out"
	echo main > "$t/debs/phantom-mirage_9.9.9-1_ubuntu26.04_$arch.deb"
	echo common > "$t/debs/phantom-mirage-common_9.9.9-1_ubuntu26.04_all.deb"
	run=$(sh "$t/tree/release/make-run.sh" "$t/debs" ubuntu26.04 "$arch" "$t/out")
	base=$(basename "$run")
	[ "$base" = "phantom-mirage_9.9.9-1_ubuntu26.04_$arch.run" ] || fail "name $base"
	grep -q "PM_DISTRO=ubuntu26.04" "$run" || fail "header distro"
	grep -q "PM_ARCH=$arch" "$run" || fail "header arch $arch"
done
echo "release-matrix OK"
