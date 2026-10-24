#!/bin/sh
# Build a self-extracting installer (#110):
#
#   release/make-run.sh DEBDIR DISTRO ARCH [OUTDIR]
#
# DEBDIR holds phantom-mirage_<ver>_<distro>_<arch>.deb and
# phantom-mirage-common_<ver>_<distro>_all.deb (<ver> = the Debian
# version, e.g. 1.7.0-4). Writes OUTDIR/phantom-mirage_<ver>_<distro>_<arch>.run:
# a POSIX sh header followed by a tar.gz of the two .debs, install.sh,
# phantom-mirage-uninstall and an inner SHA256SUMS. Run it with
#   sudo sh phantom-mirage_<ver>_<distro>_<arch>.run [install.sh options]
set -eu
die() { echo "make-run.sh: $*" >&2; exit 1; }
[ $# -ge 3 ] || die "usage: make-run.sh DEBDIR DISTRO ARCH [OUTDIR]"
debdir=$1 distro=$2 arch=$3 out=${4:-.}
here=$(cd "$(dirname "$0")" && pwd)
top=$(dirname "$here")

main=$(cd "$debdir" && ls -1 | grep -E "^phantom-mirage_[^_]+_${distro}_${arch}\.deb\$" | sort -V | tail -n 1) || true
[ -n "$main" ] || die "no phantom-mirage_*_${distro}_${arch}.deb in $debdir"
ver=$(echo "$main" | sed -E 's/^phantom-mirage_([^_]+)_.*/\1/')
common=phantom-mirage-common_${ver}_${distro}_all.deb
[ -f "$debdir/$common" ] || die "$common not in $debdir"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir "$work/p"
cp "$debdir/$main" "$debdir/$common" "$work/p/"
cp "$here/install.sh" "$work/p/install.sh"
cp "$top/debian/scripts/phantom-mirage-uninstall" "$work/p/phantom-mirage-uninstall"
(cd "$work/p" && sha256sum "$main" "$common" install.sh phantom-mirage-uninstall > SHA256SUMS)
(cd "$work/p" && tar -czf "$work/payload.tgz" "$main" "$common" install.sh phantom-mirage-uninstall SHA256SUMS)
sum=$(sha256sum "$work/payload.tgz" | cut -d' ' -f1)

cat > "$work/header" <<'HDR'
#!/bin/sh
# Phantom Mirage self-extracting installer: sudo sh THIS.run [install.sh options]
# (e.g. -i eth0 -n 192.0.2.248/29). Built by release/make-run.sh.
main() {
	set -eu
	PM_VER=@VER@
	PM_DISTRO=@DISTRO@
	PM_ARCH=@ARCH@
	PM_SUM=@SUM@
	self=$0
	die() { echo "$(basename "$self"): $*" >&2; exit 1; }
	[ -r "$self" ] || die "cannot read myself; run it as: sudo sh FILE.run"
	have_arch=$(dpkg --print-architecture 2>/dev/null || echo unknown)
	have_distro=unknown
	osr=${PM_OS_RELEASE:-/etc/os-release}
	if [ -r "$osr" ]; then have_distro=$(. "$osr" && echo "${ID:-}${VERSION_ID:-}"); fi
	[ "$have_distro" = "$PM_DISTRO" ] || die "this installer is for $PM_DISTRO, but this system is $have_distro; download the .run for $have_distro"
	[ "$have_arch" = "$PM_ARCH" ] || die "this installer is for $PM_ARCH, but this system is $have_arch; download the .run for $have_arch"
	skip=$(awk '/^__PM_PAYLOAD_BELOW__$/ { print NR + 1; exit }' "$self")
	[ -n "$skip" ] || die "payload marker not found (file truncated?)"
	got=$(tail -n +"$skip" "$self" | sha256sum | cut -d' ' -f1)
	[ "$got" = "$PM_SUM" ] || die "payload checksum mismatch (got $got, want $PM_SUM); download the file again"
	[ "$(id -u)" = 0 ] || die "run as root: sudo sh $self"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM HUP
	tail -n +"$skip" "$self" | tar -xzf - -C "$tmp"
	(cd "$tmp" && sha256sum -c --quiet SHA256SUMS) || die "inner SHA256SUMS mismatch"
	echo "phantom-mirage $PM_VER ($PM_DISTRO/$PM_ARCH): payload verified, running install.sh"
	rc=0
	(cd "$tmp" && PM_FROM_RUN=1 sh install.sh "$@") || rc=$?
	return $rc
}
main "$@"
exit $?
__PM_PAYLOAD_BELOW__
HDR
sed -i -e "s/@VER@/$ver/" -e "s/@DISTRO@/$distro/" -e "s/@ARCH@/$arch/" -e "s/@SUM@/$sum/" "$work/header"
mkdir -p "$out"
dst="$out/phantom-mirage_${ver}_${distro}_${arch}.run"
cat "$work/header" "$work/payload.tgz" > "$dst"
chmod 755 "$dst"
echo "$dst"
