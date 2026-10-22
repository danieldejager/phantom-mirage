#!/bin/sh
# Download and install the newest Phantom Mirage release (#110).
# Run as your normal user (gh must be logged in; no token is stored):
#
#   gh api -H 'Accept: application/vnd.github.raw' \
#     repos/danieldejager/phantom-mirage/contents/release/get-mirage.sh | sh
#   sh get-mirage.sh [--tag TAG] [install.sh options, e.g. -i eth0 -n CIDR]
#
# Picks the newest non-draft release (prereleases included) or --tag,
# the .run for this distro (/etc/os-release) and arch (dpkg
# --print-architecture), checks it against the release's SHA256SUMS and
# runs it with sudo. Everything is inside main() so a truncated
# "| sh" download runs nothing.
main() {
	set -eu
	REPO=danieldejager/phantom-mirage
	say() { echo "get-mirage: $*"; }
	die() { echo "get-mirage: $*" >&2; exit 1; }
	tag=
	while [ $# -gt 0 ]; do
		case $1 in
			--tag) [ $# -ge 2 ] || die "--tag needs a value"; tag=$2; shift 2 ;;
			--tag=*) tag=${1#*=}; shift ;;
			--) shift; break ;;
			*) break ;;
		esac
	done
	command -v gh >/dev/null 2>&1 || die "gh (GitHub CLI) is not installed"
	if ! gh auth status >/dev/null 2>&1; then
		echo "get-mirage: run gh auth login first" >&2
		exit 1
	fi
	arch=$(dpkg --print-architecture) || die "dpkg --print-architecture failed"
	osr=${PM_OS_RELEASE:-/etc/os-release}
	[ -r "$osr" ] || die "$osr not found"
	distro=$(. "$osr" && echo "${ID:-}${VERSION_ID:-}")
	if [ -z "$tag" ]; then
		tag=$(gh api "repos/$REPO/releases" --jq '[.[] | select(.draft | not)][0].tag_name // empty') || die "could not list releases"
		[ -n "$tag" ] || die "no published release found"
	fi
	assets=$(gh api "repos/$REPO/releases/tags/$tag" --jq '.assets[].name') || die "release $tag not found"
	run=$(printf '%s\n' "$assets" | grep -E "^phantom-mirage_[^_]+_${distro}_${arch}\.run\$" | sort -V | tail -n 1 || true)
	[ -n "$run" ] || die "release $tag has no .run for $distro/$arch (assets: $(printf '%s ' $assets))"
	printf '%s\n' "$assets" | grep -qx SHA256SUMS || die "release $tag has no SHA256SUMS"
	say "release $tag: $run"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM HUP
	gh release download "$tag" -R "$REPO" -D "$tmp" -p "$run" -p SHA256SUMS || die "download failed"
	(cd "$tmp" && grep -E "[ *]${run}\$" SHA256SUMS > run.sum) || die "$run is not listed in SHA256SUMS"
	(cd "$tmp" && sha256sum -c run.sum) || die "checksum mismatch for $run; not installing"
	say "checksum OK; running: sudo sh $run $*"
	rc=0
	sudo sh "$tmp/$run" "$@" || rc=$?
	return $rc
}
main "$@"
