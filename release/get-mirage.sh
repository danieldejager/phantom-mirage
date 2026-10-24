#!/bin/sh
# Download and install the newest Phantom Mirage release (#110).
# Run as your normal user (gh must be logged in; no token is stored):
#
#   gh api -H 'Accept: application/vnd.github.raw' \
#     repos/danieldejager/phantom-mirage/contents/release/get-mirage.sh | sh
#   sh get-mirage.sh [--tag TAG | --stable | --prerelease] [install.sh options, e.g. -i eth0 -n CIDR]
#   (with "| sh", pass options as: ... | sh -s -- --stable -i eth0)
#
# Picks the most recently published non-draft release (by published_at,
# prereleases included; the API order and the Latest flag are ignored),
# or with --stable the newest non-prerelease, or --tag TAG. --prerelease
# states the default explicitly. Then the .run for this distro
# (/etc/os-release) and arch (dpkg --print-architecture), checks it
# against the release's SHA256SUMS and runs it with sudo.
#
# Signature (#121): if release/SHA256SUMS.pub (a cosign public key) is
# committed on the default branch (or PM_SIGNING_PUBKEY names a local
# copy), the release must carry SHA256SUMS.sig and it must verify with
# cosign verify-blob, or nothing is installed. Without the key the
# checksums are used alone and a warning says they are unsigned. Everything is inside main() so a truncated
# "| sh" download runs nothing.
main() {
	set -eu
	REPO=danieldejager/phantom-mirage
	say() { echo "get-mirage: $*"; }
	die() { echo "get-mirage: $*" >&2; exit 1; }
	tag= channel=prerelease
	while [ $# -gt 0 ]; do
		case $1 in
			--tag) [ $# -ge 2 ] || die "--tag needs a value"; tag=$2; shift 2 ;;
			--tag=*) tag=${1#*=}; shift ;;
			--stable) channel=stable; shift ;;
			--prerelease|--pre) channel=prerelease; shift ;;
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
		sel='select(.draft | not)'
		[ "$channel" = prerelease ] || sel='select((.draft | not) and (.prerelease | not))'
		tag=$(gh api "repos/$REPO/releases" --jq "[.[] | $sel] | sort_by(.published_at) | last | .tag_name // empty") || die "could not list releases"
		[ -n "$tag" ] || die "no published $( [ "$channel" = stable ] && echo 'stable ')release found"
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
	pub=
	if [ -n "${PM_SIGNING_PUBKEY:-}" ]; then
		cp "$PM_SIGNING_PUBKEY" "$tmp/SHA256SUMS.pub" || die "cannot read $PM_SIGNING_PUBKEY"; pub=1
	elif gh api -H 'Accept: application/vnd.github.raw' "repos/$REPO/contents/release/SHA256SUMS.pub" > "$tmp/SHA256SUMS.pub" 2>/dev/null && [ -s "$tmp/SHA256SUMS.pub" ]; then
		pub=1
	fi
	if [ -n "$pub" ]; then
		printf '%s\n' "$assets" | grep -qx SHA256SUMS.sig || die "release $tag has no SHA256SUMS.sig but a signing key is published; refusing an unsigned release"
		command -v cosign >/dev/null 2>&1 || die "cosign is needed to verify SHA256SUMS.sig (https://docs.sigstore.dev/cosign/system_config/installation/)"
		gh release download "$tag" -R "$REPO" -D "$tmp" -p SHA256SUMS.sig || die "download of SHA256SUMS.sig failed"
		cosign verify-blob --key "$tmp/SHA256SUMS.pub" --signature "$tmp/SHA256SUMS.sig" --insecure-ignore-tlog=true "$tmp/SHA256SUMS" >/dev/null 2>&1 || die "SHA256SUMS signature does not verify; not installing"
		say "SHA256SUMS signature OK"
	else
		say "warning: SHA256SUMS is unsigned (no release/SHA256SUMS.pub published yet); the checksum proves integrity, not who made the release"
	fi
	say "checksum OK; running: sudo sh $run $*"
	rc=0
	sudo sh "$tmp/$run" "$@" || rc=$?
	return $rc
}
main "$@"
