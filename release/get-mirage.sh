#!/bin/sh
# Install Phantom Mirage on Ubuntu 26.04 (amd64 or arm64). No gh account.
#
#   curl -fsSL https://github.com/danieldejager/phantom-mirage/releases/latest/download/get-mirage.sh | sudo bash
#   sudo bash get-mirage.sh --yes -i eth0 -n 192.0.2.248/29
#
# With no channel flag, and with --stable, this uses GitHub's Latest
# release (mark-1). A release with no files is skipped. --tag names one
# release and does not substitute another. --prerelease is the newest
# published release that has files, including prereleases. Extra arguments
# are passed to the .run installer.
#
# The release SHA256SUMS.sig is a cosign sign-blob signature: ECDSA P-256
# over the SHA-256 of SHA256SUMS. openssl dgst -sha256 -verify checks that
# same signature. Checksums and the signature are always required.
# Everything is inside main() so a truncated "| sh" download runs nothing.
main() {
	set -eu
	REPO=danieldejager/phantom-mirage
	API=https://api.github.com/repos/$REPO
	PUB=$API/contents/release/SHA256SUMS.pub
	say() { echo "get-mirage: $*"; }
	die() { echo "get-mirage: $*" >&2; exit 1; }

	tag= channel=stable
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

	if [ "$(id -u)" != 0 ] && [ -z "${PM_GET_MIRAGE_TEST:-}" ]; then
		die "run as root: curl -fsSL https://github.com/$REPO/releases/latest/download/get-mirage.sh | sudo bash"
	fi

	osr=${PM_OS_RELEASE:-/etc/os-release}
	[ -r "$osr" ] || die "$osr not found"
	# shellcheck disable=SC1090
	distro=$(. "$osr" && echo "${ID:-}${VERSION_ID:-}")
	pretty=$(. "$osr" && echo "${PRETTY_NAME:-$distro}")
	[ "$distro" = ubuntu26.04 ] || die "this installer is for Ubuntu 26.04; this system is $pretty"
	arch=$(dpkg --print-architecture) || die "dpkg --print-architecture failed"
	case $arch in
		amd64|arm64) ;;
		*) die "this installer is for amd64 or arm64; this system is $arch" ;;
	esac

	if [ -z "${PM_GET_MIRAGE_TEST:-}" ]; then
		need=
		command -v curl >/dev/null 2>&1 || need="$need curl"
		command -v jq >/dev/null 2>&1 || need="$need jq"
		command -v openssl >/dev/null 2>&1 || need="$need openssl"
		command -v base64 >/dev/null 2>&1 || need="$need coreutils"
		[ -f /etc/ssl/certs/ca-certificates.crt ] || need="$need ca-certificates"
		if [ -n "$need" ]; then
			say "installing$need"
			apt-get update
			# shellcheck disable=SC2086
			DEBIAN_FRONTEND=noninteractive apt-get install -y $need
		fi
	fi
	command -v curl >/dev/null 2>&1 || die "curl is not installed"
	command -v jq >/dev/null 2>&1 || die "jq is not installed"
	command -v openssl >/dev/null 2>&1 || die "openssl is not installed"

	fetch() { # url [output]
		hdr="Accept: application/vnd.github+json"
		tok=${GH_TOKEN:-${GITHUB_TOKEN:-}}
		if [ -n "$tok" ]; then
			if [ $# -ge 2 ]; then
				curl -fsSL --max-time 60 -H "$hdr" -H "Authorization: Bearer $tok" -o "$2" "$1"
			else
				curl -fsSL --max-time 60 -H "$hdr" -H "Authorization: Bearer $tok" "$1"
			fi
		else
			if [ $# -ge 2 ]; then
				curl -fsSL --max-time 60 -H "$hdr" -o "$2" "$1"
			else
				curl -fsSL --max-time 60 -H "$hdr" "$1"
			fi
		fi
	}
	fetch "$API" /dev/null || die "cannot reach https://api.github.com (check DNS and outbound HTTPS)"

	assets_of() { # json -> names, one per line
		printf '%s' "$1" | jq -r '(.assets // [])[].name'
	}
	has_files() { # json
		[ "$(printf '%s' "$1" | jq -r '(.assets // []) | length')" -gt 0 ]
	}

	if [ -z "$tag" ]; then
		if [ "$channel" = stable ]; then
			latest=$(fetch "$API/releases/latest") || die "could not read the Latest release"
			if has_files "$latest"; then
				tag=$(printf '%s' "$latest" | jq -r '.tag_name // empty')
			else
				say "Latest release has no files; looking for an older stable release"
				list=$(fetch "$API/releases") || die "could not list releases"
				tag=$(printf '%s' "$list" | jq -r '[.[] | select((.draft | not) and (.prerelease | not) and ((.assets // []) | length) > 0)] | sort_by(.published_at) | last | .tag_name // empty')
			fi
			[ -n "$tag" ] || die "no published stable release with files"
		else
			list=$(fetch "$API/releases") || die "could not list releases"
			tag=$(printf '%s' "$list" | jq -r '[.[] | select((.draft | not) and ((.assets // []) | length) > 0)] | sort_by(.published_at) | last | .tag_name // empty')
			[ -n "$tag" ] || die "no published release with files"
		fi
	fi
	case $tag in
		*[!A-Za-z0-9._-]*) die "release tag contains unexpected characters: $tag" ;;
	esac
	rel=$(fetch "$API/releases/tags/$tag") || die "release $tag not found"
	assets=$(assets_of "$rel")
	run=$(printf '%s\n' "$assets" | grep -E "^phantom-mirage_[^_]+_${distro}_${arch}\.run\$" | sort -V | tail -n 1 || true)
	[ -n "$run" ] || die "release $tag has no .run for $distro/$arch (assets: $(printf '%s ' $assets))"
	printf '%s\n' "$assets" | grep -qx SHA256SUMS || die "release $tag has no SHA256SUMS"
	printf '%s\n' "$assets" | grep -qx SHA256SUMS.sig || die "release $tag has no SHA256SUMS.sig; refusing an unsigned release"
	say "release $tag: $run"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM HUP
	base="https://github.com/$REPO/releases/download/$tag"
	fetch "$base/$run" "$tmp/$run" || die "download of $run failed"
	fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download of SHA256SUMS failed"
	fetch "$base/SHA256SUMS.sig" "$tmp/SHA256SUMS.sig" || die "download of SHA256SUMS.sig failed"
	if [ -n "${PM_SIGNING_PUBKEY:-}" ]; then
		cp "$PM_SIGNING_PUBKEY" "$tmp/SHA256SUMS.pub" || die "cannot read $PM_SIGNING_PUBKEY"
	else
		tok=${GH_TOKEN:-${GITHUB_TOKEN:-}}
		if [ -n "$tok" ]; then
			curl -fsSL --max-time 60 -H "Accept: application/vnd.github.raw" -H "Authorization: Bearer $tok" -o "$tmp/SHA256SUMS.pub" "$PUB" || die "could not download the signing key"
		else
			curl -fsSL --max-time 60 -H "Accept: application/vnd.github.raw" -o "$tmp/SHA256SUMS.pub" "$PUB" || die "could not download the signing key"
		fi
	fi
	[ -s "$tmp/SHA256SUMS.pub" ] || die "signing key is empty"
	(cd "$tmp" && grep -E "[ *]${run}\$" SHA256SUMS > run.sum) || die "$run is not listed in SHA256SUMS"
	(cd "$tmp" && sha256sum -c run.sum) || die "checksum mismatch for $run; not installing"
	base64 -d < "$tmp/SHA256SUMS.sig" > "$tmp/sig.bin" 2>/dev/null || die "SHA256SUMS.sig is not a signature"
	[ -s "$tmp/sig.bin" ] || die "SHA256SUMS.sig is empty"
	openssl dgst -sha256 -verify "$tmp/SHA256SUMS.pub" -signature "$tmp/sig.bin" "$tmp/SHA256SUMS" >/dev/null \
		|| die "SHA256SUMS signature does not verify; not installing"
	say "SHA256SUMS signature OK"
	say "checksum OK; running: sh $run $*"
	# Leave stdin as the pipe. phantom-mirage-setup reads whichever terminal
	# actually receives keystrokes (sudo's pty is not always that terminal).
	# PM_FROM_GET_MIRAGE tells setup that this command is the user's
	# request to install and start: with no keyboard it starts anyway.
	PM_FROM_GET_MIRAGE=1
	export PM_FROM_GET_MIRAGE
	sh "$tmp/$run" "$@"
}
main "$@"
