#!/bin/sh
# Build and install Phantom Mirage from this source checkout.
#
#   ./install-from-source.sh [--yes] [--deb-dir DIR] [--no-setup]
#   ./install-from-source.sh --source-install [--with-python] [--prefix DIR] [--yes]
#
# Default (Debian and Ubuntu): installs the packaging build dependencies
# with apt-get, builds the phantom-mirage and phantom-mirage-common .debs
# from this checkout with dpkg-buildpackage -us -uc -b (in a temporary
# copy, so the checkout stays clean), copies them to the deb directory
# and installs them with apt-get. That gives the same layout as the
# release packages: phantom-mirage-setup, the web console, systemd units
# and /etc/phantom-mirage. Nothing is enabled or started and no admin
# password is set; run sudo phantom-mirage-setup afterwards.
#
# --source-install keeps the plain ./autogen.sh, ./configure, make,
# make install path (binaries and data only, no setup helper or console).
#
# Safe to run again. It never touches existing /etc/phantom-mirage config
# or the web console's config, admin account, certificate or alerts
# (package conffiles are kept by dpkg).
#
# Not called install.sh: automake 1.17 rejects a top-level install.sh.
set -eu

say() { echo "install-from-source.sh: $*"; }
die() { echo "install-from-source.sh: error: $*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
Usage: ./install-from-source.sh [options]

Build Phantom Mirage from this checkout and install it.

By default the Debian packages are built from the checkout
(dpkg-buildpackage -us -uc -b) and installed with apt-get. This installs
phantom-mirage-setup, the web console, the systemd units and
/etc/phantom-mirage, but enables and starts nothing.

Options:
  --yes, -y         do not ask before installing packages
  --deb-dir DIR     where to put the built .debs
                    (default: phantom-mirage-debs next to the checkout)
  --no-setup        do not print the phantom-mirage-setup next step
  --source-install  instead of .debs, run autogen, configure, make and
                    make install (no phantom-mirage-setup or web console)
  --with-python     with --source-install only: also install python3-dev
                    and configure --with-python
  --prefix DIR      with --source-install only: install under DIR
                    (default: /usr/local)
  --help, -h        show this help

Examples:
  ./install-from-source.sh                 # build and install the .debs, asks first
  ./install-from-source.sh --yes           # same, non-interactive
  sudo phantom-mirage-setup                # then: admin password at a hidden prompt
  ./install-from-source.sh --source-install --prefix /opt/phantom-mirage

Supported: Debian and Ubuntu (apt-get). The script uses sudo when it is
not run as root. It never asks for or accepts the console admin
password; phantom-mirage-setup asks for it at a hidden prompt.
USAGE
}

mode=deb
with_python=no
prefix=
deb_dir=
yes=no
setup=yes
while [ $# -gt 0 ]; do
	case $1 in
	--source-install) mode=source ;;
	--with-python) with_python=yes ;;
	--prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; prefix=$2; [ -n "$prefix" ] || die "--prefix needs a directory"; shift ;;
	--prefix=*) prefix=${1#--prefix=}; [ -n "$prefix" ] || die "--prefix needs a directory" ;;
	--deb-dir) [ $# -ge 2 ] || die "--deb-dir needs a directory"; deb_dir=$2; [ -n "$deb_dir" ] || die "--deb-dir needs a directory"; shift ;;
	--deb-dir=*) deb_dir=${1#--deb-dir=}; [ -n "$deb_dir" ] || die "--deb-dir needs a directory" ;;
	--yes|-y) yes=yes ;;
	--no-setup) setup=no ;;
	--help|-h) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
	shift
done
if [ "$mode" = deb ]; then
	[ "$with_python" = no ] || die "--with-python only applies with --source-install (the .debs are built without Python)"
	[ -z "$prefix" ] || die "--prefix only applies with --source-install (the .debs install under /usr)"
else
	[ -z "$deb_dir" ] || die "--deb-dir does not apply with --source-install"
	[ -n "$prefix" ] || prefix=/usr/local
fi

cd "$(dirname "$0")"
[ -f configure.ac ] && [ -x autogen.sh ] || die "run this from the phantom-mirage source checkout"
[ "$mode" = source ] || [ -f debian/control ] || die "debian/control not found; use --source-install"
src=$(pwd)

if [ "$(id -u)" = 0 ]; then
	SUDO=
else
	command -v sudo >/dev/null 2>&1 || die "not root and sudo is not installed; run as root"
	SUDO=sudo
fi

# Distro check
osr=${PM_OS_RELEASE:-/etc/os-release}
[ -r "$osr" ] || die "cannot read $osr; unsupported system"
ID='' ID_LIKE='' PRETTY_NAME=''
# shellcheck disable=SC1090
. "$osr"
case " $ID $ID_LIKE " in
*" debian "*|*" ubuntu "*) ;;
*) die "unsupported distro: ${PRETTY_NAME:-$ID}. Only Debian and Ubuntu (apt-get) are supported; see README.md for the dependency list." ;;
esac
command -v apt-get >/dev/null 2>&1 || die "apt-get not found on ${PRETTY_NAME:-$ID}"
say "detected ${PRETTY_NAME:-$ID}"

# Dependencies
if [ "$mode" = deb ]; then
	# Build-Depends from debian/control (version constraints dropped,
	# debhelper-compat is provided by debhelper) plus the packaging tools.
	bdeps=$(sed -n '/^Build-Depends:/,/^[^ ]/{s/^Build-Depends://;/^[^ ]/!p;}' debian/control |
		tr ',' '\n' | sed 's/([^)]*)//g; s/\[[^]]*\]//g; s/|.*//; s/^[[:space:]]*//; s/[[:space:]]*$//' |
		sed 's/^debhelper-compat$/debhelper/' | grep -v '^$' | sort -u | tr '\n' ' ')
	[ -n "$bdeps" ] || die "could not read Build-Depends from debian/control"
	pkgs=$(printf '%s\n' build-essential dpkg-dev devscripts debhelper dh-apparmor sharutils $bdeps |
		awk '!seen[$0]++' | tr '\n' ' ')
else
	pkgs="build-essential autoconf automake libtool bison flex pkg-config
libevent-dev libdumbnet-dev libpcap-dev libedit-dev zlib1g-dev"
	[ "$with_python" = yes ] && pkgs="$pkgs python3-dev"
fi

have_pkg() {
	dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}
available() {
	cand=$(apt-cache policy "$1" 2>/dev/null | sed -n 's/^ *Candidate: *//p')
	[ -n "$cand" ] && [ "$cand" != "(none)" ]
}

say "updating the package index"
$SUDO apt-get update -qq

# configure only finds PCRE through pcre-config (PCRE 1, libpcre3-dev).
# PCRE2 is not supported, so on releases without libpcre3-dev the build
# continues without the smtp and proxy subsystems.
if [ "$mode" = source ] && available libpcre3-dev; then
	pkgs="$pkgs libpcre3-dev"
elif [ "$mode" = source ]; then
	say "note: libpcre3-dev is not available here; building without PCRE (no smtp/proxy subsystems)"
fi

missing=
for p in $pkgs; do
	have_pkg "$p" || missing="$missing $p"
done
if [ -n "$missing" ]; then
	say "packages to install:$missing"
	if [ "$yes" != yes ]; then
		if [ -t 0 ]; then
			printf 'install-from-source.sh: install them now? [Y/n] '
			read -r ans || ans=n
			case $ans in ''|y|Y|yes|YES) ;; *) die "aborted; nothing installed" ;; esac
		else
			die "not a terminal; rerun with --yes to install packages"
		fi
	fi
	# shellcheck disable=SC2086
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing
else
	say "all build dependencies already installed"
fi

# Build
if [ "$mode" = deb ]; then
	ver=$(dpkg-parsechangelog -S Version 2>/dev/null) || die "cannot read the version from debian/changelog"
	[ -n "$deb_dir" ] || deb_dir=$(dirname "$src")/phantom-mirage-debs
	mkdir -p "$deb_dir" || die "cannot create $deb_dir"
	deb_dir=$(cd "$deb_dir" && pwd)
	case "$deb_dir/" in "$src/"*) die "--deb-dir must be outside the source checkout" ;; esac

	# dpkg-buildpackage writes into debian/ and the parent directory, so
	# build in a temporary copy (without .git) and keep the checkout clean.
	work=$(mktemp -d "${TMPDIR:-/tmp}/phantom-mirage-build.XXXXXX")
	trap 'rm -rf "$work"' EXIT
	say "copying the checkout to $work/phantom-mirage"
	mkdir "$work/phantom-mirage"
	tar -C "$src" --exclude=./.git -cf - . | tar -C "$work/phantom-mirage" -xf -
	jobs=$(nproc 2>/dev/null || echo 1)
	say "running dpkg-buildpackage -us -uc -b (version $ver)"
	(cd "$work/phantom-mirage" && DEB_BUILD_OPTIONS="parallel=$jobs ${DEB_BUILD_OPTIONS:-}" dpkg-buildpackage -us -uc -b)

	arch=$(dpkg --print-architecture)
	bin="phantom-mirage_${ver}_${arch}.deb"
	common="phantom-mirage-common_${ver}_all.deb"
	[ -f "$work/$bin" ] && [ -f "$work/$common" ] || die "dpkg-buildpackage did not produce $bin and $common"
	for f in "$work"/*.deb "$work"/*.ddeb "$work"/*.buildinfo "$work"/*.changes; do
		if [ -f "$f" ]; then cp "$f" "$deb_dir/"; fi
	done
	say "packages are in $deb_dir:"
	(cd "$deb_dir" && ls -1 ./*"_${ver}_"*.deb) | sed 's|^\./|  |'

	if [ -x /usr/local/bin/phantom-mirage ] || [ -x /usr/local/sbin/phantom-mirage ]; then
		say "warning: an earlier --source-install is in /usr/local and comes first in PATH;"
		say "warning: remove it (sudo make uninstall in the checkout) to use the packaged binaries"
	fi
	say "installing $bin and $common with apt-get"
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall \
		"$deb_dir/$bin" "$deb_dir/$common"

	say "installed phantom-mirage $ver from the built packages (nothing enabled or started)"
	if [ "$setup" = yes ]; then
		say "next step: sudo phantom-mirage-setup"
		say "it asks for the admin password at a hidden prompt; existing console config is kept"
	fi
	exit 0
fi

say "running ./autogen.sh"
./autogen.sh
cfg="--prefix=$prefix"
[ "$with_python" = yes ] && cfg="$cfg --with-python"
say "running ./configure $cfg"
# shellcheck disable=SC2086
./configure $cfg
jobs=$(nproc 2>/dev/null || echo 1)
say "running make -j$jobs"
make -j"$jobs"

say "running make install"
$SUDO make install

say "installed into $prefix"
if [ "$setup" = yes ]; then
	if command -v phantom-mirage-setup >/dev/null 2>&1; then
		say "next step: sudo phantom-mirage-setup"
		say "it asks for the admin password at a hidden prompt; existing console config is kept"
	else
		say "phantom-mirage-setup and the web console ship in the Debian packages only."
		say "for them, rerun without --source-install (builds and installs the .debs), then run: sudo phantom-mirage-setup"
	fi
fi
