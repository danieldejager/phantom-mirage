#!/bin/sh
# Build and install Phantom Mirage from this source checkout.
#
#   ./install.sh [--with-python] [--prefix DIR] [--yes] [--no-setup]
#
# Installs the build dependencies with apt-get (Debian and Ubuntu), then
# runs ./autogen.sh, ./configure, make and make install. Safe to run
# again: packages already present are skipped and the build is redone in
# place. It never touches /etc/phantom-mirage or the web console's
# config, admin account, certificate or alerts.
#
# To install the release .debs instead (web console, systemd units and
# phantom-mirage-setup included) use release/get-mirage.sh.
set -eu

say() { echo "install.sh: $*"; }
die() { echo "install.sh: error: $*" >&2; exit 1; }

usage() {
	cat <<'USAGE'
Usage: ./install.sh [options]

Build Phantom Mirage from this checkout and install it.

Options:
  --with-python   build embedded Python 3 support (also installs python3-dev)
  --prefix DIR    install under DIR (default: /usr/local)
  --yes, -y       do not ask before installing packages
  --no-setup      do not print the phantom-mirage-setup next step
  --help, -h      show this help

Supported: Debian and Ubuntu (apt-get). The script asks for sudo when it
is not run as root. It never asks for or accepts the console admin
password; phantom-mirage-setup asks for it at a hidden prompt.
USAGE
}

with_python=no
prefix=/usr/local
yes=no
setup=yes
while [ $# -gt 0 ]; do
	case $1 in
	--with-python) with_python=yes ;;
	--prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; prefix=$2; shift ;;
	--prefix=*) prefix=${1#--prefix=} ;;
	--yes|-y) yes=yes ;;
	--no-setup) setup=no ;;
	--help|-h) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
	shift
done
[ -n "$prefix" ] || die "--prefix needs a directory"

cd "$(dirname "$0")"
[ -f configure.ac ] && [ -x autogen.sh ] || die "run this from the phantom-mirage source checkout"

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
pkgs="build-essential autoconf automake libtool bison flex pkg-config
libevent-dev libdumbnet-dev libpcap-dev libedit-dev zlib1g-dev"
[ "$with_python" = yes ] && pkgs="$pkgs python3-dev"

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
if available libpcre3-dev; then
	pkgs="$pkgs libpcre3-dev"
else
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
			printf 'install.sh: install them now? [Y/n] '
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
		say "for them, install the release .debs (release/get-mirage.sh), then run: sudo phantom-mirage-setup"
	fi
fi
