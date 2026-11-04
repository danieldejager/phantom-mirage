#!/bin/sh
# Build and install Phantom Mirage from this source checkout.
#
#   ./install-from-source.sh [--yes] [--deb-dir DIR] [--no-setup]
#   ./install-from-source.sh --source-install [--with-python] [--prefix DIR] [--yes]
#
# Default (Debian and Ubuntu): installs the packaging build dependencies
# with apt-get, builds the phantom-mirage and phantom-mirage-common .debs
# from this checkout with dpkg-buildpackage -us -uc -b (in a temporary
# private temporary copy, so the checkout stays clean), installs them
# with apt-get straight from that copy, then copies them to the deb
# directory if that directory is safe (exit 3 if the copy is skipped).
# That gives the same layout as the
# release packages: phantom-mirage-setup, the web console, systemd units
# and /etc/phantom-mirage. It then runs sudo phantom-mirage-setup on this
# terminal (asked first; --yes answers yes), which asks for the sensor
# name and the admin password itself. --no-setup skips that step.
#
# --source-install keeps the plain ./autogen.sh, ./configure, make,
# make install path (binaries and data only, no setup helper or console).
#
# Everything run as root is confirmed first (--yes answers yes). This
# script never asks for, reads or stores the admin password.
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
(dpkg-buildpackage -us -uc -b, in a private temporary copy) and installed
with apt-get from there. This installs phantom-mirage-setup, the web
console, the systemd units and /etc/phantom-mirage. A copy of the .debs
is then kept in the deb directory, and sudo phantom-mirage-setup runs on
this terminal to configure and start the sensor.

It asks before each step that runs as root (with sudo when not root):
  1. apt-get update and apt-get install of missing build dependencies
     (only asked, and only run, when some are missing)
  2. apt-get install of the built .debs (or, with --source-install,
     make install)
  3. sudo phantom-mirage-setup (deb mode only, skipped with --no-setup).
     It asks for the sensor name and console settings, and for the
     admin password at its own hidden prompt. It needs a terminal: with
     --yes and no terminal it is skipped and the command is printed.

Options:
  --yes, -y         answer yes to every question (needed without a terminal)
  --deb-dir DIR     where to keep a copy of the built .debs
                    (default: phantom-mirage-debs next to the checkout).
                    Must not be a symlink, must be owned by you and not
                    writable by group or others; it is created (0755) if
                    missing. If it fails these checks the install still
                    happens, the copy is skipped and the exit code is 3.
  --no-setup        do not run phantom-mirage-setup afterwards (run it
                    yourself later with: sudo phantom-mirage-setup)
  --source-install  instead of .debs, run autogen, configure, make and
                    make install (no phantom-mirage-setup or web console)
  --with-python     with --source-install only: also install python3-dev
                    and configure --with-python
  --prefix DIR      with --source-install only: install under DIR
                    (default: /usr/local)
  --help, -h        show this help

Examples:
  ./install-from-source.sh                 # build, install, then set up; asks first
  ./install-from-source.sh --yes           # same without the questions; setup still
                                           # asks for the sensor name and admin password
  ./install-from-source.sh --yes --no-setup  # build and install only
  sudo phantom-mirage-setup                # run setup later (after --no-setup)
  ./install-from-source.sh --deb-dir ~/debs  # keep the .debs in ~/debs
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

# Asks before anything runs as root; --yes answers yes.
confirm() {
	[ "$yes" = yes ] && return 0
	[ -t 0 ] || die "not a terminal; rerun with --yes to allow: $1"
	printf 'install-from-source.sh: %s? [Y/n] ' "$1"
	read -r ans || ans=n
	case $ans in ''|y|Y|yes|YES) ;; *) die "aborted; nothing more was run" ;; esac
}

# configure only finds PCRE through pcre-config (PCRE 1, libpcre3-dev).
# PCRE2 is not supported, so on releases without libpcre3-dev the build
# continues without the smtp and proxy subsystems. Checked against the
# current package index, before any apt-get update.
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
	say "missing build dependencies:$missing"
	confirm "run apt-get update and apt-get install of these packages as root"
	say "updating the package index"
	$SUDO apt-get update -qq
	# shellcheck disable=SC2086
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $missing
else
	say "all build dependencies already installed; no apt-get update needed"
fi

# Copy the built packages from $work into $1 (see the comment where it is
# called). Returns non zero, with a message, if $1 is unsafe.
keep_debs() {
	d=$1
	if [ ! -e "$d" ] && [ ! -L "$d" ]; then
		mkdir -m 0755 "$d" 2>/dev/null || { say "cannot create $d; not copying the .debs"; return 1; }
	fi
	if [ -L "$d" ]; then say "refusing $d: it is a symlink; not copying the .debs"; return 1; fi
	if [ ! -d "$d" ]; then say "refusing $d: not a directory; not copying the .debs"; return 1; fi
	owner=$(stat -c %u "$d") || return 1
	if [ "$owner" != "$(id -u)" ]; then
		say "refusing $d: owned by uid $owner, not by you (uid $(id -u)); not copying the .debs"; return 1
	fi
	if [ -n "$(find "$d" -maxdepth 0 -perm /022)" ]; then
		say "refusing $d: writable by group or others; not copying the .debs"; return 1
	fi
	for f in "$work"/*.deb "$work"/*.ddeb "$work"/*.buildinfo "$work"/*.changes; do
		[ -f "$f" ] && [ ! -L "$f" ] || continue
		tmpf=$(mktemp "$d/.pm-copy.XXXXXX") || { say "cannot write in $d; not copying the .debs"; return 1; }
		cp "$f" "$tmpf" && chmod 0644 "$tmpf" && mv -fT "$tmpf" "$d/${f##*/}" ||
			{ rm -f "$tmpf"; say "copying ${f##*/} to $d failed"; return 1; }
	done
}

# Build
if [ "$mode" = deb ]; then
	ver=$(dpkg-parsechangelog -S Version 2>/dev/null) || die "cannot read the version from debian/changelog"
	[ -n "$deb_dir" ] || deb_dir=$(dirname "$src")/phantom-mirage-debs
	case "$deb_dir" in /*) ;; *) deb_dir=$(pwd)/$deb_dir ;; esac
	case "$deb_dir/" in "$src/"*) die "--deb-dir must be outside the source checkout" ;; esac

	# dpkg-buildpackage writes into debian/ and the parent directory, so
	# build in a private temporary copy (mktemp -d, mode 0700, without
	# .git) and keep the checkout clean. The .debs are installed straight
	# from there; the deb directory only gets a copy afterwards.
	work=$(mktemp -d "${TMPDIR:-/tmp}/phantom-mirage-build.XXXXXX")
	trap 'rm -rf "$work"' EXIT
	chmod 0700 "$work"
	say "copying the checkout to $work/phantom-mirage"
	mkdir "$work/phantom-mirage"
	tar -C "$src" --exclude=./.git -cf "$work/src.tar" . || die "cannot archive the checkout"
	tar -C "$work/phantom-mirage" -xf "$work/src.tar" || die "cannot unpack the checkout copy"
	rm -f "$work/src.tar"
	jobs=$(nproc 2>/dev/null || echo 1)
	say "running dpkg-buildpackage -us -uc -b (version $ver)"
	(cd "$work/phantom-mirage" && DEB_BUILD_OPTIONS="parallel=$jobs ${DEB_BUILD_OPTIONS:-}" dpkg-buildpackage -us -uc -b)

	arch=$(dpkg --print-architecture)
	bin="phantom-mirage_${ver}_${arch}.deb"
	common="phantom-mirage-common_${ver}_all.deb"
	[ -f "$work/$bin" ] && [ ! -L "$work/$bin" ] && [ -f "$work/$common" ] && [ ! -L "$work/$common" ] ||
		die "dpkg-buildpackage did not produce $bin and $common"

	if [ -x /usr/local/bin/phantom-mirage ] || [ -x /usr/local/sbin/phantom-mirage ]; then
		say "warning: an earlier --source-install is in /usr/local and comes first in PATH;"
		say "warning: remove it (sudo make uninstall in the checkout) to use the packaged binaries"
	fi
	confirm "install $bin and $common with apt-get as root"
	say "installing $bin and $common with apt-get from $work"
	$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall \
		"$work/$bin" "$work/$common"

	say "installed phantom-mirage $ver from the built packages"

	# Keep a copy of the .debs. Only into a directory that is ours: not a
	# symlink, owned by this user and not writable by group or others
	# (created here with mode 0755 if missing). Each file goes to a fresh
	# mktemp name in that directory and is renamed into place, so no
	# planted symlink is followed. If the directory fails the checks the
	# install above stands, the copy is skipped and the exit code is 3.
	if keep_debs "$deb_dir"; then
		say "packages are in $deb_dir:"
		(cd "$deb_dir" && ls -1 ./*"_${ver}_"*.deb) | sed 's|^\./|  |'
		rc=0
	else
		say "the install succeeded, but the .debs were NOT copied to $deb_dir (see above)"
		say "rerun with --deb-dir pointing at a directory you own, or omit it"
		rc=3
	fi

	# Run phantom-mirage-setup on this terminal. It prompts for the sensor
	# name and, at a hidden prompt, the admin password; nothing is passed
	# to it or read from it here. Without a terminal it cannot ask for the
	# password, so it is skipped and the exact command is printed.
	setup_cmd="${SUDO:+sudo }phantom-mirage-setup"
	if [ "$setup" = no ]; then
		say "skipped phantom-mirage-setup (--no-setup); next step: $setup_cmd"
		exit $rc
	fi
	if [ ! -t 0 ]; then
		say "not running phantom-mirage-setup: no terminal for its sensor name and admin password prompts"
		say "next step, on a terminal: $setup_cmd"
		exit $rc
	fi
	if [ "$yes" != yes ]; then
		printf 'install-from-source.sh: run %s now to configure and start the sensor? [Y/n] ' "$setup_cmd"
		read -r ans || ans=n
		case $ans in ''|y|Y|yes|YES) ;; *)
			say "not running phantom-mirage-setup; next step: $setup_cmd"
			exit $rc ;;
		esac
	fi
	say "running $setup_cmd (existing console config is kept)"
	src_rc=0
	$SUDO /usr/sbin/phantom-mirage-setup || src_rc=$?
	if [ $src_rc != 0 ]; then
		say "phantom-mirage-setup failed (exit $src_rc); the packages are installed"
		say "fix the problem shown above, then run: $setup_cmd"
		exit $src_rc
	fi
	exit $rc
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

confirm "run make install into $prefix as root"
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
