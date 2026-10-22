#!/bin/sh
# Install Phantom Mirage from a folder holding the release .debs (#110).
# Lives in release/ (automake rejects a top-level install.sh); attach it
# to the release as install.sh next to the .debs and SHA256SUMS.
#
#   sudo sh install.sh [phantom-mirage-setup options, e.g. --network CIDR]
#
# Verifies SHA256SUMS, picks the .debs for this distro (ubuntu26.04 or
# debian13) and architecture (dpkg --print-architecture), purges any
# installed Phantom Mirage or honeyd first via phantom-mirage-uninstall
# (config included: meant for test boxes),
# installs farpd from the archive if missing, installs non-interactively
# and runs phantom-mirage-setup (which points farpd at the decoys).
set -eu
cd "$(dirname "$0")"
die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

[ "$(id -u)" = 0 ] || die "run as root: sudo sh install.sh"
[ -r SHA256SUMS ] || die "SHA256SUMS not found next to install.sh"

arch=$(dpkg --print-architecture)
. /etc/os-release
distro=$ID$VERSION_ID
case $distro in ubuntu26.04|debian13) ;; *) say "warning: $PRETTY_NAME is not a tested distro (ubuntu26.04, debian13)" ;; esac

pick() {	# pick NAME ARCH: newest matching .deb, distro-tagged names first
	f=$(ls -1 2>/dev/null | grep -E "^$1_[^_]+_${distro}_$2\.deb\$" | sort -V | tail -n 1)
	[ -n "$f" ] || f=$(ls -1 2>/dev/null | grep -E "^$1_[^_]+_$2\.deb\$" | sort -V | tail -n 1)
	[ -n "$f" ] && echo "$f"
}
main=$(pick phantom-mirage "$arch") || die "no phantom-mirage .deb for $distro/$arch here: $(ls -1 *.deb 2>/dev/null | tr '\n' ' ')"
common=$(pick phantom-mirage-common all) || die "no phantom-mirage-common .deb for $distro here"
say "this is $distro/$arch: $main $common"

for f in "$main" "$common"; do
	grep -q "[ *]$f\$" SHA256SUMS || die "$f is not listed in SHA256SUMS"
done
grep -E "[ *](${main}|${common})\$" SHA256SUMS | sha256sum -c - || die "checksum mismatch; download the files again"

# Remove ANY existing install first (phantom-mirage*, old honeyd*, leftover
# conffiles such as /etc/init.d/phantom-mirage, config, state, logs, farpd
# config written by setup) with the uninstall script shipped next to this
# file, so a half-configured older release never leaks into the new one.
old=$(dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' phantom-mirage phantom-mirage-common honeyd honeyd-common 2>/dev/null | awk -F'\t' '$3 != "" && $3 !~ /^(un|pn)/ {print $1"="$2}' | tr '\n' ' ' || true)
if [ -r ./phantom-mirage-uninstall ]; then sh ./phantom-mirage-uninstall --yes
elif [ -x /usr/sbin/phantom-mirage-uninstall ]; then /usr/sbin/phantom-mirage-uninstall --yes
else die "phantom-mirage-uninstall not found next to install.sh"
fi
left=
for p in phantom-mirage phantom-mirage-common honeyd honeyd-common; do
	st=$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null || true)
	case $st in ''|un*|pn*) ;; *) left="$left package:$p($st)" ;; esac
done
for d in /etc/init.d/phantom-mirage /etc/default/phantom-mirage /etc/phantom-mirage /var/lib/phantom-mirage /var/log/phantom-mirage; do
	[ -e "$d" ] && left="$left $d"
done
[ -z "$left" ] || die "old install not fully removed:$left"
if [ -n "$old" ]; then say "old version removed cleanly: $old"
else say "no previous install found (clean)"; fi

if ! dpkg-query -W -f='${db:Status-Abbrev}' farpd 2>/dev/null | grep -q '^ii'; then
	say "installing farpd from the archive (answers ARP for the decoys)"
	DEBIAN_FRONTEND=noninteractive apt-get install -y farpd || {
		apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y farpd
	} || say "warning: could not install farpd; decoys will not answer ARP (phantom-mirage-setup will say so)"
fi

say "installing"
DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confnew "./$main" "./$common"
say "configuring"
exec /usr/sbin/phantom-mirage-setup "$@"
