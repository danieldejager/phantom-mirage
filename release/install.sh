#!/bin/sh
# Install Phantom Mirage from a folder holding the release .debs (#110).
# Lives in release/ (automake rejects a top-level install.sh); attach it
# to the release as install.sh next to the .debs and SHA256SUMS.
#
#   sudo sh install.sh [phantom-mirage-setup options, e.g. --network CIDR]
#   sudo sh install.sh --yes -i IF -n CIDR   (unattended: --yes lets setup
#                                           start services without a terminal)
#
# Verifies SHA256SUMS, picks the .debs for this distro (ubuntu26.04 or
# debian13) and architecture (dpkg --print-architecture),
# purges any installed Phantom Mirage or honeyd first via
# phantom-mirage-uninstall
# (keeping /etc/default/phantom-mirage, the web console's admin account,
# certificate, settings and alerts, and the JSON event log, which are
# stashed in /var/backups/phantom-mirage.keep and put back afterwards),
# installs farpd from the archive if missing, installs non-interactively
# and runs phantom-mirage-setup (which points farpd at the decoys).
# If any step after the backup fails, the previous packages, config and
# data are restored automatically and the backup location and manual
# restore commands are printed (#121).
set -eu
cd "$(dirname "$0")"
die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }

[ "$(id -u)" = 0 ] || [ -n "${PM_TEST_ROOT:-}" ] || die "run as root: sudo sh install.sh"
[ -r SHA256SUMS ] || die "SHA256SUMS not found next to install.sh"

arch=$(dpkg --print-architecture)
. "${PM_TEST_ROOT:-}/etc/os-release"
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
# Optional signature over SHA256SUMS (#121): with SHA256SUMS.pub (cosign
# public key) next to this file, SHA256SUMS.sig must verify. Inside a .run
# the payload was already checked against the release's SHA256SUMS (and
# its signature) by get-mirage.sh, so stay quiet there.
if [ -r SHA256SUMS.pub ]; then
	[ -r SHA256SUMS.sig ] || die "SHA256SUMS.pub is here but SHA256SUMS.sig is missing; refusing an unsigned release"
	command -v cosign >/dev/null 2>&1 || die "cosign is needed to verify SHA256SUMS.sig (https://docs.sigstore.dev/cosign/system_config/installation/)"
	cosign verify-blob --key SHA256SUMS.pub --signature SHA256SUMS.sig --insecure-ignore-tlog=true SHA256SUMS >/dev/null 2>&1 || die "SHA256SUMS signature does not verify; not installing"
	say "SHA256SUMS signature OK"
elif [ -z "${PM_FROM_RUN:-}" ]; then
	say "warning: SHA256SUMS is unsigned (no SHA256SUMS.pub here); the checksums prove integrity, not who made the release"
fi

# Rollback (#121): before anything is removed, the previous install is
# saved under $KEEP: its .debs (dpkg-repack, the apt cache or apt-get
# download, whichever works), a tar of its config, state and logs, and
# the pieces carried over to the new version. If any later step fails
# (uninstall, apt-get install, phantom-mirage-setup) the EXIT trap purges
# the half-installed new version, reinstalls the saved .debs and unpacks
# the saved files. The backup is removed only after a successful install.
# PM_TEST_ROOT prefixes file paths for ci/test_install_rollback.sh only.
R=${PM_TEST_ROOT:-}
KEEP=$R/var/backups/phantom-mirage.keep
STATE_PATHS="etc/default/phantom-mirage etc/init.d/phantom-mirage etc/phantom-mirage var/lib/phantom-mirage var/log/phantom-mirage"
old=$(dpkg-query -W -f='${Package}\t${Version}\t${db:Status-Abbrev}\n' phantom-mirage phantom-mirage-common honeyd honeyd-common 2>/dev/null | awk -F'\t' '$3 != "" && $3 !~ /^(un|pn)/ {print $1"="$2}' | tr '\n' ' ' || true)
mkdir -p "$KEEP"
chmod 0700 "$KEEP"
rm -rf "$KEEP/debs" "$KEEP/state.tar"
mkdir -p "$KEEP/debs"
debs_missing=
if [ -n "$old" ] && ! command -v dpkg-repack >/dev/null 2>&1; then
	say "installing dpkg-repack (rebuilds the installed .debs for rollback)"
	DEBIAN_FRONTEND=noninteractive apt-get install -y dpkg-repack </dev/null >/dev/null 2>&1 || {
		apt-get update </dev/null >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y dpkg-repack </dev/null >/dev/null 2>&1
	} || say "warning: could not install dpkg-repack (no mirror?); trying the apt cache instead"
fi
for pv in $old; do
	p=${pv%%=*} v=${pv#*=} vf=$(echo "${pv#*=}" | sed 's/:/%3a/')
	if command -v dpkg-repack >/dev/null 2>&1 && (cd "$KEEP/debs" && dpkg-repack "$p" >/dev/null 2>&1); then :
	elif f=$(ls -1 "$R/var/cache/apt/archives/${p}_${vf}_"*.deb 2>/dev/null | head -n 1) && [ -n "$f" ]; then cp -a "$f" "$KEEP/debs/"
	elif (cd "$KEEP/debs" && apt-get download "$p=$v" </dev/null >/dev/null 2>&1); then :
	else debs_missing="$debs_missing $pv"
	fi
done
present=
for d in $STATE_PATHS; do [ -e "$R/$d" ] && present="$present $d"; done
# shellcheck disable=SC2086
[ -z "$present" ] || tar -C "$R/" -cpf "$KEEP/state.tar" $present
[ -e "$R/etc/default/phantom-mirage" ] && cp -a "$R/etc/default/phantom-mirage" "$KEEP/default"
[ -d "$R/var/lib/phantom-mirage/console" ] && { rm -rf "$KEEP/console"; cp -a "$R/var/lib/phantom-mirage/console" "$KEEP/console"; }
[ -e "$R/var/log/phantom-mirage/events.jsonl" ] && cp -a "$R/var/log/phantom-mirage/events.jsonl" "$KEEP/events.jsonl"
if [ -n "$old$present" ]; then
	say "backup of the current install: $KEEP (debs/, state.tar)"
	[ -z "$debs_missing" ] || say "warning: could not save the .debs of:$debs_missing (rollback would restore config and data only)"
fi

restore_hint() {
	echo "install.sh: backup kept in $KEEP; to restore by hand:" >&2
	echo "install.sh:   sudo apt-get install -y $KEEP/debs/*.deb   # previous packages ($old)" >&2
	echo "install.sh:   sudo tar -C $R/ -xpf $KEEP/state.tar          # previous config, state and logs" >&2
	[ -z "$debs_missing" ] || echo "install.sh:   (no saved .deb for$debs_missing: reinstall it with get-mirage.sh --tag <old tag>)" >&2
}
rollback() {
	rc=$?
	trap - EXIT
	[ "$rc" != 0 ] || exit 0
	set +e
	echo "install.sh: install failed (exit $rc); rolling back to the previous version" >&2
	if [ -z "$old$present" ]; then
		echo "install.sh: there was no previous install to restore" >&2
		exit "$rc"
	fi
	DEBIAN_FRONTEND=noninteractive dpkg --purge --force-all phantom-mirage phantom-mirage-common </dev/null >/dev/null 2>&1
	ok=1
	if ls "$KEEP"/debs/*.deb >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "$KEEP"/debs/*.deb </dev/null || ok=
	fi
	if [ -e "$KEEP/state.tar" ]; then tar -C "$R/" -xpf "$KEEP/state.tar" || ok=; fi
	if [ -n "$ok" ] && [ -z "$debs_missing" ]; then
		echo "install.sh: rolled back to the previous install ($old)" >&2
	else
		echo "install.sh: rollback incomplete" >&2
	fi
	restore_hint
	exit "$rc"
}
trap rollback EXIT
trap 'exit 130' INT TERM HUP

# Remove ANY existing install first (phantom-mirage*, old honeyd*, leftover
# conffiles such as /etc/init.d/phantom-mirage, config, state, logs, farpd
# config written by setup) with the uninstall script shipped next to this
# file, so a half-configured older release never leaks into the new one.
if [ -r ./phantom-mirage-uninstall ]; then PM_KEEP_BACKUP=1 sh ./phantom-mirage-uninstall --yes </dev/null
elif [ -x "$R/usr/sbin/phantom-mirage-uninstall" ]; then PM_KEEP_BACKUP=1 "$R/usr/sbin/phantom-mirage-uninstall" --yes </dev/null
else die "phantom-mirage-uninstall not found next to install.sh"
fi
left=
for p in phantom-mirage phantom-mirage-common honeyd honeyd-common; do
	st=$(dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null || true)
	case $st in ''|un*|pn*) ;; *) left="$left package:$p($st)" ;; esac
done
for d in $STATE_PATHS; do
	[ -e "$R/$d" ] && left="$left /$d"
done
[ -z "$left" ] || die "old install not fully removed:$left"
if [ -n "$old" ]; then say "old version removed cleanly: $old"
else say "no previous install found (clean)"; fi

if ! dpkg-query -W -f='${db:Status-Abbrev}' farpd 2>/dev/null | grep -q '^ii'; then
	say "installing farpd from the archive (answers ARP for the decoys)"
	DEBIAN_FRONTEND=noninteractive apt-get install -y farpd </dev/null || {
		apt-get update </dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y farpd </dev/null
	} || say "warning: could not install farpd; decoys will not answer ARP (phantom-mirage-setup will say so)"
fi

say "installing"
DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confnew "./$main" "./$common" </dev/null
if [ -e "$KEEP/default" ]; then
	cp -a "$KEEP/default" "$R/etc/default/phantom-mirage"
	say "kept /etc/default/phantom-mirage"
fi
if [ -d "$KEEP/console" ]; then
	mkdir -p "$R/var/lib/phantom-mirage/console"
	cp -a "$KEEP/console/." "$R/var/lib/phantom-mirage/console/"
	chown -R phantom-mirage-console:phantom-mirage-console "$R/var/lib/phantom-mirage/console"
	chown root:phantom-mirage-console "$R/var/lib/phantom-mirage/console"
	chmod 0770 "$R/var/lib/phantom-mirage/console"
	say "kept the web console admin account, certificate, settings and alerts"
fi
if [ -e "$KEEP/events.jsonl" ]; then
	mkdir -p "$R/var/log/phantom-mirage"
	cp -a "$KEEP/events.jsonl" "$R/var/log/phantom-mirage/events.jsonl"
	chown phantom-mirage:phantom-mirage-console "$R/var/log/phantom-mirage/events.jsonl" 2>/dev/null || true
	chmod 0640 "$R/var/log/phantom-mirage/events.jsonl"
fi
say "configuring"
"$R/usr/sbin/phantom-mirage-setup" "$@"
trap - EXIT
rm -rf "$KEEP"
say "done; removed the backup $KEEP"
