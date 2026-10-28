#!/bin/bash
# debian/scripts/pm-start: exact argv from /etc/default/phantom-mirage (#110)
set -euo pipefail
cd "$(dirname "$0")/.."
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir "$t/net"; touch "$t/net/eth0"

# pm MODE FILE: run pm-start in a clean environment, argv on stdout
pm() {
  env -i PATH=/usr/bin:/bin PM_LIBDIR="$PWD/debian/scripts" PM_SYSFS_NET="$t/net" \
    PM_DEFAULT="$2" PM_UID=999 PM_GID=998 PM_PRINT_ARGV=1 ${SH:-/bin/sh} debian/scripts/pm-start "$1"
}
same() {	# same NAME EXPECTED ACTUAL
  if [ "$2" != "$3" ]; then
    echo "FAIL: $1"; diff <(echo "$2") <(echo "$3") || true; exit 1
  fi
  echo "ok: $1"
}
fails() {	# fails NAME PATTERN FILE: check exits 78 with PATTERN on stderr
  local rc=0; pm check "$3" 2>"$t/err" >/dev/null || rc=$?
  if [ $rc != 78 ] || ! grep -q -- "$2" "$t/err"; then
    echo "FAIL: $1 (rc=$rc)"; cat "$t/err"; exit 1
  fi
  echo "ok: $1 -> $(cat "$t/err")"
}

# 1. shipped default: refused, nothing started
fails "shipped default" '^phantom-mirage: INTERFACE is not set in ' debian/phantom-mirage.default

# 2. user-edited with the sed commands from the 26.04 live test
sed -e 's/^INTERFACE=.*/INTERFACE="eth0"/' -e 's|^NETWORK=.*|NETWORK=10.211.55.200/29|' \
  debian/phantom-mirage.default > "$t/edited"
pm check "$t/edited"
same "verify argv (sed-edited)" "/usr/bin/phantom-mirage
--verify-config
-f
/etc/phantom-mirage/phantom-mirage.conf
-i
eth0
--disable-webserver
10.211.55.200/29" "$(pm verify "$t/edited")"
same "run argv (sed-edited)" "/usr/bin/phantom-mirage
-d
-f
/etc/phantom-mirage/phantom-mirage.conf
-l
/var/log/phantom-mirage/phantom-mirage.log
-p
/etc/phantom-mirage/columbo-v1.db
-a
/etc/phantom-mirage/nmap.assoc
-0
/etc/phantom-mirage/pf.os
-x
/etc/phantom-mirage/xprobe2.conf
-m
/etc/phantom-mirage/nmap-mac-prefixes
-u
999
-g
998
-i
eth0
--sandbox-daemon
--sandbox-scripts
--disable-webserver
10.211.55.200/29" "$(pm run "$t/edited")"

# 3. SANDBOX and multi-word OPTIONS/NETWORK from the file, no globbing
printf '%s\n' 'INTERFACE=eth0' 'NETWORK="10.1.1.8/29 10.1.1.16/29"' "OPTIONS='--disable-webserver -V'" 'SANDBOX=""' '#OPTIONS=*' > "$t/multi"
same "verify argv (multi-word)" "/usr/bin/phantom-mirage
--verify-config
-f
/etc/phantom-mirage/phantom-mirage.conf
-i
eth0
--disable-webserver
-V
10.1.1.8/29
10.1.1.16/29" "$(pm verify "$t/multi")"
[ "$(pm run "$t/multi" | grep -c sandbox)" = 0 ]; echo "ok: SANDBOX=\"\" turns the sandbox off"

# 4. the 26.04 bug: a stray quote must not swallow the comments below it
sed -e 's/^INTERFACE=.*/INTERFACE="eth0"/' -e 's|^NETWORK=.*|NETWORK="10.211.55.200/29|' \
  debian/phantom-mirage.default > "$t/stray"
fails "unterminated quote on NETWORK" 'line [0-9]*: unbalanced or stray quote in NETWORK="10.211.55.200/29' "$t/stray"
printf '%s\n' 'INTERFACE=eth0' 'NETWORK=10.1.1.8/29 # decoys' > "$t/inline"
fails "inline comment" 'comment after the value' "$t/inline"
printf '%s\n' 'INTERFACE=eth0' 'NETWORK=$(reboot)' > "$t/subst"
fails "command substitution" 'are not supported' "$t/subst"
printf '%s\n' 'INTERFACE=eth0' 'NETWORK=10.1.1.8/29' 'some text' > "$t/junk"
fails "stray text line" 'line 3: expected KEY=VALUE' "$t/junk"
printf 'INTERFACE=eth0\r\nNETWORK="10.1.1.8/29"\r\n' > "$t/crlf"
same "CRLF file" "10.1.1.8/29" "$(pm verify "$t/crlf" | tail -n 1)"
# pinned sha256 of the default personality file (#150)
mkdir "$t/etc"; cp fingerprints/columbo-v1.db fingerprints/columbo-v1.db.sha256 "$t/etc/"
pmetc() { env -i PATH=/usr/bin:/bin PM_LIBDIR="$PWD/debian/scripts" PM_SYSFS_NET="$t/net" \
    PM_DEFAULT="$t/edited" PM_ETC="$t/etc" ${SH:-/bin/sh} debian/scripts/pm-start check; }
pmetc && echo "ok: columbo-v1.db matches pinned sha256"
echo tampered >> "$t/etc/columbo-v1.db"
rc=0; pmetc 2>"$t/err" || rc=$?
if [ $rc != 78 ] || ! grep -q 'does not match its pinned sha256' "$t/err"; then
  echo "FAIL: tampered columbo-v1.db accepted (rc=$rc)"; cat "$t/err"; exit 1
fi
echo "ok: tampered columbo-v1.db -> $(cat "$t/err")"
echo "pm-start test OK"
