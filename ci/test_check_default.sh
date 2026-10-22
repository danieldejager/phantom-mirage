#!/bin/bash
# debian/scripts/check-default against sample /etc/default files (#110)
set -euo pipefail
cd "$(dirname "$0")/.."
chk=$PWD/debian/scripts/check-default
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir "$t/net"; touch "$t/net/eth0"
export PM_SYSFS_NET=$t/net
unset INTERFACE NETWORK ALLOW_WIDE_NETWORK

# expect RC PATTERN -- file contents
expect() {
  local want=$1 pat=$2; shift 2
  printf '%s\n' "$@" > "$t/default"
  local rc=0; env -i PM_SYSFS_NET="$PM_SYSFS_NET" ${SH:-/bin/sh} "$chk" "$t/default" 2>"$t/err" || rc=$?
  local okmsg
  if [ -n "$pat" ]; then grep -q -- "$pat" "$t/err" && okmsg=1 || okmsg=
  else [ ! -s "$t/err" ] && okmsg=1 || okmsg=; fi
  if [ "$rc" != "$want" ] || [ -z "$okmsg" ]; then
    echo "FAIL: [$*] rc=$rc (want $want), stderr:"; cat "$t/err"; exit 1
  fi
  echo "ok: [$*] -> $rc ${pat:+($(cat "$t/err"))}"
}

# the shipped file is refused
cp debian/phantom-mirage.default "$t/default"
rc=0; env -i PM_SYSFS_NET="$PM_SYSFS_NET" ${SH:-/bin/sh} "$chk" "$t/default" 2>"$t/err" || rc=$?
[ "$rc" = 78 ] && grep -q '^phantom-mirage: INTERFACE is not set in ' "$t/err" || { echo "FAIL: shipped default"; cat "$t/err"; exit 1; }
echo "ok: shipped default -> 78 ($(cat "$t/err"))"

expect 78 'INTERFACE is not set'      'INTERFACE=""' 'NETWORK=192.168.1.8/29'
expect 78 'interface "eth9" (INTERFACE in .*) does not exist' 'INTERFACE=eth9' 'NETWORK=192.168.1.8/29'
expect 78 'NETWORK is not set'        'INTERFACE=eth0' 'NETWORK=""'
expect 78 'NETWORK=10.0.0.0/8 .* wider than /24' 'INTERFACE=eth0' 'NETWORK=10.0.0.0/8'
expect 78 'wider than /24'            'INTERFACE=eth0' 'NETWORK="192.168.1.8/29 10.1.0.0/16"'
expect 78 'wider than /120'           'INTERFACE=eth0' 'NETWORK=2001:db8::/64'
expect 0  ''                          'INTERFACE=eth0' 'NETWORK=192.168.1.8/29'
expect 0  ''                          'INTERFACE=eth0' 'NETWORK=10.99.0.0/24'
expect 0  ''                          'INTERFACE=eth0' 'NETWORK=192.168.1.9'
expect 0  ''                          'INTERFACE=eth0' 'NETWORK=10.0.0.0/8' 'ALLOW_WIDE_NETWORK=yes'
expect 0  ''                          'INTERFACE=eth0' 'NETWORK=""' 'ALLOW_WIDE_NETWORK=yes'
echo "check-default test OK"
