#!/bin/bash
# Pid file (/run/phantom-mirage/phantom-mirage.pid) with --sandbox-daemon:
# start, stop, restart, a stale pid file and a second instance. After the
# privilege drop the daemon can't unlink the file in the root-only
# control socket dir, so on exit it must be gone or empty, and an empty or
# stale one must not stop the next start. Needs root and NET_ADMIN.
# Optional env: HD_EXTRA, HD_WRAP, HD_LOGDIR (as in ci/sandbox_daemon.sh).
set -uo pipefail
D=$PWD
PF=/run/phantom-mirage/phantom-mirage.pid
L=${HD_LOGDIR:-$D}
W=$(mktemp -d)
cat > $W/pf.conf <<CONF
create default
set default default tcp action reset
CONF
rc=0
fail() { echo "pidfile: $*" >&2; rc=1; }
start() {
  log=$L/pidfile-$1.log
  timeout 60 ${HD_WRAP:-} ./phantom-mirage -d -f $W/pf.conf -i lo \
    --sandbox-daemon --disable-webserver \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc -0 $D/pf.os \
    -m $D/nmap-mac-prefixes ${HD_EXTRA:-} > $log 2>&1 &
  hp=$!
  for i in $(seq 1 40); do
    grep -q 'seccomp allowlist active' $log && break; sleep 0.5
  done
  hd=$(pgrep -n -x phantom-mirage)
}
stop() {
  kill -TERM $hd; wait $hp
  if [ -s $PF ]; then fail "$1: $PF still names a pid after exit: $(cat $PF)"; fi
  if [ -e $PF ]; then echo "$1: $PF left empty (dropped privileges)"; else echo "$1: $PF removed"; fi
}
check_running() {
  [ -n "$hd" ] && kill -0 $hd || { fail "$1: daemon not running"; cat $log; return; }
  [ "$(cat $PF)" = "$hd" ] || fail "$1: $PF is '$(cat $PF)', want $hd"
  [ "$(stat -c '%a %u' $PF)" = "644 0" ] || fail "$1: $PF is $(stat -c '%a %u' $PF), want 644 root"
  [ "$(stat -c '%a %u' /run/phantom-mirage)" = "700 0" ] || fail "$1: dir not root 0700"
  [ "$(stat -c '%a %u' /run/phantom-mirage/phantom-mirage.sock)" = "600 0" ] || fail "$1: socket not root 0600"
}

start first; check_running first
# a second instance must refuse to start and leave the pid file alone
timeout 30 ./phantom-mirage -d -f $W/pf.conf -i lo --disable-webserver \
  -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc -0 $D/pf.os \
  -m $D/nmap-mac-prefixes ${HD_EXTRA:-} > $L/pidfile-second.log 2>&1 \
  && fail "second instance started"
grep -q 'already running' $L/pidfile-second.log || fail "second instance: no 'already running'"
[ "$(cat $PF)" = "$hd" ] || fail "second instance clobbered $PF"
stop first

start restart; check_running restart; stop restart

# stale: a pid that is not running
install -d -m 0700 /run/phantom-mirage
pid=999999; while kill -0 $pid 2>/dev/null; do pid=$((pid - 1)); done
echo $pid > $PF
start stale; check_running stale
grep -q 'replacing stale pid file' $log || fail "stale: not logged"
stop stale

for f in $L/pidfile-*.log; do
  if grep -E 'denied syscall|killed by SIGSYS|runtime error|ERROR: AddressSanitizer' $f; then fail "$f"; fi
done
rm -rf $W
[ $rc = 0 ] && echo "pidfile OK"
exit $rc
