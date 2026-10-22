#!/bin/bash
# --sandbox-daemon (#16): one phantom-mirage with the daemon seccomp allowlist
# serving a subsystem, a shell script port, an internal Python 3 service,
# the status page and phantom-mirage-ctl, through SIGHUP/SIGUSR1; once with
# --sandbox-scripts on top. Any denied syscall (daemon: "sandbox-daemon:
# denied syscall", child: "killed by SIGSYS") fails the run.
# Needs root, NET_ADMIN, a --with-python build, /tmp/subsys_echo and the
# libphantom-mirage.so shim (see the subsystem step). Optional env:
#   HD_EXTRA  extra phantom-mirage args (e.g. "-u 0 -g 0" in a user namespace)
#   HD_WRAP   command prefix for phantom-mirage (e.g. strace)
#   HD_LEARN  1: run without --sandbox-daemon (strace collection) and
#             skip the filter checks and the negative check
#   HD_LANDLOCK  "require": fail unless the daemon reports Landlock active
#             (default: also accept the logged "Landlock unavailable")
#   HD_NOPY   1: the binary has no embedded Python (the Docker image): no
#             internal Python service, status page or phantom-mirage-ctl "!"
#             probes; Landlock is then checked from the daemon's log only
#             and the off-list syscall check is skipped
#   HD_SUBSYS subsystem binary (default /tmp/subsys_echo)
set -uo pipefail
D=$PWD
W=${HD_WORK:-/tmp/hdsd}
rm -rf $W; install -d -m 1777 $W $W/rw $W/log
ip route replace 10.99.0.0/24 dev lo
cp ci/svc_escape.sh $W/svc_escape.sh
rm -rf $W/htdocs; cp -r webserver/htdocs $W/htdocs
chown -R ${HD_OWNER:-65534:65534} $W/htdocs/graphs
cat > $W/sd.conf <<CONF
create default
set default default tcp action block
create linux
set linux personality "Linux 2.6.32"
set linux default tcp action reset
add linux subsystem "${HD_SUBSYS:-/tmp/subsys_echo}"
add linux tcp port 2323 "/bin/sh $W/svc_escape.sh"
$( [ "${HD_NOPY:-0}" = 1 ] || echo 'add linux tcp port 7 internal "echo_banner"' )
bind 10.99.0.10 linux
CONF
mkdir -p /var/run
rc=0
SBD=--sandbox-daemon
ACTIVE='sandbox-daemon: seccomp allowlist active'
if [ "${HD_LEARN:-0}" = 1 ]; then SBD=; ACTIVE='Demoting process privileges'; fi
NOPY=${HD_NOPY:-0}
if [ "$NOPY" = 1 ]; then WEB=--disable-webserver; else WEB="--webserver-port=8080 --webserver-root=$W/htdocs"; fi
export NOPY
run() {
  mode=$1; shift
  log=${HD_LOGDIR:-$D}/sandbox-daemon-$mode.log
  PYTHONPATH=$D/scripts/python timeout 90 ${HD_WRAP:-} ./phantom-mirage -d \
    -f $W/sd.conf -i lo $SBD \
    $WEB \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc \
    -0 $D/pf.os -m $D/nmap-mac-prefixes \
    -l $W/log/phantom-mirage.log -s $W/log/service.log --json-log=$W/log/events.jsonl \
    --heartbeat=1 ${HD_EXTRA:-} "$@" > $log 2>&1 &
  hp=$!
  for i in $(seq 1 40); do
    grep -q 'Listen: .*:18080' $log && grep -q "$ACTIVE" $log && break
    sleep 0.5
  done
  sleep 1
  python3 - <<'PY' || { echo "$mode: traffic checks failed" >&2; rc=1; }
import os, socket, urllib.request
nopy = os.environ.get("NOPY") == "1"
for n in range(3):
    s = socket.create_connection(("10.99.0.10", 18080), timeout=5)
    assert s.recv(16) == b"hello\n"
    s.close()
s = socket.create_connection(("10.99.0.10", 2323), timeout=5); s.recv(1); s.close()
for n in range(0 if nopy else 2):
    s = socket.create_connection(("10.99.0.10", 7), timeout=5)
    f = s.makefile("rb")
    assert f.readline().startswith(b"honeyd echo (python ")
    s.sendall(b"hi\r\n"); assert f.readline() == b"echo: hi\r\n"
    s.sendall(b"quit\r\n"); s.close()
if not nopy:
    with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=5) as r:
        assert r.status == 200 and b"10.99.0.10" in r.read()
print("traffic OK")
PY
  if [ "$NOPY" != 1 ]; then
    echo '! import honeyd; print(6 * 7)' | timeout 5 ./phantom-mirage-ctl > $W/ctl.out 2>&1 || true
    grep -q '^42' $W/ctl.out || { echo "$mode: phantom-mirage-ctl ! failed" >&2; cat $W/ctl.out; rc=1; }
  fi
  echo 'list template' | timeout 5 ./phantom-mirage-ctl > $W/ctl2.out 2>&1 || true
  grep -q '10.99.0.10' $W/ctl2.out || { echo "$mode: phantom-mirage-ctl list failed" >&2; rc=1; }
  if [ -z "$SBD" ]; then :; elif [ "$NOPY" = 1 ] && grep -q 'sandbox-daemon: Landlock ABI' $log; then
    : # no "!" probe without Python; the log line says Landlock is on
  elif grep -q 'sandbox-daemon: Landlock ABI' $log; then
    # Landlock on the daemon: writes outside the log/socket/graphs dirs
    # and TCP connects (no proxy configured) are refused with EACCES.
    echo "! import ctypes, socket; c = ctypes.CDLL(None, use_errno=True); r = c.open(b'$W/ll_probe', 0o1101, 0o644); e = ctypes.get_errno(); g = c.open(b'$W/log/ll_ok', 0o1101, 0o644); print('LL', r, e, g >= 0, socket.socket().connect_ex(('127.0.0.1', 8080)))" |
      timeout 5 ./phantom-mirage-ctl > $W/ctl3.out 2>&1 || true
    cat $W/ctl3.out
    grep -q "^LL -1 13 True" $W/ctl3.out || { echo "$mode: Landlock fs rules not enforced" >&2; rc=1; }
    [ -e $W/ll_probe ] && { echo "$mode: Landlock let the daemon write $W" >&2; rc=1; }
    abi=$(sed -n 's/.*sandbox-daemon: Landlock ABI \([0-9]*\).*/\1/p' $log | head -1)
    if [ "${abi:-0}" -ge 4 ]; then
      grep -q "^LL -1 13 True 13" $W/ctl3.out || { echo "$mode: Landlock TCP connect not denied" >&2; rc=1; }
    fi
  elif [ "${HD_LANDLOCK:-}" = require ]; then
    echo "$mode: Landlock required but not active" >&2; rc=1
  else
    grep -q 'sandbox-daemon: Landlock unavailable' $log || { echo "$mode: Landlock state not logged" >&2; rc=1; }
  fi
  hd=$(pgrep -n -x phantom-mirage || true)
  if [ -n "$hd" ]; then
    kill -HUP $hd; sleep 1; kill -USR1 $hd; sleep 1
    python3 -c "import socket; s=socket.create_connection(('10.99.0.10',18080),timeout=5); assert s.recv(16)==b'hello\n'" \
      || { echo "$mode: subsystem dead after SIGHUP" >&2; rc=1; }
    kill -0 $hd || { echo "$mode: phantom-mirage died" >&2; rc=1; }
    kill -INT $hd
  else
    echo "$mode: phantom-mirage not running" >&2; rc=1
  fi
  wait $hp
  echo "=== $mode"; cat $log
  grep -q "$ACTIVE" $log || { echo "$mode: filter not reported active" >&2; rc=1; }
  if grep -E 'sandbox-daemon: denied syscall|killed by SIGSYS|runtime error|ERROR: AddressSanitizer' $log; then
    echo "$mode: denied syscall or sanitizer report" >&2; rc=1
  fi
}
run plain
run scripts --sandbox-scripts --sandbox-allow-write=$W/rw
[ "${HD_LEARN:-0}" = 1 ] && exit $rc
[ "$NOPY" = 1 ] && { echo "sandbox-daemon: off-list syscall check needs Python (skipped)"; exit $rc; }

# Negative check: a syscall off the list (mount, via phantom-mirage-ctl "!") must
# be reported and kill the daemon with SIGSYS.
log=${HD_LOGDIR:-$D}/sandbox-daemon-deny.log
PYTHONPATH=$D/scripts/python timeout 60 ${HD_WRAP:-} ./phantom-mirage -d \
  -f $W/sd.conf -i lo --sandbox-daemon --disable-webserver \
  -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc \
  -0 $D/pf.os -m $D/nmap-mac-prefixes ${HD_EXTRA:-} > $log 2>&1 &
hp=$!
for i in $(seq 1 40); do
  grep -q 'sandbox-daemon: seccomp allowlist active' $log && break; sleep 0.5
done
sleep 1
echo '! import ctypes, os; ctypes.CDLL(None).mount(b"none", b"/mnt", b"tmpfs", 0, None)' |
  timeout 5 ./phantom-mirage-ctl > /dev/null 2>&1 || true
wait $hp; st=$?
echo "=== deny (exit $st)"; cat $log
grep -q 'sandbox-daemon: denied syscall' $log || { echo "deny: denial not logged" >&2; rc=1; }
if pgrep -x phantom-mirage >/dev/null; then echo "deny: phantom-mirage still running" >&2; pkill -x phantom-mirage; rc=1; fi
exit $rc
