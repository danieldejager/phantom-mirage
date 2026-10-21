#!/bin/bash
# --sandbox-daemon (#16): one honeyd with the daemon seccomp allowlist
# serving a subsystem, a shell script port, an internal Python 3 service,
# the status page and honeydctl, through SIGHUP/SIGUSR1; once with
# --sandbox-scripts on top. Any denied syscall (daemon: "sandbox-daemon:
# denied syscall", child: "killed by SIGSYS") fails the run.
# Needs root, NET_ADMIN, a --with-python build, /tmp/subsys_echo and the
# libhoneyd.so shim (see the subsystem step). Optional env:
#   HD_EXTRA  extra honeyd args (e.g. "-u 0 -g 0" in a user namespace)
#   HD_WRAP   command prefix for honeyd (e.g. strace)
set -uo pipefail
D=$PWD
W=/tmp/hdsd
rm -rf $W; install -d -m 1777 $W $W/rw
ip route replace 10.99.0.0/24 dev lo
cp ci/svc_escape.sh $W/svc_escape.sh
rm -rf $W/htdocs; cp -r webserver/htdocs $W/htdocs
chown -R ${HD_OWNER:-65534:65534} $W/htdocs/graphs
cat > $W/sd.conf <<'CONF'
create default
set default default tcp action block
create linux
set linux personality "Linux 2.6.32"
set linux default tcp action reset
add linux subsystem "/tmp/subsys_echo"
add linux tcp port 2323 "/bin/sh /tmp/hdsd/svc_escape.sh"
add linux tcp port 7 internal "echo_banner"
bind 10.99.0.10 linux
CONF
mkdir -p /var/run
rc=0
run() {
  mode=$1; shift
  log=$D/sandbox-daemon-$mode.log
  PYTHONPATH=$D/scripts/python timeout 90 ${HD_WRAP:-} ./honeyd -d \
    -f $W/sd.conf -i lo --sandbox-daemon \
    --webserver-port=8080 --webserver-root=$W/htdocs \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc \
    -0 $D/pf.os -m $D/nmap-mac-prefixes \
    -l $W/honeyd.log -s $W/service.log --json-log=$W/events.jsonl \
    --heartbeat=1 ${HD_EXTRA:-} "$@" > $log 2>&1 &
  hp=$!
  for i in $(seq 1 40); do
    grep -q 'Listen: .*:18080' $log && grep -q 'sandbox-daemon: seccomp allowlist active' $log && break
    sleep 0.5
  done
  sleep 1
  python3 - <<'PY' || { echo "$mode: traffic checks failed" >&2; rc=1; }
import socket, urllib.request
for n in range(3):
    s = socket.create_connection(("10.99.0.10", 18080), timeout=5)
    assert s.recv(16) == b"hello\n"
    s.close()
s = socket.create_connection(("10.99.0.10", 2323), timeout=5); s.recv(1); s.close()
for n in range(2):
    s = socket.create_connection(("10.99.0.10", 7), timeout=5)
    f = s.makefile("rb")
    assert f.readline().startswith(b"honeyd echo (python ")
    s.sendall(b"hi\r\n"); assert f.readline() == b"echo: hi\r\n"
    s.sendall(b"quit\r\n"); s.close()
with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=5) as r:
    assert r.status == 200 and b"10.99.0.10" in r.read()
print("traffic OK")
PY
  echo '! import honeyd; print(6 * 7)' | timeout 5 ./honeydctl > $W/ctl.out 2>&1 || true
  grep -q '^42' $W/ctl.out || { echo "$mode: honeydctl ! failed" >&2; cat $W/ctl.out; rc=1; }
  echo 'list template' | timeout 5 ./honeydctl > $W/ctl2.out 2>&1 || true
  grep -q '10.99.0.10' $W/ctl2.out || { echo "$mode: honeydctl list failed" >&2; rc=1; }
  hd=$(pgrep -n -x honeyd || true)
  if [ -n "$hd" ]; then
    kill -HUP $hd; sleep 1; kill -USR1 $hd; sleep 1
    python3 -c "import socket; s=socket.create_connection(('10.99.0.10',18080),timeout=5); assert s.recv(16)==b'hello\n'" \
      || { echo "$mode: subsystem dead after SIGHUP" >&2; rc=1; }
    kill -0 $hd || { echo "$mode: honeyd died" >&2; rc=1; }
    kill -INT $hd
  else
    echo "$mode: honeyd not running" >&2; rc=1
  fi
  wait $hp
  echo "=== $mode"; cat $log
  grep -q 'sandbox-daemon: seccomp allowlist active' $log || { echo "$mode: filter not reported active" >&2; rc=1; }
  if grep -E 'sandbox-daemon: denied syscall|killed by SIGSYS|runtime error|ERROR: AddressSanitizer' $log; then
    echo "$mode: denied syscall or sanitizer report" >&2; rc=1
  fi
}
run plain
run scripts --sandbox-scripts --sandbox-allow-write=$W/rw

# Negative check: a syscall off the list (mount, via honeydctl "!") must
# be reported and kill the daemon with SIGSYS.
log=$D/sandbox-daemon-deny.log
PYTHONPATH=$D/scripts/python timeout 60 ${HD_WRAP:-} ./honeyd -d \
  -f $W/sd.conf -i lo --sandbox-daemon --disable-webserver \
  -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc \
  -0 $D/pf.os -m $D/nmap-mac-prefixes ${HD_EXTRA:-} > $log 2>&1 &
hp=$!
for i in $(seq 1 40); do
  grep -q 'sandbox-daemon: seccomp allowlist active' $log && break; sleep 0.5
done
sleep 1
echo '! import ctypes, os; ctypes.CDLL(None).mount(b"none", b"/mnt", b"tmpfs", 0, None)' |
  timeout 5 ./honeydctl > /dev/null 2>&1 || true
wait $hp; st=$?
echo "=== deny (exit $st)"; cat $log
grep -q 'sandbox-daemon: denied syscall' $log || { echo "deny: denial not logged" >&2; rc=1; }
if pgrep -x honeyd >/dev/null; then echo "deny: honeyd still running" >&2; pkill -x honeyd; rc=1; fi
exit $rc
