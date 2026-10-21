#!/bin/bash
# --sandbox-scripts per-script namespaces (#16): a script port must run
# as pid 1 of its own PID namespace, with its own hostname (UTS), a
# private /tmp (mount namespace) and only "lo" (network namespace), and a
# second script must fail to connect out (to a listener on the host's
# 127.0.0.1) or bind a TCP port: scripts get no network at all. Runs
# with and without --sandbox-daemon. Needs root and NET_ADMIN.
# Env: HD_NS=require  fail unless namespaces were used (default: also
#                     accept the logged "user namespaces unavailable")
#      HD_LTRACE=DIR  strace -f the pm-script-ns launcher (and the
#                     scripts it runs) into DIR/launcher-MODE
#      HD_EXTRA, HD_WRAP, HD_LOGDIR as in ci/sandbox_daemon.sh
set -uo pipefail
D=$PWD
L=${HD_LOGDIR:-$D}
W=$(mktemp -d /var/tmp/hdns.XXXXXX); chmod 755 $W  # not /tmp: scripts get a private one
ip route replace 10.99.0.0/24 dev lo
cat > $W/probe.sh <<'SH'
#!/bin/sh
echo "pid=$$ host=$(uname -n) links=$(ip -o link | wc -l) loup=$(ip -o link show lo | grep -c LOWER_UP)"
echo probe > /tmp/ns_probe_$1 && echo "tmp=$(cat /tmp/ns_probe_$1)"
echo "shadow=$(cat /etc/shadow >/dev/null 2>&1 && echo y || echo n) etchostname=$(cat /etc/hostname >/dev/null 2>&1 && echo y || echo n) home=$(ls /home >/dev/null 2>&1 && echo y || echo n)"
SH
cat > $W/probe_net.sh <<'SH'
#!/bin/sh
echo "pid=$$ host=$(uname -n)"
python3 - <<'PY'
import errno, socket
def t(f):
    try:
        f()
        return "y"
    except OSError as e:
        return "n(%s)" % errno.errorcode.get(e.errno, e.errno)
def c():
    s = socket.socket(); s.settimeout(3); s.connect(("127.0.0.1", 2499))
def b():
    s = socket.socket(); s.bind(("127.0.0.1", 2498)); s.listen(1)
print("connect=%s bind=%s" % (t(c), t(b)))
PY
SH
cat > $W/ns.conf <<CONF
create default
set default default tcp action reset
create linux
set linux personality "Linux 2.6.32"
set linux default tcp action reset
add linux tcp port 2424 "/bin/sh $W/probe.sh a"
add linux tcp port 2425 "/bin/sh $W/probe_net.sh b"
bind 10.99.0.11 linux
CONF
rm -f /tmp/ns_probe_a /tmp/ns_probe_b
# a listener on the host's loopback for the outbound check
python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",2499)); s.listen(8); time.sleep(900)' &
lsn=$!
ll_abi() { python3 -c 'import ctypes; l=ctypes.CDLL(None,use_errno=True); print(max(0,l.syscall(444,None,0,1)))' 2>/dev/null || echo 0; }
rc=0
fail() { echo "script-ns: $*" >&2; rc=1; }
run() {
  mode=$1; shift
  log=$L/script-ns-$mode.log
  timeout 60 ${HD_WRAP:-} ./phantom-mirage -d -f $W/ns.conf -i lo \
    --sandbox-scripts --disable-webserver \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc -0 $D/pf.os \
    -m $D/nmap-mac-prefixes ${HD_EXTRA:-} "$@" > $log 2>&1 &
  hp=$!
  for i in $(seq 1 40); do grep -q 'sandbox: \(scripts run in their own\|unprivileged user namespaces\)' $log && break; sleep 0.5; done
  sleep 1
  sp=
  if [ -n "${HD_LTRACE:-}" ] && lp=$(pgrep -x pm-script-ns | head -1); then
    strace -f -qq -o ${HD_LTRACE}/launcher-$mode -p $lp & sp=$!; sleep 1
  fi
  if [ "$mode" = daemon ]; then
    grep -q 'script launcher seccomp allowlist active' $log || fail "$mode: launcher seccomp allowlist not active"
  fi
  out=$(python3 - <<'PY'
import socket
for port in (2424, 2425):
    s = socket.create_connection(("10.99.0.11", port), timeout=10)
    data = b""
    while True:
        b = s.recv(4096)
        if not b: break
        data += b
    s.close()
    print(port, data.decode(errors="replace").replace("\n", " "))
PY
)
  echo "$mode: $out"
  [ -n "$sp" ] && { kill $sp; wait $sp 2>/dev/null; }
  isol=$(grep '^2424' <<<"$out"); net=$(grep '^2425' <<<"$out")
  if grep -q 'scripts run in their own' $log; then
    grep -q 'pid=1 host=phantom-mirage-script links=1 loup=0 tmp=probe' <<<"$isol" || fail "$mode: isolated script: $isol"
    grep -q 'pid=1 host=phantom-mirage-script' <<<"$net" || fail "$mode: net script not namespaced: $net"
    [ -e /tmp/ns_probe_a ] && fail "$mode: /tmp is not private"
    grep -q 'shadow=n etchostname=n home=n' <<<"$isol" || fail "$mode: script sees host files: $isol"
  elif [ "${HD_NS:-}" = require ]; then
    fail "$mode: namespaces required but unavailable"
  else
    grep -q 'unprivileged user namespaces unavailable' $log || fail "$mode: fallback not logged"
    grep -q 'pid=' <<<"$isol" || fail "$mode: script did not run in fallback mode: $isol"
  fi
  # no network, with or without namespaces (then Landlock ABI 4+ alone)
  grep -q 'connect=n' <<<"$net" || fail "$mode: script connected out: $net"
  if ! grep -q 'Landlock unavailable' $log && [ "$(ll_abi)" -ge 4 ]; then
    grep -q 'bind=n' <<<"$net" || fail "$mode: script could bind a TCP port: $net"
  fi
  hd=$(pgrep -n -x phantom-mirage)
  [ -n "$hd" ] && kill -INT $hd
  wait $hp
  echo "=== $mode"; cat $log
  if grep -E 'denied syscall|killed by SIGSYS|runtime error|ERROR: AddressSanitizer' $log; then fail "$mode: denial or sanitizer report"; fi
  for i in $(seq 1 20); do pgrep -f "$W/probe" > /dev/null || break; sleep 0.5; done
  pgrep -f "$W/probe" && fail "$mode: script left running"
  rm -f /tmp/ns_probe_a /tmp/ns_probe_b
}
run scripts
run daemon --sandbox-daemon
kill $lsn 2>/dev/null
# the old per-script network opt-in is gone, and says so
if ./phantom-mirage --sandbox-scripts --sandbox-script-net=/bin/true -i lo > $L/script-net.log 2>&1; then
  fail "--sandbox-script-net was accepted"
fi
grep -q -- '--sandbox-script-net has been removed: scripts get no network' $L/script-net.log || fail "--sandbox-script-net: no clear error: $(cat $L/script-net.log)"
rm -rf $W
[ $rc = 0 ] && echo "script-ns OK"
exit $rc
