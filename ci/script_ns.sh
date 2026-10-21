#!/bin/bash
# --sandbox-scripts per-script namespaces (#16): a script port must run
# as pid 1 of its own PID namespace, with its own hostname (UTS), a
# private /tmp (mount namespace) and only "lo" (network namespace), and a
# port listed with --sandbox-script-net must keep the host network. Runs
# with and without --sandbox-daemon. Needs root and NET_ADMIN.
# Env: HD_NS=require  fail unless namespaces were used (default: also
#                     accept the logged "user namespaces unavailable")
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
SH
cp $W/probe.sh $W/probe_net.sh
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
rc=0
fail() { echo "script-ns: $*" >&2; rc=1; }
run() {
  mode=$1; shift
  log=$L/script-ns-$mode.log
  timeout 60 ${HD_WRAP:-} ./phantom-mirage -d -f $W/ns.conf -i lo \
    --sandbox-scripts --sandbox-script-net=$W/probe_net.sh --disable-webserver \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc -0 $D/pf.os \
    -m $D/nmap-mac-prefixes ${HD_EXTRA:-} "$@" > $log 2>&1 &
  hp=$!
  for i in $(seq 1 40); do grep -q 'sandbox: \(scripts run in their own\|unprivileged user namespaces\)' $log && break; sleep 0.5; done
  sleep 1
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
  isol=$(grep '^2424' <<<"$out"); net=$(grep '^2425' <<<"$out")
  if grep -q 'scripts run in their own' $log; then
    grep -q 'pid=1 host=phantom-mirage-script links=1 loup=0 tmp=probe' <<<"$isol" || fail "$mode: isolated script: $isol"
    grep -q 'pid=1 host=phantom-mirage-script' <<<"$net" || fail "$mode: net script not namespaced: $net"
    # the host network: same interfaces, lo up (a new netns has lo down)
    grep -q "links=$(ip -o link | wc -l) loup=1 " <<<"$net" || fail "$mode: --sandbox-script-net script lost the host network: $net"
    [ -e /tmp/ns_probe_a ] && fail "$mode: /tmp is not private"
  elif [ "${HD_NS:-}" = require ]; then
    fail "$mode: namespaces required but unavailable"
  else
    grep -q 'unprivileged user namespaces unavailable' $log || fail "$mode: fallback not logged"
    grep -q 'pid=' <<<"$isol" || fail "$mode: script did not run in fallback mode: $isol"
  fi
  hd=$(pgrep -n -x phantom-mirage)
  [ -n "$hd" ] && kill -INT $hd
  wait $hp
  echo "=== $mode"; cat $log
  if grep -E 'denied syscall|killed by SIGSYS|runtime error|ERROR: AddressSanitizer' $log; then fail "$mode: denial or sanitizer report"; fi
  pgrep -f "$W/probe" && fail "$mode: script left running"
  rm -f /tmp/ns_probe_a /tmp/ns_probe_b
}
run scripts
run daemon --sandbox-daemon
rm -rf $W
[ $rc = 0 ] && echo "script-ns OK"
exit $rc
