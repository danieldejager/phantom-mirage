#!/bin/bash
# The existing service scripts (scripts/: sh, Perl, Python 3) under
# --sandbox-scripts with namespaces and the minimal read-only root (#16).
# Each one gets the same request twice: run directly (as the same
# unprivileged user, same working directory) and through phantom-mirage.
# A script that answers directly must answer in the sandbox too, and the
# sandboxed run must not log a missing file, module or permission that
# the direct run did not.
# Modes:
#   build tree (default): starts ./phantom-mirage --sandbox-scripts
#     --sandbox-daemon itself; needs root and NET_ADMIN.
#   HD_SYSTEMD=1: adds the ports to the installed config and reloads
#     phantom-mirage.service (run after ci/systemd_unit.sh's config).
# Env: HD_LOGDIR (logs), HD_EXTRA (extra phantom-mirage args).
set -uo pipefail
D=$PWD
L=${HD_LOGDIR:-$D}
rc=0
fail() { echo "ns-services: $*" >&2; rc=1; }
IP=10.99.0.14
ip route replace 10.99.0.0/24 dev lo

if [ "${HD_SYSTEMD:-0}" = 1 ]; then
  TOP=/usr/share/phantom-mirage
  RUNAS=$(id -u phantom-mirage):$(id -g phantom-mirage)
else
  TOP=$D
  RUNAS=65534:65534
fi
cd $TOP
# helpers and modules, not services; proxy.pl needs the network
mapfile -t S < <(find scripts -type f \( -name '*.sh' -o -name '*.pl' -o -name '*.py' \) |
  grep -v -e '^scripts/lib/' -e '^scripts/python/' -e buildSNMPConfig -e honeydsum \
    -e '/mdns/dns.py' -e '/proxy.pl' -e '/nbns-wpad-query.py' | sort)
echo "ns-services: ${#S[@]} scripts"
interp() { case $1 in *.sh) echo sh;; *.pl) echo perl;; *.py) echo python3;; esac; }

W=$(mktemp -d /var/tmp/hdsvc.XXXXXX); chmod 755 $W
conf=$W/svc.conf
{
  echo 'create default'; echo 'set default default tcp action reset'
  echo 'create svc'; echo 'set svc personality "Linux 2.6.32"'
  echo 'set svc default tcp action reset'
  for i in "${!S[@]}"; do
    echo "add svc tcp port $((3000 + i)) \"$(interp ${S[$i]}) ${S[$i]} \$ipsrc \$sport \$ipdst \$dport\""
  done
  echo "bind $IP svc"
} > $conf
REQ='GET / HTTP/1.0\r\nHost: x\r\n\r\nHELO x\r\nUSER a\r\nPASS b\r\nQUIT\r\n'

if [ "${HD_SYSTEMD:-0}" = 1 ]; then
  grep -v '^create default\|^set default' $conf >> /etc/phantom-mirage/phantom-mirage.conf
  systemctl reload phantom-mirage; sleep 3
  svclog=
else
  svclog=$W/service.log
  PATH=/usr/bin:/bin timeout 600 ./phantom-mirage -d -f $conf -i lo \
    --sandbox-scripts --sandbox-daemon --disable-webserver -s $svclog \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc -0 $D/pf.os \
    -m $D/nmap-mac-prefixes ${HD_EXTRA:-} > $L/ns-services.log 2>&1 &
  hp=$!
  for i in $(seq 1 40); do grep -q 'scripts run in their own' $L/ns-services.log && break; sleep 0.5; done
  sleep 1
  grep -q 'minimal read-only root' $L/ns-services.log || fail "namespaces / read-only root not active"
fi

BAD='Can.t locate|ModuleNotFoundError|ImportError|No such file|Permission denied|Read-only file system|not found|Traceback'
ok=0
for i in "${!S[@]}"; do
  s=${S[$i]}; port=$((3000 + i))
  : > $W/dir.err
  dout=$(printf "$REQ" | timeout 5 setpriv --reuid=${RUNAS%:*} --regid=${RUNAS#*:} --clear-groups -- \
    env -i PATH=/usr/bin:/bin HOME=/nonexistent $(interp $s) $s 10.0.0.1 1234 $IP $port 2> $W/dir.err | head -c 4096 | wc -c)
  [ -n "$svclog" ] && before=$(wc -l < $svclog 2>/dev/null || echo 0)
  sout=$(REQ="$REQ" PORT=$port IP=$IP python3 - <<'PY'
import os, socket
req = os.environ["REQ"].encode().decode("unicode_escape").encode()
try:
    s = socket.create_connection((os.environ["IP"], int(os.environ["PORT"])), timeout=5)
    s.sendall(req)
    s.shutdown(socket.SHUT_WR)
    d = b""
    s.settimeout(5)
    while len(d) < 4096:
        b = s.recv(4096)
        if not b: break
        d += b
except Exception:
    d = b""
print(len(d))
PY
)
  serr=
  if [ -n "$svclog" ]; then sleep 0.3; serr=$(tail -n +$((before + 1)) $svclog 2>/dev/null); fi
  printf '%-45s direct=%-5s sandbox=%s\n' "$s" "$dout" "$sout"
  if [ "$dout" -gt 0 ] && [ "$sout" -eq 0 ]; then fail "$s: answers directly but not in the sandbox"; continue; fi
  if [ -n "$serr" ] && grep -Eq "$BAD" <<<"$serr" && ! grep -Eq "$BAD" $W/dir.err; then
    fail "$s: sandbox-only error: $(grep -E "$BAD" <<<"$serr" | head -3)"; continue
  fi
  ok=$((ok + 1))
done
echo "ns-services: $ok/${#S[@]} scripts behave the same in the sandbox"

if [ "${HD_SYSTEMD:-0}" != 1 ]; then
  kill -INT $hp 2>/dev/null; wait $hp
  if grep -E 'denied syscall|killed by SIGSYS|read-only root:|not running it' $L/ns-services.log; then fail "denial in the log"; fi
  cp $svclog $L/ns-services-service.log 2>/dev/null
fi
rm -rf $W
[ $rc = 0 ] && echo "ns-services OK"
exit $rc
