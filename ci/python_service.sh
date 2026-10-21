#!/bin/bash
# Embedded Python 3 service script under the sanitizers (#36).
# Needs a honeyd built with --with-python, root and NET_ADMIN.
# 10.99.0.0/24 must be routed over lo (see the subsystem step).
set -euo pipefail
D=$PWD
install -d -m 1777 /tmp/hdpy
cat > /tmp/hdpy/py.conf <<'CONF'
create default
set default default tcp action block
create linux
set linux personality "Linux 2.6.32"
set linux default tcp action reset
add linux tcp port 7 internal "echo_banner"
bind 10.99.0.10 linux
CONF
mkdir -p /var/run
# Reject a missing module at config time
printf 'create x\nadd x tcp port 7 internal "no_such_module"\n' > /tmp/hdpy/bad.conf
if ./honeyd --verify-config -f /tmp/hdpy/bad.conf -i lo --disable-webserver \
    -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc \
    -0 $D/pf.os -m $D/nmap-mac-prefixes > /tmp/hdpy/bad.log 2>&1; then
  cat /tmp/hdpy/bad.log; echo "missing python module was accepted" >&2; exit 1
fi
grep -q 'Bad python module' /tmp/hdpy/bad.log
# No --disable-webserver: the Python 2 webserver must not stop startup.
PYTHONPATH=$D/scripts/python timeout 60 ./honeyd -d -f /tmp/hdpy/py.conf -i lo \
  -p $D/nmap-os-db -x $D/xprobe2.conf -a $D/nmap.assoc \
  -0 $D/pf.os -m $D/nmap-mac-prefixes \
  -l /tmp/hdpy/honeyd.log -s /tmp/hdpy/service.log > honeyd-py.log 2>&1 &
hp=$!
for i in $(seq 1 30); do
  grep -q 'Demoting process privileges' honeyd-py.log && break; sleep 0.5
done
sleep 1
rc=0
python3 - <<'PY' || rc=1
import socket
for n in range(3):
    s = socket.create_connection(("10.99.0.10", 7), timeout=5)
    f = s.makefile("rb")
    banner = f.readline()
    assert banner.startswith(b"honeyd echo (python "), banner
    payload = b"hi \xff\x00 %d\r\n" % n
    s.sendall(payload)
    line = f.readline()
    assert line == b"echo: " + payload, line
    s.sendall(b"quit\r\n")
    assert f.read() == b"", "server did not close"
    s.close()
print("python service: 3 connections OK")
PY
# honeydctl "!" runs Python inside honeyd (pyextend_run)
echo '! import honeyd; print(6 * 7, honeyd.version)' | timeout 5 ./honeydctl > honeyd-py-ctl.out 2>&1 || true
cat honeyd-py-ctl.out
grep -q '^42 ' honeyd-py-ctl.out || { echo "honeydctl ! did not run python" >&2; rc=1; }
sleep 1
kill -INT $hp 2>/dev/null || true
wait $hp || true
cat honeyd-py.log
echo "--- service log"; cat /tmp/hdpy/service.log || true
cp /tmp/hdpy/service.log honeyd-py-service.log 2>/dev/null || true
if grep -E 'runtime error|ERROR: AddressSanitizer' honeyd-py.log; then rc=1; fi
grep -q 'internal webserver disabled' honeyd-py.log || { echo "webserver fallback not logged" >&2; rc=1; }
grep -q 'python echo .* bytes from' /tmp/hdpy/service.log || { echo "honeyd.log() not in service log" >&2; rc=1; }
exit $rc
