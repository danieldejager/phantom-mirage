#!/bin/bash
# The installed package under real systemd (#16): phantom-mirage.service
# with its defaults (--sandbox-daemon --sandbox-scripts, ProtectSystem=
# strict, RestrictNamespaces=user mnt pid ipc uts net). Checks that the
# daemon is sandboxed, a script gets its own namespaces, the pid file and
# control socket behave across restart/stop, nothing is denied, and that
# removing the sandbox flags gives the loud warning. Run as root on a host
# booted with systemd, after installing the .deb.
set -uo pipefail
U=phantom-mirage
rc=0
fail() { echo "systemd-unit: $*" >&2; rc=1; }
since=$(date '+%Y-%m-%d %H:%M:%S')
jr() { journalctl -u $U --since "$since" --no-pager -o cat; }

ip route replace 10.99.0.0/24 dev lo
cat > /etc/phantom-mirage/ns_probe.sh <<'SH'
#!/bin/sh
echo "pid=$$ host=$(uname -n) links=$(ip -o link | wc -l) loup=$(ip -o link show lo | grep -c LOWER_UP)"
echo probe > /tmp/ns_probe && echo "tmp=$(cat /tmp/ns_probe)"
SH
chmod 755 /etc/phantom-mirage/ns_probe.sh
cat > /etc/phantom-mirage/phantom-mirage.conf <<'CONF'
create default
set default default tcp action reset
create linux
set linux personality "Linux 2.6.32"
set linux default tcp action reset
add linux tcp port 2424 "/bin/sh /etc/phantom-mirage/ns_probe.sh"
bind 10.99.0.12 linux
CONF
sed -i 's/^INTERFACE=.*/INTERFACE="lo"/; s#^NETWORK=.*#NETWORK=10.99.0.0/24#' /etc/default/phantom-mirage

wait_up() {
  for i in $(seq 1 40); do
    systemctl is-active -q $U && test -S /run/$U/$U.sock && test -s /run/$U/$U.pid && break
    sleep 0.5
  done
  sleep 1
}
probe() {
  python3 - <<'PY'
import socket
s = socket.create_connection(("10.99.0.12", 2424), timeout=10)
d = b""
while True:
    b = s.recv(4096)
    if not b: break
    d += b
print(d.decode(errors="replace").replace("\n", " "))
PY
}
check_running() {
  what=$1
  systemctl is-active -q $U || { fail "$what: not active"; systemctl status $U --no-pager; return; }
  mp=$(systemctl show -p MainPID --value $U)
  [ "$(cat /run/$U/$U.pid)" = "$mp" ] || fail "$what: pid file '$(cat /run/$U/$U.pid)' != MainPID $mp"
  [ "$(stat -c '%a %u' /run/$U/$U.pid)" = "644 0" ] || fail "$what: pid file $(stat -c '%a %u' /run/$U/$U.pid)"
  [ "$(stat -c '%a %u' /run/$U)" = "700 0" ] || fail "$what: /run/$U is $(stat -c '%a %u' /run/$U)"
  [ "$(stat -c '%a %u %F' /run/$U/$U.sock)" = "600 0 socket" ] || fail "$what: socket $(stat -c '%a %u %F' /run/$U/$U.sock)"
  grep -E '^(Uid|NoNewPrivs|Seccomp|CapEff):' /proc/$mp/status
  grep -Eq "^Uid:\s+$(id -u $U)\s" /proc/$mp/status || fail "$what: daemon not running as $U"
  grep -Eq '^NoNewPrivs:\s+1' /proc/$mp/status || fail "$what: no_new_privs not set"
  grep -Eq '^Seccomp:\s+2' /proc/$mp/status || fail "$what: no seccomp filter"
  echo 'list template' | timeout 5 phantom-mirage-ctl | grep -q 10.99.0.12 || fail "$what: phantom-mirage-ctl list failed"
  out=$(probe); echo "$what: $out"
  # (hostname stays the host's: the unit's ProtectHostname=yes forbids
  # sethostname, though the script still has its own UTS namespace)
  grep -Eq 'pid=1 host=[^ ]+ links=1 loup=0 tmp=probe' <<<"$out" || fail "$what: script not namespaced: $out"
  [ -e /tmp/ns_probe ] && fail "$what: script /tmp not private"
}

systemctl show -p ProtectSystem -p RestrictNamespaces -p NoNewPrivileges $U
[ "$(systemctl show -p ProtectSystem --value $U)" = strict ] || fail "ProtectSystem is not strict"

systemctl start $U; wait_up; check_running start
old=$(cat /run/$U/$U.pid)
systemctl restart $U; wait_up; check_running restart
[ "$(cat /run/$U/$U.pid)" != "$old" ] || fail "restart: pid file not updated"
systemctl reload $U || fail "reload failed"; sleep 2; check_running reload
jr | grep -q 'rereading configuration on signal 1' || fail "reload: SIGHUP not received"
systemctl stop $U
[ -e /run/$U ] && fail "stop: /run/$U left behind"

echo "=== journal"; jr
jr | grep -q 'sandbox-daemon: seccomp allowlist active' || fail "seccomp allowlist not reported"
jr | grep -q 'sandbox-daemon: Landlock ABI' || fail "daemon Landlock not active"
jr | grep -q 'scripts run in their own user, mount, PID, IPC, UTS and network namespaces' || fail "script namespaces not active"
if jr | grep -E 'denied syscall|killed by SIGSYS|WITHOUT|Landlock unavailable|namespaces unavailable'; then fail "denial or warning in the journal"; fi

# Without the sandbox flags: loud warning (and still runs)
mkdir -p /etc/systemd/system/$U.service.d
printf '[Service]\nEnvironment=SANDBOX=\n' > /etc/systemd/system/$U.service.d/nosandbox.conf
systemctl daemon-reload
since=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
systemctl start $U; wait_up
systemctl is-active -q $U || fail "no-sandbox: not active"
jr | grep -q 'WARNING: running under systemd WITHOUT --sandbox-daemon and --sandbox-scripts' || { fail "no-sandbox: no warning"; jr; }
systemctl stop $U
rm -rf /etc/systemd/system/$U.service.d; systemctl daemon-reload

[ $rc = 0 ] && echo "systemd-unit OK"
exit $rc
