#!/bin/bash
# The installed package under real systemd (#16): phantom-mirage.service
# with its defaults (--sandbox-daemon --sandbox-scripts, ProtectSystem=
# strict, RestrictNamespaces=user mnt pid ipc uts net). Checks that the
# daemon is sandboxed, a script gets its own namespaces, the pid file and
# control socket behave across restart/stop, nothing is denied (with
# HD_APPARMOR=require: the launcher runs under its enforcing AppArmor
# profile with the userns restriction on, and no AppArmor denials), and that
# removing the sandbox flags gives the loud warning. Run as root on a host
# booted with systemd, after installing the .deb.
set -uo pipefail
U=phantom-mirage
rc=0
fail() { echo "systemd-unit: $*" >&2; rc=1; }
since=$(date '+%Y-%m-%d %H:%M:%S'); since0=$since
jr() { journalctl -u $U --since "$since" --no-pager -o cat; }

ip route replace 10.99.0.0/24 dev lo
# a listener on the host's loopback: scripts must not reach it
python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",2499)); s.listen(8); time.sleep(900)' &
lsn=$!
cat > /etc/phantom-mirage/ns_probe.sh <<'SH'
#!/bin/sh
echo "pid=$$ host=$(uname -n) links=$(ip -o link | wc -l) loup=$(ip -o link show lo | grep -c LOWER_UP)"
echo probe > /tmp/ns_probe && echo "tmp=$(cat /tmp/ns_probe)"
echo "shadow=$(cat /etc/shadow >/dev/null 2>&1 && echo y || echo n) etchostname=$(cat /etc/hostname >/dev/null 2>&1 && echo y || echo n) home=$(ls /home >/dev/null 2>&1 && echo y || echo n)"
python3 -c 'import socket; s=socket.socket(); s.settimeout(3)
try:
    s.connect(("127.0.0.1", 2499)); print("connect=y")
except OSError as e:
    print("connect=n")'
SH
chmod 755 /etc/phantom-mirage/ns_probe.sh
# personality from columbo-v1.db: the unit loads only that database (pm-start -p)
cat > /etc/phantom-mirage/phantom-mirage.conf <<'CONF'
create default
set default default tcp action reset
create linux
set linux personality "ubuntu2404"
set linux default tcp action reset
add linux tcp port 2424 "/bin/sh /etc/phantom-mirage/ns_probe.sh"
add linux tcp port 2525 "/nonexistent/pm-missing-script"
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
  # AppArmor (debian/apparmor): only the launcher is confined, enforcing
  if [ "${HD_APPARMOR:-}" = require ]; then
    lp=$(pgrep -x pm-script-ns | head -1)
    [ -n "$lp" ] || fail "$what: no pm-script-ns launcher process"
    lab=$(cat /proc/$lp/attr/apparmor/current 2>/dev/null || cat /proc/$lp/attr/current)
    echo "$what: launcher $lp: $lab; daemon: $(cat /proc/$mp/attr/apparmor/current 2>/dev/null || cat /proc/$mp/attr/current)"
    [ "$lab" = "pm-script-ns (enforce)" ] || fail "$what: launcher is '$lab', not pm-script-ns (enforce)"
  fi
  sp=
  if [ -n "${HD_LTRACE:-}" ] && lp=$(pgrep -x pm-script-ns | head -1); then
    strace -f -qq -o ${HD_LTRACE}/launcher-$what -p $lp & sp=$!; sleep 1
  fi
  out=$(probe); echo "$what: $out"
  if [ "$what" = start ]; then
    # the failing exec (see the AppArmor notes below), traced too
    python3 -c 'import socket; s=socket.create_connection(("10.99.0.12",2525),timeout=10); s.settimeout(5); s.recv(64)' 2>/dev/null; sleep 1
  fi
  [ -n "$sp" ] && { kill $sp; wait $sp 2>/dev/null; }
  # (hostname stays the host's: the unit's ProtectHostname=yes forbids
  # sethostname, though the script still has its own UTS namespace)
  grep -Eq 'pid=1 host=[^ ]+ links=1 loup=0 tmp=probe' <<<"$out" || fail "$what: script not namespaced: $out"
  [ -e /tmp/ns_probe ] && fail "$what: script /tmp not private"
  grep -q 'shadow=n etchostname=n home=n' <<<"$out" || fail "$what: script sees host files: $out"
  grep -q 'connect=n' <<<"$out" || fail "$what: script connected out: $out"
}

systemctl show -p ProtectSystem -p RestrictNamespaces -p NoNewPrivileges $U
[ "$(systemctl show -p ProtectSystem --value $U)" = strict ] || fail "ProtectSystem is not strict"

systemctl start $U; wait_up; check_running start
# A script whose exec fails: the launcher logs from inside its user
# namespace (where it holds capabilities). That error path used to fall
# back to /dev/console (LOG_CONS) and trip the profile's
# "deny capability dac_override" (see the AppArmor checks below).
python3 -c 'import socket; s=socket.create_connection(("10.99.0.12",2525),timeout=10); s.settimeout(5); s.recv(64)' 2>/dev/null; sleep 1
old=$(cat /run/$U/$U.pid)
systemctl restart $U; wait_up; check_running restart
[ "$(cat /run/$U/$U.pid)" != "$old" ] || fail "restart: pid file not updated"
systemctl reload $U || fail "reload failed"; sleep 2; check_running reload
grep -q 'rereading configuration on signal 1' <<<"$(jr)" || fail "reload: SIGHUP not received"
systemctl stop $U
[ -e /run/$U ] && fail "stop: /run/$U left behind"

echo "=== journal"; jr
grep -q 'sandbox-daemon: seccomp allowlist active' <<<"$(jr)" || fail "seccomp allowlist not reported"
grep -q 'sandbox-daemon: Landlock ABI' <<<"$(jr)" || fail "daemon Landlock not active"
grep -q 'script launcher seccomp allowlist active' <<<"$(jr)" || fail "launcher seccomp allowlist not active"
grep -q 'scripts run in their own user, mount, PID, IPC, UTS and network namespaces' <<<"$(jr)" || fail "script namespaces not active"
grep -q 'sandbox: execv(/nonexistent/pm-missing-script)' <<<"$(jr)" || fail "launcher exec-failure path not exercised"
if jr | grep -E 'denied syscall|killed by SIGSYS|WITHOUT|Landlock unavailable|namespaces unavailable'; then fail "denial or warning in the journal"; fi

# Without the sandbox flags: loud warning (and still runs)
mkdir -p /etc/systemd/system/$U.service.d
printf '[Service]\nEnvironment=SANDBOX=\n' > /etc/systemd/system/$U.service.d/nosandbox.conf
systemctl daemon-reload
since=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
systemctl start $U; wait_up
systemctl is-active -q $U || fail "no-sandbox: not active"
grep -q 'WARNING: running under systemd WITHOUT --sandbox-daemon and --sandbox-scripts' <<<"$(jr)" || { fail "no-sandbox: no warning"; jr; }
systemctl stop $U
rm -rf /etc/systemd/system/$U.service.d; systemctl daemon-reload

if [ "${HD_APPARMOR:-}" = require ]; then
  aa-status | sed -n '/profiles are in enforce mode/,/profiles are in complain/p' | grep -E 'pm-script-ns|phantom-mirage-script|enforce mode|complain' || true
  aa-status --json 2>/dev/null | python3 -c 'import json,sys; p=json.load(sys.stdin)["profiles"]; print({k:v for k,v in p.items() if "mirage" in k or "script-ns" in k}); assert p.get("pm-script-ns")=="enforce" and p.get("phantom-mirage-script")=="enforce", p' \
    || fail "AppArmor profiles not loaded in enforce mode"
  sysctl kernel.apparmor_restrict_unprivileged_userns
  [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1 ] || fail "userns restriction is not on, the test proves nothing"
  if journalctl -k --since "$since0" --no-pager | grep -E 'apparmor="(DENIED|ALLOWED)".*profile="(pm-script-ns|phantom-mirage[^"]*)'; then fail "AppArmor denials in the kernel log"; fi
  if dmesg | grep -E 'apparmor="(DENIED|ALLOWED)".*profile="(pm-script-ns|phantom-mirage[^"]*)'; then fail "AppArmor denials in dmesg"; fi
  # explicitly: the launcher never needs DAC overrides (#93 follow-up)
  if { journalctl -k --since "$since0" --no-pager; dmesg; } | grep -E 'capname="dac_(override|read_search)"'; then
    fail "dac_override/dac_read_search requested under the AppArmor profile"
  fi
fi

kill $lsn 2>/dev/null
[ $rc = 0 ] && echo "systemd-unit OK"
exit $rc
