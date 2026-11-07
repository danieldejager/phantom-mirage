#!/bin/sh
# A service script is forked after the daemon has already dropped to
# nobody, and cmd_setpriv() calls cmd_droppriv() again. setgroups() then
# returns EPERM. That second call must still run the script when the
# supplementary groups are already only the target gid.
#
# Nightly build 42253311080 (Phantom Mirage Mark 1, commit cb45bc7) died
# here: "cmd_droppriv: setgroups(65534) failed" and the script never ran.
# Needs root, the built ./phantom-mirage, and NET_ADMIN for the 10.99.0.0/24
# route. Skips otherwise so a non-root local run stays green.
set -eu
cd "$(dirname "$0")/.."
D=$PWD

if [ "$(id -u)" != 0 ]; then
	echo "script-droppriv: skipped, needs root"
	exit 0
fi
if [ ! -x ./phantom-mirage ]; then
	echo "script-droppriv: ./phantom-mirage is not built" >&2
	exit 1
fi

W=$(mktemp -d)
hp=
cleanup() {
	if [ -n "$hp" ]; then
		kill "$hp" 2>/dev/null || true
		wait "$hp" 2>/dev/null || true
	fi
	rm -rf "$W"
}
trap cleanup EXIT

printf '%s\n' '#!/bin/sh' 'echo hello-from-script' > "$W/hi.sh"
# The daemon drops to nobody before forking the script.
chmod 755 "$W" "$W/hi.sh"
cat > "$W/c.conf" <<CONF
create default
set default default tcp action block
create linux
set linux personality "Linux 2.6.32"
set linux default tcp action reset
add linux tcp port 2323 "/bin/sh $W/hi.sh"
bind 10.99.0.10 linux
CONF

ip route replace 10.99.0.0/24 dev lo
mkdir -p /var/run /run
./phantom-mirage -d -f "$W/c.conf" -i lo --disable-webserver \
	-p "$D/nmap-os-db" -x "$D/xprobe2.conf" -a "$D/nmap.assoc" \
	-0 "$D/pf.os" -m "$D/nmap-mac-prefixes" > "$W/log" 2>&1 &
hp=$!
i=0
while [ "$i" -lt 40 ]; do
	if grep -q 'Demoting process privileges' "$W/log" 2>/dev/null; then
		break
	fi
	i=$((i + 1))
	sleep 0.25
done

set +e
python3 -c 'import socket; s=socket.create_connection(("10.99.0.10",2323),timeout=5); d=s.recv(64); raise SystemExit(0 if d.startswith(b"hello-from-script") else 1)'
rc=$?
set -e
if [ "$rc" != 0 ] || grep -q 'setgroups(' "$W/log"; then
	echo "script-droppriv: script did not run (rc=$rc)" >&2
	cat "$W/log" >&2
	exit 1
fi
echo "script-droppriv OK"
