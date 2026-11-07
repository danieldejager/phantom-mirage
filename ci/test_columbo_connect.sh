#!/bin/sh
# A normal TCP client must complete a handshake with the packaged
# personality ubuntu2404 (columbo-v1.db) and reach a service script.
# The systemd jobs failed here: the SYN-ACK copied our own TSval into
# TSecr, the client reset it, and ci/systemd_unit.sh reported
# "script not namespaced" with an empty probe.
# Needs root, ./phantom-mirage, and NET_ADMIN. Skips otherwise.
set -eu
cd "$(dirname "$0")/.."
D=$PWD

if [ "$(id -u)" != 0 ]; then
	echo "columbo-connect: skipped, needs root"
	exit 0
fi
if [ ! -x ./phantom-mirage ]; then
	echo "columbo-connect: ./phantom-mirage is not built" >&2
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

printf '%s\n' '#!/bin/sh' 'echo hello-from-columbo' > "$W/hi.sh"
chmod 755 "$W" "$W/hi.sh"
cat > "$W/c.conf" <<CONF
create default
set default default tcp action reset
create linux
set linux personality "ubuntu2404"
set linux default tcp action reset
add linux tcp port 2424 "/bin/sh $W/hi.sh"
bind 10.99.0.12 linux
CONF

ip route replace 10.99.0.0/24 dev lo
mkdir -p /var/run /run
./phantom-mirage -d -f "$W/c.conf" -i lo --disable-webserver \
	-p "$D/fingerprints/columbo-v1.db" -x "$D/xprobe2.conf" \
	-a "$D/nmap.assoc" -0 "$D/pf.os" -m "$D/nmap-mac-prefixes" \
	>"$W/log" 2>&1 &
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
python3 -c 'import socket; s=socket.create_connection(("10.99.0.12",2424),timeout=5); s.settimeout(3); d=s.recv(64); raise SystemExit(0 if d.startswith(b"hello-from-columbo") else 1)'
rc=$?
set -e
if [ "$rc" != 0 ]; then
	echo "columbo-connect: ubuntu2404 handshake failed (rc=$rc)" >&2
	cat "$W/log" >&2
	exit 1
fi
echo "columbo-connect OK"
