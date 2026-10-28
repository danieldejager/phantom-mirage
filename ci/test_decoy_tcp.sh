#!/bin/sh
# ci/test_decoy_tcp.sh: regression test for #123. Builds the Debian
# /etc/phantom-mirage/phantom-mirage.conf with debian/mkconf.sh, runs
# ./phantom-mirage on one end of a veth pair for a /29 of decoys (none
# bound, so all use the "default" template, as on a fresh install), and
# connects from a separate network namespace: a TCP SYN to an open port
# must get a SYN-ACK (connect succeeds), a closed port must get RST, and
# with the pre-#123 config (TCP filtered) nothing answers. If nft is
# present, pm-firewall's ruleset is applied too, to show it does not
# drop decoy TCP. Needs root, NET_ADMIN and SYS_ADMIN (veth, unshare --net;
# no "ip netns add", which a container refuses). Run from the build tree.
set -eu
D=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
HV=pmtcp0 AV=pmtcp1 nspid=
NET=10.98.0.240/29 DECOY=10.98.0.241
pid=
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	[ -n "$pid" ] && wait "$pid" 2>/dev/null || true
	[ -n "${fw:-}" ] && PM_DEFAULT=$T/default PM_CONSOLE_STATE=$T sh "$D/console/pm-firewall" remove || true
	ip link del $HV 2>/dev/null || true
	[ -n "$nspid" ] && kill "$nspid" 2>/dev/null || true
	rm -rf "$T"
}
trap cleanup EXIT INT TERM

unshare --net sleep infinity &
nspid=$!
i=0
while [ "$(readlink /proc/$nspid/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
	i=$((i + 1)); [ $i -lt 50 ] || { echo "unshare --net failed"; exit 1; }
	sleep 0.1
done
inns() { nsenter --net=/proc/$nspid/ns/net "$@"; }
ip link add $HV type veth peer name $AV
ip link set $AV netns $nspid
ip addr add 10.98.0.2/24 dev $HV	# the sensor's own LAN address
ip link set $HV up
inns ip link set lo up
inns ip addr add 10.98.0.1/24 dev $AV
inns ip link set $AV up
# veth leaves TCP checksums to "hardware"; the daemon (rightly) drops bad
# checksums, so make the attacker compute them like a real NIC would
inns ethtool -K $AV tx off >/dev/null 2>&1 || true
# farpd's job on the VM: point the decoy addresses at the sensor's MAC
mac=$(cat /sys/class/net/$HV/address)
inns ip neigh replace $DECOY lladdr "$mac" dev $AV nud permanent

if command -v nft >/dev/null 2>&1; then
	echo "NETWORK=\"$NET\"" > "$T/default"
	PM_DEFAULT=$T/default PM_CONSOLE_STATE=$T sh "$D/console/pm-firewall" apply && fw=1 && echo "ok pm-firewall ruleset applied for $NET"
fi

# probe CONF EXPECT_OPEN EXPECT_CLOSED: EXPECT_* = OPEN|REFUSED|TIMEOUT
probe() {
	"$D/phantom-mirage" -d -f "$1" -i $HV --disable-webserver \
	  -p "$D/fingerprints/columbo-v1.db" -x "$D/xprobe2.conf" -a "$D/nmap.assoc" \
	  -0 "$D/pf.os" -m "$D/nmap-mac-prefixes" $NET > "$T/log" 2>&1 &
	pid=$!
	sleep 2
	r=$(inns python3 -c '
import socket, errno, sys
for p in (22, 8080):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect((sys.argv[1], p)); print("OPEN", end=" ")
    except ConnectionRefusedError: print("REFUSED", end=" ")
    except OSError: print("TIMEOUT", end=" ")
' $DECOY)
	kill $pid; wait $pid 2>/dev/null || true; pid=
	if [ "$r" != "$2 $3 " ]; then
		echo "FAIL $1: port 22/8080 got '$r', want '$2 $3'"; cat "$T/log"; exit 1
	fi
	echo "ok $(basename "$1"): 22 $2, 8080 $3"
}

sh "$D/debian/mkconf.sh" "$D/config.sample" "$T/new.conf"
probe "$T/new.conf" OPEN REFUSED

# negative control: the pre-#123 Debian config (TCP filtered). The
# personality sed matches mkconf.sh (a no-op now that config.sample names
# ws2022-fwoff; kept for older samples). TCP stays filtered, so nothing may
# answer.
sed -e 's/^set default default icmp action filtered$/set default default icmp action open/' \
    -e 's/^set windows personality "OpenBSD 4.0 (x86)"$/set windows personality "ws2022-fwoff"/' \
    -e 's/^bind 192\.168\.3\.137 windows/# &/' "$D/config.sample" > "$T/old.conf"
grep -q '^set windows personality "ws2022-fwoff"$' "$T/old.conf"
grep -q '^set default default tcp action filtered$' "$T/old.conf"
probe "$T/old.conf" TIMEOUT TIMEOUT
echo "PASS: decoy TCP SYN to an open port gets SYN-ACK (#123)"
