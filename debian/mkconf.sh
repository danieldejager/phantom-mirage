#!/bin/sh
# debian/mkconf.sh IN OUT: turn config.sample into the Debian
# /etc/phantom-mirage/phantom-mirage.conf. Used by debian/rules and by
# ci/test_decoy_tcp.sh, so the test checks exactly what ships.
#
# The sample's only bind (192.168.3.137 windows) is commented out below
# (#110), so every decoy in NETWORK falls back to the "default" template.
# That template must therefore look like a host: ICMP echo answered
# (#110) and some TCP ports open with RST for the rest (#123). Before
# #123 TCP stayed "filtered", so decoys answered ping but no port ever
# answered a SYN.
set -eu
in=$1 out=$2
sed -e 's/^set default default icmp action filtered$/set default default icmp action open/' \
    -e 's/^set default default tcp action filtered$/set default default tcp action reset\
add default tcp port 21 open\
add default tcp port 22 open\
add default tcp port 23 open\
add default tcp port 80 open\
add default tcp port 443 open\
add default tcp port 445 open\
add default tcp port 3389 open/' \
    -e 's/^bind 192\.168\.3\.137 windows/# &/' "$in" > "$out.tmp"
grep -q '^set default default icmp action open$' "$out.tmp"
grep -q '^set default default tcp action reset$' "$out.tmp"
grep -q '^add default tcp port 22 open$' "$out.tmp"
if grep -q '^bind 192\.168\.3\.137' "$out.tmp"; then exit 1; fi
mv "$out.tmp" "$out"
