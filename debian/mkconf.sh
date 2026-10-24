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
# #129: the default template is one Linux (Ubuntu 24.04) host: 21/22/23/80
# open, everything else RST (443/445/3389 too: no believable TLS/SMB/RDP
# without a real implementation; a Windows host belongs in its own
# template bound to its own IP). PM_DECOY picks what 21/22/23/80 do:
# "banners" (default) runs scripts/mirage/banner.sh (static banners,
# shell builtins only, no network); "tripwire" leaves them silent. The
# other mode's lines stay in the config as comments to switch by hand.
# PM_SCRIPTS overrides the installed scripts dir (ci/test_decoy_tcp.sh).
set -eu
in=$1 out=$2
b="/bin/sh ${PM_SCRIPTS:-/usr/share/phantom-mirage/scripts}/mirage/banner.sh"
case ${PM_DECOY:-banners} in
banners) c='' o='#' ;;
tripwire) c='#' o='' ;;
*) echo "mkconf.sh: PM_DECOY must be tripwire or banners" >&2; exit 1 ;;
esac
# escaped for the sed replacement below
e=$(printf '%s\n' "$b" | sed 's/[\/&]/\\&/g')
lines=
for ps in 21:ftp 22:ssh 23:telnet 80:http; do
	lines="$lines$o"'add default tcp port '"${ps%:*}"' open\
'"$c"'add default tcp port '"${ps%:*}"' "'"$e ${ps#*:}"'"\
'
done
sed -e 's/^set default default icmp action filtered$/set default default icmp action open/' \
    -e 's/^set default default tcp action filtered$/set default default tcp action reset\
# decoy ports (#129): banners or silent tripwires, see debian\/mkconf.sh;\
# to switch a port, comment one of its two lines and uncomment the other\
'"${lines%?}"'/' \
    -e 's/^bind 192\.168\.3\.137 windows/# &/' "$in" > "$out.tmp"
grep -q '^set default default icmp action open$' "$out.tmp"
grep -q '^set default default tcp action reset$' "$out.tmp"
grep -q '^add default tcp port 22 \(open\|"/bin/sh .*/mirage/banner.sh ssh"\)$' "$out.tmp"
if grep -q '^add default tcp port \(443\|445\|3389\) ' "$out.tmp"; then exit 1; fi
if grep -q '^bind 192\.168\.3\.137' "$out.tmp"; then exit 1; fi
mv "$out.tmp" "$out"
