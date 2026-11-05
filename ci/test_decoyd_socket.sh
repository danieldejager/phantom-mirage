#!/bin/sh
# pm-decoyd-socket (postinst upgrade path) against a fake systemctl that
# logs its calls: no console and no socket means no change; a console
# already set up, or an enabled socket, gets the socket enabled and
# restarted and the old helper stopped; a failing systemctl never fails.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
s=$here/debian/scripts/pm-decoyd-socket
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
cat > "$d/sc" <<'X'
#!/bin/sh
echo "$*" >> "$LOG"
case "$*" in
"is-enabled --quiet phantom-mirage-console.service") [ -e "$STATE/console" ] ;;
"is-enabled --quiet pm-decoyd.socket") [ -e "$STATE/socket" ] ;;
*) [ ! -e "$STATE/fail" ] ;;
esac
X
chmod +x "$d/sc"
export PM_SYSTEMCTL="$d/sc" LOG="$d/log" STATE="$d"

: > "$LOG"; "$s"
if grep -q '^enable\|^restart\|^stop' "$LOG"; then echo "changed units without a console" >&2; exit 1; fi

touch "$d/console"; : > "$LOG"; "$s" >/dev/null
grep -qx 'enable pm-decoyd.socket' "$LOG"
grep -qx 'stop pm-decoyd.service' "$LOG"
grep -qx 'restart pm-decoyd.socket' "$LOG"
# idempotent: same calls again, still success
: > "$LOG"; "$s" >/dev/null; grep -qx 'restart pm-decoyd.socket' "$LOG"

rm "$d/console"; touch "$d/socket"; : > "$LOG"; "$s" >/dev/null
grep -qx 'restart pm-decoyd.socket' "$LOG"

touch "$d/fail"; "$s" 2> "$d/err" >/dev/null
grep -q 'enable --now pm-decoyd.socket' "$d/err"
echo "test_decoyd_socket: ok"
