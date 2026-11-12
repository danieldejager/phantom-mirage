#!/bin/sh
# phantom-mirage-setup asks on a terminal before it enables or starts
# anything. With no terminal (the one-line install) it enables and starts.
# Journal lines shown on a failed start lose control chars.
# Everything is stubbed: no root, no systemd, no network changes.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
setup=$src/debian/scripts/phantom-mirage-setup
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
fail() { echo "test_setup_confirm: FAIL: $*" >&2; cat "$t/o" >&2 2>/dev/null || true; exit 1; }
mkdir -p "$t/bin" "$t/lib"
stub() { printf '#!/bin/sh\n%s\n' "$2" > "$t/bin/$1"; chmod +x "$t/bin/$1"; }
stub id 'echo 0'
stub ip 'case "$*" in
*"route show default"*) echo "default via 10.0.0.1 dev lo" ;;
*"addr show"*) echo "1: lo    inet 10.0.0.5/24 brd 10.0.0.255 scope global lo" ;;
esac'
stub systemctl 'echo "systemctl $*" >> "$PM_TEST_LOG"; case "$*" in "restart phantom-mirage") exit "${PM_RESTART_RC:-0}" ;; esac; exit 0'
stub journalctl 'printf "line one\033[31m red\033]0;title\007 end\n"'
stub sleep 'exit 0'
printf '#!/bin/sh\nexit 0\n' > "$t/lib/check-default"; chmod +x "$t/lib/check-default"
run() {
	: > "$t/log"; rc=0
	PATH="$t/bin:$PATH" PM_TESTING=1 PM_NO_BANNER=1 PM_LIBDIR="$t/lib" PM_TEST_LOG="$t/log" \
		PM_DEFAULT="$t/default" PM_FDEFAULT="$t/farpd" "$@" > "$t/o" 2>&1 || rc=$?
}

# no terminal, no --yes: config written, then the sensor is enabled and started
run sh "$setup" -i lo -n 10.0.0.248/29 < /dev/null
[ $rc = 0 ] || fail "non-interactive rc=$rc"
grep -q '^INTERFACE="lo"' "$t/default" || fail "config not written"
grep -q 'interface: lo' "$t/o" || fail "no interface in the plan"
grep -q 'subnet:    10.0.0.5/24' "$t/o" || fail "no subnet in the plan"
grep -q 'gateway:   10.0.0.1' "$t/o" || fail "no gateway in the plan"
grep -q 'decoys:    10.0.0.248/29' "$t/o" || fail "no /29 in the plan"
grep -q 'no terminal: enabling and starting without asking' "$t/o" || fail "no autostart message"
grep -q '^systemctl enable phantom-mirage$' "$t/log" || fail "sensor not enabled"
grep -q '^systemctl restart phantom-mirage$' "$t/log" || fail "sensor not started"

# re-run keeps the existing INTERFACE/NETWORK and starts again (still no terminal)
run sh "$setup" < /dev/null
grep -q 'no terminal: enabling and starting without asking' "$t/o" || fail "re-run did not autostart"
grep -q '^systemctl restart phantom-mirage$' "$t/log" || fail "re-run did not start"

# --yes: explicit opt in starts the sensor
run sh "$setup" --yes -i lo -n 10.0.0.248/29 < /dev/null
[ $rc = 0 ] || fail "--yes rc=$rc"
grep -q '^systemctl restart phantom-mirage$' "$t/log" || fail "--yes did not start the sensor"

# on a terminal: "n" refuses, Enter starts
if command -v script >/dev/null 2>&1; then
	printf 'n\n' | run script -qec "sh '$setup' -i lo -n 10.0.0.248/29" /dev/null
	grep -q 'enable and start phantom-mirage now? \[Y/n\]' "$t/o" || fail "no terminal question"
	grep -q 'answered no' "$t/o" || fail "n not honoured"
	grep -q 'systemctl' "$t/log" && fail "started after n"
	printf '\n' | run script -qec "sh '$setup' -i lo -n 10.0.0.248/29" /dev/null
	grep -q '^systemctl restart phantom-mirage$' "$t/log" || fail "Enter did not start"
	run script -qec "sh '$setup' -i lo -n 10.0.0.248/29" /dev/null < /dev/null
	grep -q 'systemctl' "$t/log" && fail "EOF on the terminal started services"
else
	echo "test_setup_confirm: skipped the terminal checks (needs script(1))"
fi

# failed start: journal lines printed without control characters
PM_RESTART_RC=1 run sh "$setup" --yes -i lo -n 10.0.0.248/29 < /dev/null
[ $rc = 1 ] || fail "failed start rc=$rc"
grep -q 'Last 20 journal lines' "$t/o" || fail "no journal heading"
grep -q 'line one\[31m red\]0;title end' "$t/o" || fail "journal line not shown cleaned"
LC_ALL=C grep -q "$(printf '\033')" "$t/o" && fail "escape character reached the terminal"
LC_ALL=C grep -q "$(printf '\007')" "$t/o" && fail "BEL reached the terminal"
echo "test_setup_confirm: all passed"
