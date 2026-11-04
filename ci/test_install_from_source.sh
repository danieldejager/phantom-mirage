#!/bin/sh
# Checks for the top-level source install-from-source.sh: help, bad options and the
# unsupported distro exit, all before any package or build step runs.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
fail() { echo "test_install_from_source: FAIL: $*" >&2; cat "$t/o" >&2; exit 1; }

sh -n "$src/install-from-source.sh"

rc=0; sh "$src/install-from-source.sh" --help > "$t/o" 2>&1 || rc=$?
[ $rc = 0 ] || fail "--help rc=$rc"
grep -q -- '--with-python' "$t/o" || fail "--help lacks --with-python"

rc=0; sh "$src/install-from-source.sh" --bogus > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "--bogus accepted"
grep -q 'unknown option' "$t/o" || fail "no unknown option message"

printf 'ID=fedora\nPRETTY_NAME="Fedora Linux 42"\n' > "$t/os-release"
rc=0; PM_OS_RELEASE="$t/os-release" sh "$src/install-from-source.sh" --yes > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "unsupported distro accepted"
grep -q 'unsupported distro: Fedora Linux 42' "$t/o" || fail "no unsupported distro message"

echo "test_install_from_source: all passed"
