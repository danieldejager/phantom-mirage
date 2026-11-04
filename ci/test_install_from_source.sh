#!/bin/sh
# Checks for the top-level install-from-source.sh: help, bad options, the
# deb mode versus --source-install option checks and the unsupported
# distro exit, all before any package or build step runs.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
fail() { echo "test_install_from_source: FAIL: $*" >&2; cat "$t/o" >&2; exit 1; }

sh -n "$src/install-from-source.sh"

rc=0; sh "$src/install-from-source.sh" --help > "$t/o" 2>&1 || rc=$?
[ $rc = 0 ] || fail "--help rc=$rc"
for o in --with-python --source-install --deb-dir --prefix --yes --no-setup 'sudo phantom-mirage-setup' 'dpkg-buildpackage'; do
	grep -q -- "$o" "$t/o" || fail "--help lacks $o"
done

# --prefix and --with-python only apply to --source-install
rc=0; sh "$src/install-from-source.sh" --prefix /opt/x > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "--prefix accepted in deb mode"
grep -q -- '--prefix only applies with --source-install' "$t/o" || fail "no --prefix deb mode message"
rc=0; sh "$src/install-from-source.sh" --with-python > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "--with-python accepted in deb mode"
grep -q -- '--with-python only applies with --source-install' "$t/o" || fail "no --with-python deb mode message"
rc=0; sh "$src/install-from-source.sh" --source-install --deb-dir /tmp/x > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "--deb-dir accepted with --source-install"
grep -q -- '--deb-dir does not apply with --source-install' "$t/o" || fail "no --deb-dir message"
rc=0; sh "$src/install-from-source.sh" --source-install --prefix '' > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "empty --prefix accepted"

rc=0; sh "$src/install-from-source.sh" --bogus > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "--bogus accepted"
grep -q 'unknown option' "$t/o" || fail "no unknown option message"

printf 'ID=fedora\nPRETTY_NAME="Fedora Linux 42"\n' > "$t/os-release"
rc=0; PM_OS_RELEASE="$t/os-release" sh "$src/install-from-source.sh" --yes > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "unsupported distro accepted"
grep -q 'unsupported distro: Fedora Linux 42' "$t/o" || fail "no unsupported distro message"
rc=0; PM_OS_RELEASE="$t/os-release" sh "$src/install-from-source.sh" --source-install --yes > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] || fail "unsupported distro accepted with --source-install"
grep -q 'unsupported distro: Fedora Linux 42' "$t/o" || fail "no unsupported distro message (--source-install)"

echo "test_install_from_source: all passed"
