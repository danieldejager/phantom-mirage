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

# Default (deb) path end to end with stubs: nothing is built or installed
# for real. sudo and apt-get only log; dpkg-buildpackage writes two fake
# .debs to the parent of the build copy, as the real one does.
mkdir "$t/bin"
printf 'ID=ubuntu\nPRETTY_NAME="Ubuntu 26.04 LTS"\n' > "$t/ubuntu"
stub() { printf '#!/bin/sh\n%s\n' "$2" > "$t/bin/$1"; chmod +x "$t/bin/$1"; }
stub sudo 'echo "sudo $*" >> "$PM_TEST_LOG"'
stub apt-get 'echo "apt-get $*" >> "$PM_TEST_LOG"'
stub apt-cache 'exit 0'
stub dpkg-query 'exit 1'
stub dpkg-parsechangelog 'echo 9.9-1'
stub dpkg 'echo amd64'
stub dpkg-buildpackage 'echo stub > ../phantom-mirage_9.9-1_amd64.deb; echo stub > ../phantom-mirage-common_9.9-1_all.deb'
run() {
	: > "$t/log"
	rc=0
	PATH="$t/bin:$PATH" PM_TEST_LOG="$t/log" PM_OS_RELEASE="$t/ubuntu" TMPDIR="$t" \
		sh "$src/install-from-source.sh" "$@" > "$t/o" 2>&1 < /dev/null || rc=$?
}
installed_from_temp() {
	grep -q "apt-get install -y --reinstall $t/phantom-mirage-build\.[^/]*/phantom-mirage_9.9-1_amd64.deb" "$t/log" ||
		fail "the .debs were not installed from the private temp dir"
}
if [ "$(id -u)" = 0 ]; then
	echo "test_install_from_source: running as root, sudo stub not exercised"
fi

# no terminal and no --yes: refuses before anything runs as root
run --deb-dir "$t/out0"
[ $rc != 0 ] || fail "ran without --yes and without a terminal"
grep -q 'rerun with --yes' "$t/o" || fail "no --yes hint"
[ ! -s "$t/log" ] || fail "something ran as root unasked"

# happy path: fresh output dir is created and gets the copies
run --yes --deb-dir "$t/out1"
[ $rc = 0 ] || fail "stubbed default path rc=$rc"
grep -q 'apt-get update' "$t/log" || fail "no apt-get update"
installed_from_temp
[ -f "$t/out1/phantom-mirage_9.9-1_amd64.deb" ] && [ -f "$t/out1/phantom-mirage-common_9.9-1_all.deb" ] ||
	fail "debs not copied to the output dir"
[ -z "$(find "$t/out1" -maxdepth 0 -perm /022)" ] || fail "output dir created group or other writable"
grep -q 'next step: sudo phantom-mirage-setup' "$t/o" || fail "no next step"
ls "$t" | grep -q '^phantom-mirage-build' && fail "temp build dir left behind"

# refused: symlinked output dir; install still done from the temp dir
mkdir "$t/real"
ln -s "$t/real" "$t/out2"
run --yes --deb-dir "$t/out2"
[ $rc = 3 ] || fail "symlink output dir: rc=$rc, want 3"
grep -q "refusing $t/out2: it is a symlink" "$t/o" || fail "no symlink refusal"
installed_from_temp
[ -z "$(ls -A "$t/real")" ] || fail "copied through the symlink"

# refused: group or other writable output dir
mkdir "$t/out3"; chmod 0777 "$t/out3"
run --yes --deb-dir "$t/out3"
[ $rc = 3 ] || fail "writable output dir: rc=$rc, want 3"
grep -q "refusing $t/out3: writable by group or others" "$t/o" || fail "no writable refusal"
installed_from_temp
[ -z "$(ls -A "$t/out3")" ] || fail "copied into a writable dir"

# refused: output dir owned by someone else (/ is owned by root)
if [ "$(id -u)" != 0 ]; then
	run --yes --deb-dir /
	[ $rc = 3 ] || fail "foreign owned output dir: rc=$rc, want 3"
	grep -q "refusing /: owned by uid 0" "$t/o" || fail "no owner refusal"
	installed_from_temp
else
	echo "test_install_from_source: skipped the foreign owner check (needs a non root user)"
fi

echo "test_install_from_source: all passed"
