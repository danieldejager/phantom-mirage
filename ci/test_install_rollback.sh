#!/bin/sh
# release/install.sh rollback (#121) with mocked dpkg, apt-get and
# dpkg-repack under a fake root (PM_TEST_ROOT): a failing apt-get install
# must restore the previous packages, config and data and print how to
# restore by hand; a successful install must remove the backup.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FAIL: $*" >&2; [ -f "$t/o" ] && cat "$t/o" >&2; exit 1; }
R=$t/root
mkdir -p "$t/bin" "$t/pkg"
export PM_TEST_ROOT=$R MOCK=$t PATH="$t/bin:$PATH"
# installed packages: $MOCK/db/<pkg> holds the version
cat > "$t/bin/dpkg-query" <<'M'
#!/bin/sh
fmt=$2; shift 2; rc=1
for p in "$@"; do
	[ -f "$MOCK/db/$p" ] || continue; rc=0
	case $fmt in *Package*) printf '%s\t%s\tii \n' "$p" "$(cat "$MOCK/db/$p")" ;; *) printf 'ii ' ;; esac
done
exit $rc
M
cat > "$t/bin/dpkg" <<'M'
#!/bin/sh
case $1 in
--print-architecture) echo arm64 ;;
--purge) shift; for p in "$@"; do case $p in -*) ;; *) rm -f "$MOCK/db/$p" ;; esac; done ;;
esac
M
cat > "$t/bin/dpkg-repack" <<'M'
#!/bin/sh
echo "$1 $(cat "$MOCK/db/$1")" > "${1}_$(cat "$MOCK/db/$1")_arm64.deb"
M
# apt-get install: a .deb holds "pkg version"; fails for new debs when $MOCK/failnew exists
cat > "$t/bin/apt-get" <<'M'
#!/bin/sh
echo "apt-get $*" >> "$MOCK/apt.log"
[ "$1" = install ] || exit 0
for a in "$@"; do case $a in *.deb)
	case $a in ./*) [ -e "$MOCK/failnew" ] && { echo "E: dpkg error" >&2; exit 100; } ;; esac
	set -- $(cat "$a"); echo "$2" > "$MOCK/db/$1"
	mkdir -p "$PM_TEST_ROOT/var/lib/phantom-mirage" ;;
esac; done
M
printf '#!/bin/sh\necho 0\n' > "$t/bin/id"
printf '#!/bin/sh\nexit 0\n' > "$t/bin/chown"
chmod +x "$t/bin/"*

setup_old() {	# a 1.7.0-4 install with config, console state and an event log
	rm -rf "$R" "$t/db" "$t/apt.log" "$t/failnew"; mkdir -p "$t/db"
	echo 1.7.0-4 > "$t/db/phantom-mirage"; echo 1.7.0-4 > "$t/db/phantom-mirage-common"; echo 1.0 > "$t/db/farpd"
	mkdir -p "$R/etc/default" "$R/etc/phantom-mirage" "$R/var/lib/phantom-mirage/console" "$R/var/log/phantom-mirage" "$R/usr/sbin"
	printf 'ID=ubuntu\nVERSION_ID=26.04\nPRETTY_NAME=test\n' > "$R/etc/os-release"
	echo 'PM_NETWORK=10.0.0.0/29' > "$R/etc/default/phantom-mirage"
	echo 'old conf' > "$R/etc/phantom-mirage/phantom-mirage.conf"
	echo 'admin:hash' > "$R/var/lib/phantom-mirage/console/users"
	echo '{"e":1}' > "$R/var/log/phantom-mirage/events.jsonl"
	printf '#!/bin/sh\necho "setup $*" > "$MOCK/setup.log"\n' > "$R/usr/sbin/phantom-mirage-setup"
	chmod +x "$R/usr/sbin/phantom-mirage-setup"
}
# release folder: new debs, uninstall stand-in (removes packages and state)
cd "$t/pkg"
cp "$src/release/install.sh" .
echo "phantom-mirage 1.7.0-5" > phantom-mirage_1.7.0-5_ubuntu26.04_arm64.deb
echo "phantom-mirage-common 1.7.0-5" > phantom-mirage-common_1.7.0-5_ubuntu26.04_all.deb
cat > phantom-mirage-uninstall <<'U'
rm -f "$MOCK/db/phantom-mirage" "$MOCK/db/phantom-mirage-common"
rm -rf "$PM_TEST_ROOT/etc/default/phantom-mirage" "$PM_TEST_ROOT/etc/phantom-mirage" "$PM_TEST_ROOT/var/lib/phantom-mirage" "$PM_TEST_ROOT/var/log/phantom-mirage"
U
sha256sum *.deb > SHA256SUMS
cd - >/dev/null

# 1. failed apt-get install: rolled back
setup_old; touch "$t/failnew"
rc=0; sh "$t/pkg/install.sh" -n 10.0.0.0/29 > "$t/o" 2>&1 || rc=$?
[ $rc = 100 ] || fail "failed install rc=$rc"
[ "$(cat "$t/db/phantom-mirage")" = 1.7.0-4 ] && [ "$(cat "$t/db/phantom-mirage-common")" = 1.7.0-4 ] || fail "old packages not reinstalled"
[ "$(cat "$R/etc/default/phantom-mirage")" = 'PM_NETWORK=10.0.0.0/29' ] || fail "/etc/default not restored"
[ "$(cat "$R/etc/phantom-mirage/phantom-mirage.conf")" = 'old conf' ] || fail "config not restored"
[ "$(cat "$R/var/lib/phantom-mirage/console/users")" = 'admin:hash' ] || fail "console data not restored"
[ "$(cat "$R/var/log/phantom-mirage/events.jsonl")" = '{"e":1}' ] || fail "event log not restored"
grep -q 'rolled back to the previous install (phantom-mirage=1.7.0-4' "$t/o" || fail "no rollback message"
grep -q "backup kept in $R/var/backups/phantom-mirage.keep" "$t/o" || fail "backup location not printed"
grep -q 'tar -C .*/ -xpf .*state.tar' "$t/o" && grep -q 'apt-get install -y .*debs/\*.deb' "$t/o" || fail "manual restore steps not printed"
[ -e "$R/var/backups/phantom-mirage.keep/state.tar" ] || fail "backup removed after failure"
[ ! -e "$t/setup.log" ] || fail "setup ran after a failed install"

# 2. failing phantom-mirage-setup also rolls back
setup_old
printf '#!/bin/sh\nexit 3\n' > "$t/setupfail"; chmod +x "$t/setupfail"
cp "$t/setupfail" "$R/usr/sbin/phantom-mirage-setup"
rc=0; sh "$t/pkg/install.sh" > "$t/o" 2>&1 || rc=$?
[ $rc = 3 ] && [ "$(cat "$t/db/phantom-mirage")" = 1.7.0-4 ] && [ "$(cat "$R/etc/phantom-mirage/phantom-mirage.conf")" = 'old conf' ] || fail "setup failure not rolled back (rc=$rc)"

# 3. success: new version, carried-over data, backup removed
setup_old
rc=0; sh "$t/pkg/install.sh" -n 10.0.0.0/29 > "$t/o" 2>&1 || rc=$?
[ $rc = 0 ] || fail "install rc=$rc"
[ "$(cat "$t/db/phantom-mirage")" = 1.7.0-5 ] || fail "new version not installed"
[ "$(cat "$R/var/lib/phantom-mirage/console/users")" = 'admin:hash' ] && [ "$(cat "$R/etc/default/phantom-mirage")" = 'PM_NETWORK=10.0.0.0/29' ] || fail "kept data lost"
grep -q 'setup -n 10.0.0.0/29' "$t/setup.log" || fail "setup args"
[ ! -e "$R/var/backups/phantom-mirage.keep" ] || fail "backup left after success"
! grep -q 'rolling back' "$t/o" || fail "rollback on success"
grep -q 'warning: SHA256SUMS is unsigned' "$t/o" || fail "no unsigned warning"

# 3b. a public key without a signature is refused before anything is touched
setup_old; echo k > "$t/pkg/SHA256SUMS.pub"
rc=0; sh "$t/pkg/install.sh" > "$t/o" 2>&1 || rc=$?
rm "$t/pkg/SHA256SUMS.pub"
[ $rc = 1 ] && grep -q 'SHA256SUMS.sig is missing' "$t/o" && [ "$(cat "$t/db/phantom-mirage")" = 1.7.0-4 ] || fail "unsigned release with a key (rc=$rc)"

# 4. fresh install failing: nothing to restore, says so
setup_old; rm -f "$t/db/phantom-mirage" "$t/db/phantom-mirage-common"
rm -rf "$R/etc/default/phantom-mirage" "$R/etc/phantom-mirage" "$R/var/lib/phantom-mirage" "$R/var/log/phantom-mirage"
touch "$t/failnew"
rc=0; sh "$t/pkg/install.sh" > "$t/o" 2>&1 || rc=$?
[ $rc = 100 ] && grep -q 'no previous install to restore' "$t/o" || fail "fresh failure (rc=$rc)"
echo "test_install_rollback: all passed"
