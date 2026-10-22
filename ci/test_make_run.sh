#!/bin/sh
# release/make-run.sh: build a .run from fake .debs, then check the header:
# right distro/arch runs install.sh with the arguments, wrong distro or
# arch and a corrupted payload are refused, the temp dir is cleaned up.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$t/tree/release" "$t/tree/debian/scripts" "$t/debs" "$t/bin" "$t/out"
cp "$src/release/make-run.sh" "$t/tree/release/"
# stand-in install.sh: records its args and cwd contents
cat > "$t/tree/release/install.sh" <<'I'
#!/bin/sh
cd "$(dirname "$0")"
sha256sum -c --quiet SHA256SUMS
echo "fake-install args: $*"
echo "fake-install cwd: $PWD" > "$PM_TEST_LOG"
ls >> "$PM_TEST_LOG"
I
printf '#!/bin/sh\necho uninstall\n' > "$t/tree/debian/scripts/phantom-mirage-uninstall"
echo main > "$t/debs/phantom-mirage_9.9.9-1_ubuntu26.04_arm64.deb"
echo common > "$t/debs/phantom-mirage-common_9.9.9-1_ubuntu26.04_all.deb"
run=$(sh "$t/tree/release/make-run.sh" "$t/debs" ubuntu26.04 arm64 "$t/out")
[ "$run" = "$t/out/phantom-mirage_9.9.9-1_ubuntu26.04_arm64.run" ] || fail "name: $run"
head -c 2 "$run" | grep -q '#!' || fail "no shebang"
printf '#!/bin/sh\necho "${PM_ARCH_MOCK:-arm64}"\n' > "$t/bin/dpkg"
printf '#!/bin/sh\n[ "$1" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n' > "$t/bin/id"
chmod +x "$t/bin/"*
printf 'ID=ubuntu\nVERSION_ID=26.04\n' > "$t/os26"
printf 'ID=debian\nVERSION_ID=13\n' > "$t/osdeb"
export PATH="$t/bin:$PATH" PM_TEST_LOG="$t/log"

PM_OS_RELEASE=$t/os26 sh "$run" -i veth-h -n 10.77.0.248/29 > "$t/o" 2>&1 || { cat "$t/o"; fail "good run failed"; }
grep -q 'fake-install args: -i veth-h -n 10.77.0.248/29' "$t/o" || { cat "$t/o"; fail "args not passed"; }
for f in install.sh phantom-mirage-uninstall SHA256SUMS phantom-mirage_9.9.9-1_ubuntu26.04_arm64.deb phantom-mirage-common_9.9.9-1_ubuntu26.04_all.deb; do
	grep -qx "$f" "$t/log" || fail "$f not extracted"
done
d=$(sed -n 's/^fake-install cwd: //p' "$t/log")
[ ! -e "$d" ] || fail "temp dir $d left behind"

rc=0; PM_OS_RELEASE=$t/osdeb sh "$run" > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] && grep -q 'is for ubuntu26.04, but this system is debian13' "$t/o" || { cat "$t/o"; fail "wrong distro accepted"; }
rc=0; PM_ARCH_MOCK=amd64 PM_OS_RELEASE=$t/os26 sh "$run" > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] && grep -q 'is for arm64, but this system is amd64' "$t/o" || { cat "$t/o"; fail "wrong arch accepted"; }

cp "$run" "$t/bad.run"; printf 'x' >> "$t/bad.run"
rc=0; PM_OS_RELEASE=$t/os26 sh "$t/bad.run" > "$t/o" 2>&1 || rc=$?
[ $rc != 0 ] && grep -q 'payload checksum mismatch' "$t/o" || { cat "$t/o"; fail "corrupt payload accepted"; }
! grep -q fake-install "$t/o" || fail "install.sh ran on a corrupt payload"

# install.sh failure propagates
sed -i 's/^echo "fake-install args.*/exit 7/' "$t/tree/release/install.sh"
run=$(sh "$t/tree/release/make-run.sh" "$t/debs" ubuntu26.04 arm64 "$t/out")
rc=0; PM_OS_RELEASE=$t/os26 sh "$run" > "$t/o" 2>&1 || rc=$?
[ $rc = 7 ] || fail "install.sh exit status lost (rc=$rc)"
echo "test_make_run: all passed"
