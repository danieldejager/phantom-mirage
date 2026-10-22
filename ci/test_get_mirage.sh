#!/bin/sh
# release/get-mirage.sh with mocked gh, sudo and dpkg (#110).
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FAIL: $*" >&2; [ -f "$t/o" ] && cat "$t/o" >&2; exit 1; }
mkdir -p "$t/bin" "$t/rel"
printf 'ID=ubuntu\nVERSION_ID=26.04\n' > "$t/os"
export PM_OS_RELEASE=$t/os MOCK=$t PATH="$t/bin:$PATH"
printf '#!/bin/sh\necho arm64\n' > "$t/bin/dpkg"
printf '#!/bin/sh\necho "sudo $*" >> "$MOCK/sudo.log"\n' > "$t/bin/sudo"
# gh mock: auth status from $MOCK/authok; releases from $MOCK/releases.json;
# per-tag assets from $MOCK/rel/<tag>/ (files = assets)
cat > "$t/bin/gh" <<'G'
#!/bin/sh
echo "gh $*" >> "$MOCK/gh.log"
case "$1 $2" in
"auth status") [ -e "$MOCK/authok" ] ;;
"api repos/danieldejager/phantom-mirage/releases") cat "$MOCK/releases.json" | python3 -c '
import json,sys; r=[x for x in json.load(sys.stdin) if not x["draft"]]; print(r[0]["tag_name"] if r else "")' ;;
"api repos/danieldejager/phantom-mirage/releases/tags/"*)
	tag=${2##*/}; [ -d "$MOCK/rel/$tag" ] || exit 1; ls -1 "$MOCK/rel/$tag" ;;
"release download")
	tag=$3; shift 3; dir=
	while [ $# -gt 0 ]; do case $1 in -D) dir=$2; shift 2 ;; -p) cp "$MOCK/rel/$tag/$2" "$dir/"; shift 2 ;; *) shift ;; esac; done ;;
*) echo "unexpected gh $*" >&2; exit 9 ;;
esac
G
chmod +x "$t/bin/"*
mkrel() {	# mkrel TAG [corrupt]
	d=$t/rel/$1; mkdir -p "$d"
	echo "run $1" > "$d/phantom-mirage_${1#v}_ubuntu26.04_arm64.run"
	echo "run $1 amd64" > "$d/phantom-mirage_${1#v}_ubuntu26.04_amd64.run"
	(cd "$d" && sha256sum *.run > SHA256SUMS)
	[ -z "${2:-}" ] || echo tampered >> "$d/phantom-mirage_${1#v}_ubuntu26.04_arm64.run"
}
gm() { rm -f "$t/sudo.log" "$t/gh.log"; rc=0; sh "$src/release/get-mirage.sh" "$@" > "$t/o" 2>&1 || rc=$?; }

# 1. not authenticated
gm
[ $rc = 1 ] && grep -q 'run gh auth login first' "$t/o" || fail "not-authenticated"
[ ! -e "$t/sudo.log" ] || fail "sudo called when not authenticated"
touch "$t/authok"

# 2. newest release is a prerelease (and a draft above it is skipped)
mkrel v1.7.0-3; mkrel v1.7.0-4
cat > "$t/releases.json" <<'J'
[{"tag_name":"v1.7.0-5","draft":true,"prerelease":false},
 {"tag_name":"v1.7.0-4","draft":false,"prerelease":true},
 {"tag_name":"v1.7.0-3","draft":false,"prerelease":false}]
J
gm -i veth-h -n 10.77.0.248/29
[ $rc = 0 ] || fail "prerelease rc=$rc"
grep -q 'sudo sh .*/phantom-mirage_1.7.0-4_ubuntu26.04_arm64.run -i veth-h -n 10.77.0.248/29$' "$t/sudo.log" || fail "prerelease not picked / args"
! grep -q 'auth token\|--with-token' "$t/gh.log" || fail "token handling"

# 3. --tag
gm --tag v1.7.0-3 -i eth0
[ $rc = 0 ] && grep -q 'phantom-mirage_1.7.0-3_ubuntu26.04_arm64.run -i eth0$' "$t/sudo.log" || fail "--tag"
! grep -q 'gh api repos/danieldejager/phantom-mirage/releases$' "$t/gh.log" || fail "--tag still listed releases"

# 4. checksum mismatch: sudo must not be called
mkrel v1.7.0-6 corrupt
gm --tag v1.7.0-6
[ $rc != 0 ] && grep -q 'checksum mismatch' "$t/o" || fail "checksum mismatch not refused"
[ ! -e "$t/sudo.log" ] || fail "sudo called after checksum mismatch"

# 5. no matching asset
mkdir -p "$t/rel/v1.7.0-7"; echo x > "$t/rel/v1.7.0-7/phantom-mirage_1.7.0-7_debian13_amd64.run"
(cd "$t/rel/v1.7.0-7" && sha256sum *.run > SHA256SUMS)
gm --tag v1.7.0-7
[ $rc != 0 ] && grep -q 'has no .run for ubuntu26.04/arm64' "$t/o" || fail "no matching asset"
[ ! -e "$t/sudo.log" ] || fail "sudo called without an asset"

# 6. piped through sh works too
rm -f "$t/sudo.log"; rc=0; sh < "$src/release/get-mirage.sh" > "$t/o" 2>&1 || rc=$?
[ $rc = 0 ] && grep -q '1.7.0-4_ubuntu26.04_arm64.run$' "$t/sudo.log" || fail "| sh"
echo "test_get_mirage: all passed"
