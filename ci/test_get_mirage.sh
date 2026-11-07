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
"api -H") [ "$4" = repos/danieldejager/phantom-mirage/contents/release/SHA256SUMS.pub ] || exit 9
	[ -e "$MOCK/pub" ] || { echo '{"message":"Not Found"}'; exit 1; }; cat "$MOCK/pub" ;;
"api repos/danieldejager/phantom-mirage/releases")
	[ "$3" = --jq ] || exit 9; jq -r "$4" "$MOCK/releases.json" ;;
"api repos/danieldejager/phantom-mirage/releases/tags/"*)
	tag=${2##*/}; [ -d "$MOCK/rel/$tag" ] || exit 1; ls -1 "$MOCK/rel/$tag" ;;
"release download")
	tag=$3; shift 3; dir=
	while [ $# -gt 0 ]; do case $1 in -D) dir=$2; shift 2 ;; -p) cp "$MOCK/rel/$tag/$2" "$dir/"; shift 2 ;; *) shift ;; esac; done ;;
*) echo "unexpected gh $*" >&2; exit 9 ;;
esac
G
# cosign mock: the signature "verifies" when it reads "good <sha256 of SHA256SUMS>"
cat > "$t/bin/cosign" <<'C'
#!/bin/sh
echo "cosign $*" >> "$MOCK/cosign.log"
[ "$1 $2 $4" = "verify-blob --key --signature" ] || exit 9
sig=$5; blob=$7
[ "$(cat "$sig")" = "good $(sha256sum < "$blob" | cut -d' ' -f1)" ]
C
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

# 2. newest by published_at is a prerelease; a draft is skipped, and an
#    older "Latest" release listed first by the API is not picked
mkrel v1.7.0-3; mkrel v1.7.0-4
cat > "$t/releases.json" <<'J'
[{"tag_name":"v1.7.0","draft":false,"prerelease":false,"published_at":"2026-10-22T05:59:53Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v1.7.0-5","draft":true,"prerelease":false,"published_at":null,"assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v1.7.0-4","draft":false,"prerelease":true,"published_at":"2026-10-22T23:04:33Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v1.7.0-3","draft":false,"prerelease":true,"published_at":"2026-10-22T21:38:34Z","assets":[{"name":"SHA256SUMS"}]}]
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
grep -q 'warning: SHA256SUMS is unsigned' "$t/o" || fail "no unsigned warning"

# 7. --stable skips prereleases; --prerelease is the default
mkrel v1.7.0
gm --stable -i eth0
[ $rc = 0 ] && grep -q 'phantom-mirage_1.7.0_ubuntu26.04_arm64.run -i eth0$' "$t/sudo.log" || fail "--stable"
gm --prerelease
[ $rc = 0 ] && grep -q '1.7.0-4_ubuntu26.04_arm64.run$' "$t/sudo.log" || fail "--prerelease"
echo '[{"tag_name":"v2.0.0-1","draft":false,"prerelease":true,"published_at":"2026-10-22T05:59:53Z","assets":[{"name":"SHA256SUMS"}]}]' > "$t/rel.json"
cp "$t/releases.json" "$t/releases.bak"; cp "$t/rel.json" "$t/releases.json"
gm --stable
[ $rc != 0 ] && grep -q 'no published stable release found' "$t/o" || fail "--stable without stable release"
cp "$t/releases.bak" "$t/releases.json"

# 8. signing key published: good signature installs, bad/missing refuses
echo "fake public key" > "$t/pub"
gm --tag v1.7.0-3
[ $rc != 0 ] && grep -q 'has no SHA256SUMS.sig but a signing key is published' "$t/o" || fail "unsigned release accepted with a key"
[ ! -e "$t/sudo.log" ] || fail "sudo called for an unsigned release"
echo "good $(sha256sum < "$t/rel/v1.7.0-3/SHA256SUMS" | cut -d' ' -f1)" > "$t/rel/v1.7.0-3/SHA256SUMS.sig"
gm --tag v1.7.0-3
[ $rc = 0 ] && grep -q 'SHA256SUMS signature OK' "$t/o" && grep -q '1.7.0-3_ubuntu26.04_arm64.run$' "$t/sudo.log" || fail "good signature"
! grep -q 'unsigned' "$t/o" || fail "unsigned warning with a good signature"
echo "good 0000" > "$t/rel/v1.7.0-3/SHA256SUMS.sig"
gm --tag v1.7.0-3
[ $rc != 0 ] && grep -q 'signature does not verify' "$t/o" || fail "bad signature accepted"
[ ! -e "$t/sudo.log" ] || fail "sudo called after a bad signature"
rm "$t/pub"; echo "good $(sha256sum < "$t/rel/v1.7.0-3/SHA256SUMS" | cut -d' ' -f1)" > "$t/rel/v1.7.0-3/SHA256SUMS.sig"
echo k > "$t/local.pub"; PM_SIGNING_PUBKEY=$t/local.pub gm --tag v1.7.0-3
[ $rc = 0 ] && grep -q 'SHA256SUMS signature OK' "$t/o" || fail "PM_SIGNING_PUBKEY"

# 9. A newer release with no assets is not an automatic install target.
#    mark-1 is that release: not a prerelease, published after v1.7.0,
#    and empty. --tag can still name it and then fail closed.
cp "$t/releases.json" "$t/releases.bak"
cat > "$t/releases.json" <<'J'
[{"tag_name":"v1.7.0","draft":false,"prerelease":false,"published_at":"2026-10-22T05:59:53Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"mark-1","draft":false,"prerelease":false,"published_at":"2026-11-07T11:22:07Z","assets":[]},
 {"tag_name":"v1.7.0-4","draft":false,"prerelease":true,"published_at":"2026-10-22T23:04:33Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v9.9.9-9","draft":false,"prerelease":true,"published_at":"2026-12-01T00:00:00Z","assets":[]}]
J
gm --stable -i eth0
[ $rc = 0 ] && grep -q 'phantom-mirage_1.7.0_ubuntu26.04_arm64.run -i eth0$' "$t/sudo.log" || fail "assetless mark-1 selected as stable"
gm
[ $rc = 0 ] && grep -q '1.7.0-4_ubuntu26.04_arm64.run$' "$t/sudo.log" || fail "assetless prerelease selected"
mkdir -p "$t/rel/mark-1"
gm --tag mark-1
[ $rc != 0 ] && grep -q 'release mark-1 has no .run' "$t/o" || fail "--tag mark-1 did not fail closed"
[ ! -e "$t/sudo.log" ] || fail "sudo called for assetless --tag"
echo "test_get_mirage: all passed"
