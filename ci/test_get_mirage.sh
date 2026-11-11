#!/bin/sh
# release/get-mirage.sh with mocked curl, dpkg and the .run (#110).
# Signature cases use a real openssl key, the same check as production.
set -eu
src=$(cd "$(dirname "$0")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail() { echo "FAIL: $*" >&2; [ -f "$t/o" ] && cat "$t/o" >&2; exit 1; }
command -v jq >/dev/null || fail "jq is required"
command -v openssl >/dev/null || fail "openssl is required"
mkdir -p "$t/bin" "$t/rel"
printf 'ID=ubuntu\nVERSION_ID=26.04\nPRETTY_NAME="Ubuntu 26.04"\n' > "$t/os"
openssl ecparam -name prime256v1 -genkey -noout -out "$t/key.pem"
openssl ec -in "$t/key.pem" -pubout -out "$t/pub"
export PM_OS_RELEASE=$t/os PM_SIGNING_PUBKEY=$t/pub PM_GET_MIRAGE_TEST=1 MOCK=$t PATH="$t/bin:$PATH"
printf '#!/bin/sh\necho arm64\n' > "$t/bin/dpkg"
# curl mock. Last http(s) argument is the URL. -o FILE writes the body there.
cat > "$t/bin/curl" <<'G'
#!/bin/sh
echo "curl $*" >> "$MOCK/curl.log"
out= url=
while [ $# -gt 0 ]; do
	case $1 in
		-o) out=$2; shift 2 ;;
		-H|--max-time) shift 2 ;;
		-fsSL|-f|-s|-S|-L) shift ;;
		http*) url=$1; shift ;;
		*) shift ;;
	esac
done
[ -n "$url" ] || { echo "curl: no url" >&2; exit 9; }
body() {
	case $url in
		https://api.github.com/repos/danieldejager/phantom-mirage/releases/latest)
			cat "$MOCK/latest.json" ;;
		https://api.github.com/repos/danieldejager/phantom-mirage/releases)
			cat "$MOCK/releases.json" ;;
		https://api.github.com/repos/danieldejager/phantom-mirage/releases/tags/*)
			tag=${url##*/}
			[ -d "$MOCK/rel/$tag" ] || exit 1
			printf '{"tag_name":"%s","assets":[' "$tag"
			sep=
			for f in "$MOCK/rel/$tag"/*; do
				[ -f "$f" ] || continue
				printf '%s{"name":"%s"}' "$sep" "$(basename "$f")"
				sep=,
			done
			printf ']}\n' ;;
		https://raw.githubusercontent.com/danieldejager/phantom-mirage/master/release/SHA256SUMS.pub)
			cat "$MOCK/pub" ;;
		https://github.com/danieldejager/phantom-mirage/releases/download/*)
			rest=${url#https://github.com/danieldejager/phantom-mirage/releases/download/}
			tag=${rest%%/*}
			file=${rest#*/}
			cp "$MOCK/rel/$tag/$file" "${out:-/dev/stdout}" ;;
		https://api.github.com/repos/danieldejager/phantom-mirage)
			echo '{}' ;;
		*) echo "unexpected url $url" >&2; exit 9 ;;
	esac
}
if [ -z "$out" ]; then
	body
elif [ "$out" = /dev/null ]; then
	body >/dev/null
else
	body > "$out"
fi
G
chmod +x "$t/bin/"*
sign() {
	openssl dgst -sha256 -sign "$t/key.pem" -out "$1/sig.bin" "$1/SHA256SUMS"
	base64 -w0 "$1/sig.bin" > "$1/SHA256SUMS.sig"
	echo >> "$1/SHA256SUMS.sig"
}
mkrel() {	# mkrel TAG [corrupt]
	d=$t/rel/$1; mkdir -p "$d"
	printf '#!/bin/sh\necho "$0 $*" >> "%s/run.log"\n' "$t" > "$d/phantom-mirage_${1#v}_ubuntu26.04_arm64.run"
	printf '#!/bin/sh\necho "$0 $*" >> "%s/run.log"\n' "$t" > "$d/phantom-mirage_${1#v}_ubuntu26.04_amd64.run"
	chmod +x "$d"/*.run
	(cd "$d" && sha256sum *.run > SHA256SUMS)
	sign "$d"
	[ -z "${2:-}" ] || echo tampered >> "$d/phantom-mirage_${1#v}_ubuntu26.04_arm64.run"
}
latest_is() { # tag
	printf '{"tag_name":"%s","assets":[{"name":"SHA256SUMS"}]}\n' "$1" > "$t/latest.json"
}
gm() {
	rm -f "$t/run.log" "$t/curl.log"
	rc=0
	sh "$src/release/get-mirage.sh" "$@" > "$t/o" 2>&1 || rc=$?
}

# 1. not root, and not the test bypass: refuse before any download
env -u PM_GET_MIRAGE_TEST sh "$src/release/get-mirage.sh" --stable > "$t/o" 2>&1 || rc=$?
[ $rc = 1 ] && grep -q 'run as root' "$t/o" || fail "not-root"
[ ! -e "$t/run.log" ] || fail "installer ran when not root"

# 2. default channel: newest release with files, draft and empty skipped
mkrel v1.7.0-3; mkrel v1.7.0-4
cat > "$t/releases.json" <<'J'
[{"tag_name":"v1.7.0","draft":false,"prerelease":false,"published_at":"2026-10-22T05:59:53Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v1.7.0-5","draft":true,"prerelease":false,"published_at":null,"assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v1.7.0-4","draft":false,"prerelease":true,"published_at":"2026-10-22T23:04:33Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"v1.7.0-3","draft":false,"prerelease":true,"published_at":"2026-10-22T21:38:34Z","assets":[{"name":"SHA256SUMS"}]}]
J
gm -i veth-h -n 10.77.0.248/29
[ $rc = 0 ] || fail "prerelease rc=$rc"
grep -q 'release v1.7.0-4:' "$t/o" || fail "prerelease not announced"
grep -q 'SHA256SUMS signature OK' "$t/o" || fail "prerelease signature"
grep -q 'phantom-mirage_1.7.0-4_ubuntu26.04_arm64.run -i veth-h -n 10.77.0.248/29$' "$t/run.log" || fail "prerelease not run"
! grep -q 'Authorization:' "$t/curl.log" || fail "token sent when unset"

# 3. --tag does not list every release
gm --tag v1.7.0-3 -i eth0
[ $rc = 0 ] && grep -q 'phantom-mirage_1.7.0-3_ubuntu26.04_arm64.run -i eth0$' "$t/run.log" || fail "--tag"
! grep -q '/releases$' "$t/curl.log" || fail "--tag still listed releases"

# 4. checksum mismatch: the installer is not run
mkrel v1.7.0-6 corrupt
gm --tag v1.7.0-6
[ $rc != 0 ] && grep -q 'checksum mismatch' "$t/o" || fail "checksum mismatch not refused"
[ ! -e "$t/run.log" ] || fail "installer ran after checksum mismatch"

# 5. no matching asset
mkdir -p "$t/rel/v1.7.0-7"
echo x > "$t/rel/v1.7.0-7/phantom-mirage_1.7.0-7_debian13_amd64.run"
(cd "$t/rel/v1.7.0-7" && sha256sum *.run > SHA256SUMS)
sign "$t/rel/v1.7.0-7"
gm --tag v1.7.0-7
[ $rc != 0 ] && grep -q 'has no .run for ubuntu26.04/arm64' "$t/o" || fail "no matching asset"
[ ! -e "$t/run.log" ] || fail "installer ran without an asset"

# 6. not Ubuntu 26.04
printf 'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian GNU/Linux 13"\n' > "$t/osdeb"
PM_OS_RELEASE=$t/osdeb gm --tag v1.7.0-3
[ $rc != 0 ] && grep -q 'this installer is for Ubuntu 26.04' "$t/o" || fail "debian accepted"
[ ! -e "$t/run.log" ] || fail "installer ran on debian"

# 7. piped through sh
rm -f "$t/run.log"
rc=0
sh < "$src/release/get-mirage.sh" > "$t/o" 2>&1 || rc=$?
[ $rc = 0 ] && grep -q '1.7.0-4_ubuntu26.04_arm64.run' "$t/run.log" || fail "| sh"

# 8. --stable is GitHub Latest when that release has files
mkrel mark-1
latest_is mark-1
gm --stable -i eth0
[ $rc = 0 ] && grep -q 'release mark-1:' "$t/o" || fail "--stable did not pick Latest"
grep -q 'phantom-mirage_mark-1_ubuntu26.04_arm64.run -i eth0$' "$t/run.log" || fail "--stable run"

# 9. --stable skips an empty Latest and uses the next stable release with files
mkrel v1.7.0
printf '{"tag_name":"mark-1","assets":[]}\n' > "$t/latest.json"
cat > "$t/releases.json" <<'J'
[{"tag_name":"v1.7.0","draft":false,"prerelease":false,"published_at":"2026-10-22T05:59:53Z","assets":[{"name":"SHA256SUMS"}]},
 {"tag_name":"mark-1","draft":false,"prerelease":false,"published_at":"2026-11-07T11:22:07Z","assets":[]},
 {"tag_name":"v1.7.0-4","draft":false,"prerelease":true,"published_at":"2026-10-22T23:04:33Z","assets":[{"name":"SHA256SUMS"}]}]
J
gm --stable -i eth0
[ $rc = 0 ] && grep -q 'phantom-mirage_1.7.0_ubuntu26.04_arm64.run -i eth0$' "$t/run.log" || fail "empty Latest was selected"
grep -q 'Latest release has no files' "$t/o" || fail "no skip message"

# 10. no stable release at all
printf '{"tag_name":"v2.0.0-1","assets":[]}\n' > "$t/latest.json"
echo '[{"tag_name":"v2.0.0-1","draft":false,"prerelease":true,"published_at":"2026-10-22T05:59:53Z","assets":[{"name":"SHA256SUMS"}]}]' > "$t/releases.json"
gm --stable
[ $rc != 0 ] && grep -q 'no published stable release with files' "$t/o" || fail "--stable without stable release"

# 11. signature is mandatory: missing, bad, and a different key all refuse
rm -f "$t/rel/v1.7.0-3/SHA256SUMS.sig"
gm --tag v1.7.0-3
[ $rc != 0 ] && grep -q 'no SHA256SUMS.sig' "$t/o" || fail "unsigned release accepted"
[ ! -e "$t/run.log" ] || fail "installer ran without a signature"
sign "$t/rel/v1.7.0-3"
printf 'not a signature\n' > "$t/rel/v1.7.0-3/SHA256SUMS.sig"
gm --tag v1.7.0-3
[ $rc != 0 ] && grep -q 'signature does not verify\|SHA256SUMS.sig is not a signature' "$t/o" || fail "bad signature accepted"
[ ! -e "$t/run.log" ] || fail "installer ran after a bad signature"
sign "$t/rel/v1.7.0-3"
openssl ecparam -name prime256v1 -genkey -noout -out "$t/key2.pem"
openssl ec -in "$t/key2.pem" -pubout -out "$t/pub2"
PM_SIGNING_PUBKEY=$t/pub2 gm --tag v1.7.0-3
[ $rc != 0 ] && grep -q 'signature does not verify' "$t/o" || fail "wrong key accepted"
[ ! -e "$t/run.log" ] || fail "installer ran with the wrong key"

# 12. optional token is sent and not required
sign "$t/rel/v1.7.0-3"
GH_TOKEN=dummy-not-a-secret gm --tag v1.7.0-3
[ $rc = 0 ] && grep -q 'Authorization: Bearer dummy-not-a-secret' "$t/curl.log" || fail "token not sent"
echo "test_get_mirage: all passed"
