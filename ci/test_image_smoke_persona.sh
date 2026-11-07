#!/bin/sh
# The amd64 image smoke step mounts a config into a container whose
# entrypoint passes -p columbo-v1.db. ci/smoke.conf names the nmap-os-db
# fingerprint "Linux 2.6.32", which is not in columbo-v1.db, so that
# --verify-config failed the Mark 1 nightly (run 42253311080). The step
# rewrites that name to ubuntu2404 before mounting. This checks the
# rewrite still matches a Fingerprint line in the image database.
set -eu
cd "$(dirname "$0")/.."
wf=.github/workflows/build.yml
grep -q 's/Linux 2.6.32/ubuntu2404/' "$wf" || {
	echo "image smoke step no longer rewrites Linux 2.6.32 to ubuntu2404" >&2
	exit 1
}
grep -q 'smoke-image.conf:/etc/phantom-mirage/phantom-mirage.conf' "$wf" || {
	echo "image smoke step does not mount the rewritten config" >&2
	exit 1
}
grep -q 'Linux 2.6.32' ci/smoke.conf || {
	echo "ci/smoke.conf no longer uses the nmap personality the other jobs load" >&2
	exit 1
}
grep -q '^Fingerprint ubuntu2404$' fingerprints/columbo-v1.db || {
	echo "ubuntu2404 is not a Fingerprint in columbo-v1.db" >&2
	exit 1
}
if grep -q '^Fingerprint Linux 2.6.32$' fingerprints/columbo-v1.db; then
	echo "columbo-v1.db now contains Linux 2.6.32; the rewrite is stale" >&2
	exit 1
fi
echo "image-smoke-persona OK"
