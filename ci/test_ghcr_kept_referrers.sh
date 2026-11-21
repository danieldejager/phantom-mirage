#!/bin/bash
# ghcr_kept_referrers.py against the publish-run-21 package fixture
set -euo pipefail
cd "$(dirname "$0")"
fx=$PWD/fixtures/ghcr-retention
out=$(mktemp)
json=$(mktemp)
trap 'rm -f "$out" "$out.deletes" "$json"' EXIT

python3 ghcr_kept_referrers.py \
  --owner danieldejager --package phantom-mirage \
  --versions-json "$fx/versions.json" \
  --manifests-dir "$fx/manifests" \
  --out-excludes "$out" --out-deletes "$out.deletes" --out-json "$json" \
  >/dev/null

python3 - "$json" "$out" << 'PY'
import json, re, sys

REF = re.compile(r"^sha256-([0-9a-f]{64})\.(sig|att|sbom)$")
with open(sys.argv[1]) as f:
    d = json.load(f)
with open(sys.argv[2]) as f:
    text = f.read().strip()
tags = text.split(",") if text else []
if tags != d["exclude_tags"]:
    raise SystemExit("stdout/file tag list does not match --out-json")

# Static keeps from the 7 Nov dry run, plus the 3 newest sha-only images.
want_static = {
    "1.7.0-7", "1.7.0-6", "1.7.0-5", "1.7.0-4", "1.7.0-3",
    "1", "1.7", "1.7.0", "edge", "latest",
}
got_static = {t for v in d["static"] for t in v["tags"]}
missing = want_static - got_static
if missing:
    raise SystemExit("missing statically kept tags: %s" % sorted(missing))

want_keep_n = ["sha-4f386d2", "sha-df7362f", "sha-85c3ba7"]
got_keep_n = [t for v in d["keep_n_sha"] for t in v["tags"] if t.startswith("sha-")]
if got_keep_n != want_keep_n:
    raise SystemExit("keep-n sha tags %s, expected %s" % (got_keep_n, want_keep_n))

want_older = ["sha-4e2fe5c", "sha-386fc47"]
got_older = [t for v in d["older_sha"] for t in v["tags"] if t.startswith("sha-")]
if got_older != want_older:
    raise SystemExit("older sha tags %s, expected %s" % (got_older, want_older))

# Every kept image (static + keep-n) has 1 index + 4 child digests, and
# each of those 5 has an exact .sig tag in the fixture.
kept_subjects = set()
for digests in d["kept_digests"].values():
    kept_subjects.update(digests)
if len(d["kept_digests"]) != 10:
    raise SystemExit("expected 10 kept images, got %d" % len(d["kept_digests"]))
if len(kept_subjects) != 50:
    raise SystemExit("expected 50 kept subject digests, got %d" % len(kept_subjects))
if len(tags) != 50:
    raise SystemExit("expected 50 exact referrer excludes, got %d" % len(tags))

for t in tags:
    m = REF.fullmatch(t)
    if not m:
        raise SystemExit("exclude is not an exact referrer tag: %s" % t)
    subject = "sha256:" + m.group(1)
    if subject not in kept_subjects:
        raise SystemExit("exclude %s is not tied to a kept digest" % t)

# Signatures of the two older sha builds must not be excluded.
older_subjects = set()
for v in d["older_sha"]:
    older_subjects.add(v["digest"])
    older_subjects.update(d.get("kept_digests", {}).get(v["digest"], []))
# older images are not in kept_digests; load their children from the
# fact that their .sig tags exist and must be absent from excludes.
older_sigs = [
    "sha256-a5237775180bd82a04dab81235843fefa0156ca7f2473e21e7948da7fe20f0a1.sig",
    "sha256-1c05ff75edf7383d03f8435737f1c1ec90657127cf574c65b584d643d0de7e03.sig",
    "sha256-081674b87062c78eef24713e5d9df85dc9e48f65d43020558d475dabbea0a33f.sig",
    "sha256-0388ed95f6438dd465c0597f96ebf26319d62fbb11359de96ad869ba304fa14d.sig",
    "sha256-9da8ec4c72e0cccf0e9ad6e6fb1278a24a1beefa24403b859c30912e2a9a61e5.sig",
    "sha256-766baa55bc0e2d4ddc637591f6acee2dd88def6b85747adbda1a93c85f0c1c4c.sig",
    "sha256-b56669288e9fe477ffceb3297a321043f1cf5a18cf90a884d94c3e68c2151e3e.sig",
    "sha256-03818d519d9dace67c4cffb92f720ad91196a2ab9623587cea324f92f036b665.sig",
    "sha256-13f98af205838d88fc1f6417d44a9097baf01a2dfb2ae558df5d1571dd5b3a17.sig",
    "sha256-8047e8a36a7dee3c3d61c8efdf71137fe141f1c938302d59ee52f19b4ae12c34.sig",
]
for t in older_sigs:
    if t in tags:
        raise SystemExit("signature of a deleted image was excluded: %s" % t)
deletes = d["delete_tags"]
if len(deletes) != 10:
    raise SystemExit("expected 10 delete referrer tags, got %d" % len(deletes))
for t in older_sigs:
    if t not in deletes:
        raise SystemExit("signature of a deleted image not staged for delete: %s" % t)
for t in deletes:
    if t in tags:
        raise SystemExit("a tag is both excluded and staged for delete: %s" % t)
    if not REF.fullmatch(t):
        raise SystemExit("delete tag is not an exact referrer tag: %s" % t)

# Loose / renamed tags must not slip through.
banned = [
    "sha256-3ac826ada8f7e39c5d0ed92a2c9f3aedecaa6cb266ac20d5dbea352bed3acbad.sig.bak",
    "keep-sha256-3ac826ada8f7e39c5d0ed92a2c9f3aedecaa6cb266ac20d5dbea352bed3acbad.sig",
    "sha256-0000000000000000000000000000000000000000000000000000000000000000.sig",
]
for t in banned:
    if t in tags:
        raise SystemExit("loose or unrelated tag was excluded: %s" % t)

# The one per-platform signature of 1.7.0-7 that run 21 would have deleted
# must now be excluded (subject b3f46ee5... is a child of 3ac826...).
must = "sha256-b3f46ee5d7640efa7be82f3083d742a09c0bf5e77d62c07b1477b4837fe43f50.sig"
if must not in tags:
    raise SystemExit("missing the 1.7.0-7 platform signature that run 21 would delete")

print("ghcr kept-referrers test OK (%d exact tags)" % len(tags))
PY
