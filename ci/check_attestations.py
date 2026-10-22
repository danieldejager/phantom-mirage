#!/usr/bin/env python3
"""Check that buildx SBOM and provenance attestations exist in the registry.

Reads only manifests (docker buildx imagetools inspect --raw), never the
attestation documents themselves, and prints a short summary.  Each image
platform must have an attestation manifest carrying an SPDX SBOM and an
SLSA provenance layer.

Usage: check_attestations.py IMAGE@DIGEST
Env:   IMAGETOOLS  command used to fetch raw manifests
                   (default "docker buildx imagetools inspect"); the tests
                   point it at a fixture reader.
"""
import json
import os
import shlex
import subprocess
import sys

SBOM = "https://spdx.dev/Document"
PROV = "https://slsa.dev/provenance/"


def raw(ref):
    cmd = shlex.split(os.environ.get("IMAGETOOLS",
                                     "docker buildx imagetools inspect"))
    out = subprocess.run(cmd + [ref, "--raw"], check=True,
                         stdout=subprocess.PIPE).stdout
    return json.loads(out)


def main(ref):
    repo = ref.split("@", 1)[0]
    idx = raw(ref)
    images, atts = {}, {}
    for m in idx.get("manifests", []):
        ann = m.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            atts[ann.get("vnd.docker.reference.digest")] = m["digest"]
        else:
            p = m.get("platform") or {}
            images[m["digest"]] = "%s/%s" % (p.get("os"), p.get("architecture"))
    errors = []
    if not images:
        errors.append("no image manifests in the index")
    for dg, plat in sorted(images.items(), key=lambda x: x[1]):
        if dg not in atts:
            errors.append("%s: no attestation manifest" % plat)
            continue
        man = raw("%s@%s" % (repo, atts[dg]))
        types = sorted({(l.get("annotations") or {}).get("in-toto.io/predicate-type", "")
                        for l in man.get("layers", [])})
        sbom = any(t == SBOM for t in types)
        prov = any(t.startswith(PROV) for t in types)
        print("%s: attestation %s sbom=%s provenance=%s (%s)"
              % (plat, atts[dg][:19], sbom, prov, ", ".join(types)))
        if not sbom:
            errors.append("%s: no SPDX SBOM attestation" % plat)
        if not prov:
            errors.append("%s: no SLSA provenance attestation" % plat)
    for e in errors:
        print("ERROR:", e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or "@" not in sys.argv[1]:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
