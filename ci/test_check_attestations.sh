#!/bin/bash
# check_attestations.py against saved manifest fixtures
set -euo pipefail
cd "$(dirname "$0")"
export IMAGETOOLS="$PWD/fixtures/attest/imagetools.sh"
ref=ghcr.io/example/img@sha256:1111111111111111111111111111111111111111111111111111111111111111
python3 check_attestations.py "$ref"
if FIXTURE_OVERRIDE=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd=d_noprov.json \
   python3 check_attestations.py "$ref"; then
  echo "FAIL: missing provenance not detected"; exit 1
fi
echo "attestation check test OK"
