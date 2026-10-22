#!/bin/sh
# fake "imagetools inspect REF --raw" reading fixtures; FIXTURE_OVERRIDE=dig=file
d=$(dirname "$0"); ref=$1
case $ref in *@sha256:1111*) cat "$d/index.json"; exit;; esac
h=${ref##*sha256:}
if [ -n "$FIXTURE_OVERRIDE" ] && [ "${FIXTURE_OVERRIDE%%=*}" = "$h" ]; then cat "$d/${FIXTURE_OVERRIDE#*=}"; exit; fi
cat "$d/$h.json"
