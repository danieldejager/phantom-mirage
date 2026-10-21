#!/bin/sh
# CI (#24): service output with characters that need JSON escaping:
# quotes, a backslash, a control byte and a non-UTF-8 byte.
printf 'say "hi" \\ \001 \377\n' >&2
sleep 1
