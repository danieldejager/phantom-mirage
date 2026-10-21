#!/bin/bash
# Compare syscalls seen by strace (files given as arguments, strace -f -o
# output) with the --sandbox-daemon allowlist as compiled for this
# architecture. Prints the per-arch allowlist size and every traced call
# that is not on it; exits 1 if there is any (#16).
set -euo pipefail
D=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
{
  echo '#include <stdio.h>'
  echo '#include <sys/syscall.h>'
  echo 'int main(void) {'
  sed -n 's/^A(\([a-z0-9_]*\))$/#ifdef __NR_\1\nputs("\1");\n#endif/p' "$D/sandbox_daemon_list.h"
  echo 'return 0; }'
} > $tmp/list.c
cc -o $tmp/list $tmp/list.c
$tmp/list | sort -u > $tmp/allowed
sed -E 's/^[0-9]+ +//' "$@" | grep -oE '^(<\.\.\. )?[a-z_0-9]+[ (]' |
  sed -E 's/^<\.\.\. //; s/[ (]$//' | sort -u > $tmp/seen
echo "arch $(uname -m): $(wc -l < $tmp/allowed) syscalls on the allowlist, $(wc -l < $tmp/seen) seen"
missing=$(comm -23 $tmp/seen $tmp/allowed)
# calls strace reports that are not real syscalls / only happen before
# the filter is installed in the parent (exec of phantom-mirage itself is fine)
if [ -n "$missing" ]; then
  echo "seen but NOT allowlisted:"; echo "$missing" | sed 's/^/  /'
  rm -rf $tmp; exit 1
fi
echo "all traced syscalls are allowlisted"
rm -rf $tmp
