#!/bin/bash
# Compare syscalls seen by strace (files given as arguments, strace -f -o
# output) with the --sandbox-daemon allowlist as compiled for this
# architecture. Prints the per-arch allowlist size and every traced call
# that is not on it; exits 1 if there is any (#16).
# With --launcher: the traces are of the pm-script-ns launcher (and the
# scripts it runs), checked against its list, sandbox_daemon_list.h plus
# sandbox_ns_list.h, with no exemptions.
set -euo pipefail
D=$(cd "$(dirname "$0")/.." && pwd)
lists="$D/sandbox_daemon_list.h"; launcher=0
if [ "${1:-}" = --launcher ]; then
  shift; launcher=1; lists="$lists $D/sandbox_ns_list.h"
fi
tmp=$(mktemp -d)
{
  echo '#include <stdio.h>'
  echo '#include <sys/syscall.h>'
  echo 'int main(void) {'
  sed -n 's/^A(\([a-z0-9_]*\))$/#ifdef __NR_\1\nputs("\1");\n#endif/p' $lists
  echo 'return 0; }'
} > $tmp/list.c
cc -o $tmp/list $tmp/list.c
$tmp/list | sort -u > $tmp/allowed
sed -E 's/^[0-9]+ +//' "$@" | grep -oE '^(<\.\.\. )?[a-z_0-9]+[ (]' |
  sed -E 's/^<\.\.\. //; s/[ (]$//' | sort -u > $tmp/seen
[ $launcher = 1 ] && echo "pm-script-ns launcher allowlist:"
echo "arch $(uname -m): $(wc -l < $tmp/allowed) syscalls on the allowlist, $(wc -l < $tmp/seen) seen"
# The --sandbox-scripts launcher (sandbox_ns.c) is forked before the
# daemon's filter and is deliberately outside it; these calls are its
# alone (a daemon using them would still die with SIGSYS when enforcing).
printf '%s\n' mount sethostname unshare > $tmp/launcher
[ $launcher = 1 ] && : > $tmp/launcher
missing=$(comm -23 $tmp/seen $tmp/allowed | comm -23 - $tmp/launcher)
# calls strace reports that are not real syscalls / only happen before
# the filter is installed in the parent (exec of phantom-mirage itself is fine)
if [ -n "$missing" ]; then
  echo "seen but NOT allowlisted:"; echo "$missing" | sed 's/^/  /'
  rm -rf $tmp; exit 1
fi
echo "all traced syscalls are allowlisted"
rm -rf $tmp
