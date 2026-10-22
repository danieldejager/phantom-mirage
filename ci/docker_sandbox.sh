#!/bin/bash
# #16: the daemon and script sandbox checks inside the built image.
# Usage: ci/docker_sandbox.sh IMAGE   (an image already loaded locally)
# Builds ci/Dockerfile.sandbox-test on top of IMAGE (local only, never
# pushed) and runs, with the image's own binaries:
#   1. ci/sandbox_daemon.sh (HD_NOPY=1: the image has no embedded Python)
#      with the daemon seccomp allowlist and Landlock required, plus
#      --sandbox-scripts on top; any denied syscall fails;
#   2. ci/script_ns.sh with HD_NS=require: every script in its own
#      user/pid/mount/net/uts namespace and read-only root, no network.
# Each run gets only the privileges listed in docs/docker.md.
set -euo pipefail
img=$1
docker build --builder default -q -f ci/Dockerfile.sandbox-test \
  --build-arg BASE="$img" -t phantom-mirage:sandbox-test . >/dev/null
# as in production (docs/docker.md), plus CHOWN/KILL for the test harness
# (it chowns the graphs dir and signals the daemon after it dropped to
# nobody) and an exec /tmp for the test subsystem binary
base=(--rm --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN
  --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add KILL
  --read-only --tmpfs /run --tmpfs /tmp:exec --tmpfs /var/tmp
  --tmpfs /root/.config --security-opt no-new-privileges)
mkdir -p docker-sandbox-logs; chmod 1777 docker-sandbox-logs
logs=(-v "$PWD/docker-sandbox-logs:/logs")
rc=0
echo "::group::daemon sandbox in the image"
docker run "${base[@]}" "${logs[@]}" -e HD_NOPY=1 -e HD_LANDLOCK=require \
  -e HD_SUBSYS=/usr/local/libexec/pm-ci/subsys_echo -e HD_LOGDIR=/logs \
  phantom-mirage:sandbox-test bash ci/sandbox_daemon.sh || rc=1
echo "::endgroup::"
# --sandbox-scripts namespaces additionally need unshare/mount/pivot_root
# (docker/seccomp-sandbox-scripts.json) and an AppArmor profile that
# allows mounts (docker-default denies them).
echo "::group::script namespaces in the image"
docker run "${base[@]}" "${logs[@]}" \
  --security-opt seccomp="$PWD/docker/seccomp-sandbox-scripts.json" \
  --security-opt apparmor=unconfined \
  -e HD_NS=require -e HD_LOGDIR=/logs \
  phantom-mirage:sandbox-test bash ci/script_ns.sh || rc=1
echo "::endgroup::"
[ $rc = 0 ] && echo "docker sandbox checks OK ($(docker run --rm --entrypoint uname phantom-mirage:sandbox-test -m))"
exit $rc
