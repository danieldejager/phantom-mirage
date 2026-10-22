#!/bin/bash
# Inside the phantom-mirage-docker AppArmor profile: the profile, not the
# user namespace, decides which mounts work. As nobody in a new user +
# mount namespace, the launcher's exact tmpfs call is allowed on /tmp and
# denied anywhere else.
set -euo pipefail
m() {
  setpriv --reuid 65534 --regid 65534 --clear-groups unshare -Urm python3 -c '
import ctypes, os, sys
l = ctypes.CDLL(None, use_errno=True)
# mount("tmpfs", dir, "tmpfs", MS_NOSUID|MS_NODEV, "mode=1777,size=64m")
r = l.mount(b"tmpfs", sys.argv[1].encode(), b"tmpfs", 6, b"mode=1777,size=64m")
sys.exit(0 if r == 0 else "mount %s: %s" % (sys.argv[1], os.strerror(ctypes.get_errno())))
' "$1"
}
m /tmp
if m /mnt 2>/dev/null; then echo "apparmor probe: tmpfs on /mnt was allowed" >&2; exit 1; fi
echo "apparmor probe: tmpfs on /tmp allowed, on /mnt denied"
