/*
 * Extra syscalls of the --sandbox-scripts launcher (pm-script-ns, #16),
 * on top of sandbox_daemon_list.h; included by sandbox_daemon.c.
 * Learned with strace -f of the launcher under the systemd and
 * --sandbox-scripts CI jobs on amd64 and arm64 (ci/syscall_audit.sh
 * --launcher). Only what entering the namespaces needs; scripts lose
 * these again through the deny-list and the daemon's allowlist that
 * ns_run() applies before the exec.
 */
#ifdef __NR_unshare
A(unshare)
#endif
#ifdef __NR_mount
A(mount)
#endif
#ifdef __NR_sethostname
A(sethostname)
#endif
