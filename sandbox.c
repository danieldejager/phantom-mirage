/*
 * Copyright (c) 2026 Daniel de Jager
 * All rights reserved.
 *
 * Defence-in-depth process hardening for honeyd (#16).
 *
 * Default (Linux): when honeyd or a script child drops privileges, the
 * capability bounding and ambient sets are emptied, no_new_privs is set,
 * and we verify that real/effective/saved IDs and capabilities are gone.
 *
 * Opt-in (--sandbox-scripts): script and subsystem children additionally
 * get a Landlock filesystem allowlist (read-only system directories, no
 * writes except /dev/null and --sandbox-allow-write dirs) and a seccomp
 * deny-list of kernel-attack-surface syscalls.  See docs/sandboxing.md.
 *
 * Licensed under the GNU General Public License, version 2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "sandbox.h"

int honeyd_sandbox_scripts = 0;
int sandbox_script_private_tmp = 0;

#define MAX_WRITE_PATHS	16
static const char *write_paths[MAX_WRITE_PATHS];
static int nwrite_paths;

/*
 * Directories Landlock must never make writable as a whole (#16): shared
 * scratch space and system trees. Trailing slashes are ignored.
 */
int
sandbox_path_broad(const char *path)
{
	static const char *broad[] = {
		"/", "/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run",
		"/run/lock", "/var/lock", "/var", "/var/lib", "/var/log",
		"/var/cache", "/usr", "/etc", "/home", "/root", "/opt", "/srv",
		"/mnt", "/media", "/dev", "/proc", "/sys", "/boot", "/bin",
		"/sbin", "/lib", "/lib64", NULL
	};
	char buf[PATH_MAX];
	size_t n;
	int i;

	if (path == NULL ||
	    (size_t)snprintf(buf, sizeof(buf), "%s", path) >= sizeof(buf))
		return (1);
	for (n = strlen(buf); n > 1 && buf[n - 1] == '/'; n--)
		buf[n - 1] = '\0';
	for (i = 0; broad[i] != NULL; i++)
		if (strcmp(buf, broad[i]) == 0)
			return (1);
	return (0);
}

int
sandbox_add_write_path(const char *path)
{
	if (nwrite_paths >= MAX_WRITE_PATHS || path[0] != '/' ||
	    sandbox_path_broad(path))
		return (-1);
	write_paths[nwrite_paths++] = path;
	return (0);
}

int
sandbox_write_paths(const char * const **p)
{
	*p = write_paths;
	return (nwrite_paths);
}

#ifdef __linux__

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
/* Detected from the headers so it doesn't depend on (tracked) configure */
#if !defined(HAVE_LINUX_LANDLOCK_H) && defined(__has_include)
#if __has_include(<linux/landlock.h>)
#define HAVE_LINUX_LANDLOCK_H 1
#endif
#endif
#ifdef HAVE_LINUX_LANDLOCK_H
#include <linux/landlock.h>
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT			47
#define PR_CAP_AMBIENT_CLEAR_ALL	4
#endif

static void
fatal(const char *fmt, const char *what)
{
	syslog(LOG_ERR, fmt, what, strerror(errno));
	fprintf(stderr, "phantom-mirage: ");
	fprintf(stderr, fmt, what, strerror(errno));
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

static int
cap_last_cap(void)
{
	FILE *fp;
	int last = 63;

	if ((fp = fopen("/proc/sys/kernel/cap_last_cap", "r")) != NULL) {
		if (fscanf(fp, "%d", &last) != 1 || last < 0 || last > 63)
			last = 63;
		fclose(fp);
	}
	return (last);
}

void
sandbox_drop_caps_pre(void)
{
	int cap, last;

	/* Ambient caps survive execve() of unprivileged programs */
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

	/* Dropping from the bounding set needs CAP_SETPCAP; a child of an
	 * already-demoted honeyd has an empty set inherited anyway. */
	if (geteuid() != 0)
		return;
	last = cap_last_cap();
	for (cap = 0; cap <= last; cap++) {
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0 ||
		    errno == EINVAL)
			continue;
		if (errno == EPERM) {
			/* No CAP_SETPCAP, e.g. docker --cap-drop ALL.  Still
			 * safe: no_new_privs (set below) stops exec from
			 * granting anything the bounding set allows. */
			syslog(LOG_NOTICE, "sandbox: no CAP_SETPCAP, leaving "
			    "the capability bounding set as is");
			return;
		}
		fatal("sandbox: PR_CAPBSET_DROP(%s): %s", "cap");
	}
}

int
sandbox_verify_post(uid_t uid, gid_t gid)
{
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[2];
	uid_t ru, eu, su;
	gid_t rg, eg, sg;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal("sandbox: %sPR_SET_NO_NEW_PRIVS: %s", "");
	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		fatal("sandbox: %sno_new_privs not set: %s", "");

	if (getresuid(&ru, &eu, &su) == -1 || getresgid(&rg, &eg, &sg) == -1)
		fatal("sandbox: %sgetres[ug]id: %s", "");
	if (ru != uid || eu != uid || su != uid ||
	    rg != gid || eg != gid || sg != gid) {
		errno = EPERM;
		fatal("sandbox: %sreal/effective/saved IDs not dropped: %s", "");
	}

	if (uid == 0)
		return (0);

	/* setuid() clears permitted/effective, but not the inheritable set
	 * (some launchers set it); lowering capability sets is always
	 * allowed, so clear everything explicitly, then read it back. */
	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	if (syscall(SYS_capset, &hdr, data) == -1)
		fatal("sandbox: %scapset: %s", "");

	memset(&hdr, 0, sizeof(hdr));
	memset(data, 0, sizeof(data));
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	if (syscall(SYS_capget, &hdr, data) == -1)
		fatal("sandbox: %scapget: %s", "");
	if (data[0].effective || data[1].effective ||
	    data[0].permitted || data[1].permitted ||
	    data[0].inheritable || data[1].inheritable) {
		errno = EPERM;
		fatal("sandbox: %scapabilities remain after dropping privileges: %s", "");
	}
	return (0);
}

/* ---- opt-in script sandbox ---- */

#ifdef HAVE_LINUX_LANDLOCK_H

#define LL_RO	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | \
		 LANDLOCK_ACCESS_FS_READ_DIR)
#define LL_FILE	(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | \
		 LANDLOCK_ACCESS_FS_WRITE_FILE | LL_TRUNCATE)
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
#define LL_TRUNCATE LANDLOCK_ACCESS_FS_TRUNCATE
#else
#define LL_TRUNCATE 0
#endif

static void
ll_allow(int rfd, const char *path, __u64 access, __u64 handled)
{
	struct landlock_path_beneath_attr pb;
	struct stat st;
	int fd;

	if ((fd = open(path, O_PATH | O_CLOEXEC)) == -1) {
		/* missing paths are simply not allowed */
		if (errno != ENOENT)
			syslog(LOG_WARNING, "sandbox: landlock path %s: %s",
			    path, strerror(errno));
		return;
	}
	if (fstat(fd, &st) == 0 && !S_ISDIR(st.st_mode))
		access &= LL_FILE;
	memset(&pb, 0, sizeof(pb));
	pb.allowed_access = access & handled;
	pb.parent_fd = fd;
	if (syscall(SYS_landlock_add_rule, rfd, LANDLOCK_RULE_PATH_BENEATH,
		&pb, 0) == -1)
		syslog(LOG_WARNING, "sandbox: landlock rule for %s: %s",
		    path, strerror(errno));
	close(fd);
}

static void script_net_handled(struct landlock_ruleset_attr *, int);
static void script_net_rules(int, int);

static int
sandbox_landlock(char * const argv[])
{
	static const char *ro[] = {
		"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
		"/etc", "/opt", "/dev/urandom", "/dev/random",
		"/dev/zero", PATH_HONEYDDATA, NULL
	};
	struct landlock_ruleset_attr ra;
	__u64 handled, rw;
	char cwd[1024];
	int abi, rfd, i;

	abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
	    LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1)
		return (-1);

	handled = LANDLOCK_ACCESS_FS_EXECUTE |
	    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
	    LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
	    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
	    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
	    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		handled |= LANDLOCK_ACCESS_FS_REFER;
#endif
	if (abi >= 3)
		handled |= LL_TRUNCATE;
	rw = handled;
#ifdef LANDLOCK_ACCESS_FS_REFER
	rw &= ~LANDLOCK_ACCESS_FS_REFER;
#endif

	memset(&ra, 0, sizeof(ra));
	ra.handled_access_fs = handled;
	script_net_handled(&ra, abi);
	rfd = syscall(SYS_landlock_create_ruleset, &ra, sizeof(ra), 0);
	if (rfd == -1)
		return (-1);

	for (i = 0; ro[i] != NULL; i++)
		ll_allow(rfd, ro[i], LL_RO, handled);
	/* honeyd's working directory (config, scripts) */
	if (getcwd(cwd, sizeof(cwd)) != NULL)
		ll_allow(rfd, cwd, LL_RO, handled);
	/* the program and any absolute-path arguments (the script file) */
	for (i = 0; argv != NULL && argv[i] != NULL; i++)
		if (argv[i][0] == '/')
			ll_allow(rfd, argv[i], LL_RO, handled);
	ll_allow(rfd, "/dev/null", LL_FILE, handled);
	for (i = 0; i < nwrite_paths; i++)
		ll_allow(rfd, write_paths[i], rw, handled);
	/* a private tmpfs (own mount namespace) is the script's scratch */
	if (sandbox_script_private_tmp)
		ll_allow(rfd, "/tmp", rw, handled);
	script_net_rules(rfd, abi);

	if (syscall(SYS_landlock_restrict_self, rfd, 0) == -1) {
		close(rfd);
		return (-1);
	}
	close(rfd);
	return (abi);
}
#else
static int
sandbox_landlock(char * const argv[])
{
	errno = ENOSYS;
	return (-1);
}
#endif /* HAVE_LINUX_LANDLOCK_H */

/* ---- --sandbox-daemon: Landlock for the daemon itself (#16) ---- */

#define MAX_DAEMON_PATHS	128
#define MAX_DAEMON_PORTS	64
static char *daemon_ro[MAX_DAEMON_PATHS], *daemon_rw[MAX_DAEMON_PATHS];
static int ndaemon_ro, ndaemon_rw;
static unsigned short daemon_ports[MAX_DAEMON_PORTS];
static int ndaemon_ports, daemon_connect_any;

static void
daemon_add(char **list, int *n, const char *path)
{
	int i;

	if (path == NULL || path[0] != '/' || *n >= MAX_DAEMON_PATHS)
		return;
	for (i = 0; i < *n; i++)
		if (strcmp(list[i], path) == 0)
			return;
	if ((list[*n] = strdup(path)) != NULL)
		(*n)++;
}

void
sandbox_daemon_allow_read(const char *path)
{
	daemon_add(daemon_ro, &ndaemon_ro, path);
}

void
sandbox_daemon_allow_write(const char *path)
{
	daemon_add(daemon_rw, &ndaemon_rw, path);
}

void
sandbox_daemon_allow_connect(int port)
{
	int i;

	if (port < 0) {
		daemon_connect_any = 1;
		return;
	}
	for (i = 0; i < ndaemon_ports; i++)
		if (daemon_ports[i] == port)
			return;
	if (ndaemon_ports < MAX_DAEMON_PORTS)
		daemon_ports[ndaemon_ports++] = port;
	else
		daemon_connect_any = 1;
}

/*
 * The exec'd script launcher (sandbox_ns.c) needs the sandbox settings:
 * "-d" (--sandbox-daemon), "-w DIR" (--sandbox-allow-write), "-p PORT"
 * (daemon TCP connect port), "-a" (connect unrestricted).
 */
int
sandbox_state_argv(char **argv, int max, char *ports, size_t plen)
{
	int n = 0, i;
	size_t off = 0;

#define ADD(x) do { if (n >= max - 1) return (-1); argv[n++] = (x); } while (0)
	if (honeyd_sandbox_daemon)
		ADD("-d");
	if (daemon_connect_any)
		ADD("-a");
	for (i = 0; i < nwrite_paths; i++) {
		ADD("-w");
		ADD((char *)write_paths[i]);
	}
	for (i = 0; i < ndaemon_ports; i++) {
		int l = snprintf(ports + off, plen - off, "%u",
		    daemon_ports[i]);
		if (l < 0 || (size_t)l >= plen - off)
			return (-1);
		ADD("-p");
		ADD(ports + off);
		off += l + 1;
	}
#undef ADD
	argv[n] = NULL;
	return (n);
}

int
sandbox_state_parse(int argc, char **argv)
{
	int i;

	honeyd_sandbox_scripts = 1;
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0)
			honeyd_sandbox_daemon = 1;
		else if (strcmp(argv[i], "-a") == 0)
			daemon_connect_any = 1;
		else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc)
			sandbox_add_write_path(argv[++i]);
		else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
			sandbox_daemon_allow_connect(atoi(argv[++i]));
		else
			return (-1);
	}
	return (0);
}

#ifdef HAVE_LINUX_LANDLOCK_H
/*
 * With --sandbox-daemon, a script the launcher starts (sandbox_ns.c) is
 * not under the daemon's Landlock ruleset, so its own ruleset carries
 * the daemon's TCP rules: no bind, connect only to the proxy ports.
 */
static void
script_net_handled(struct landlock_ruleset_attr *ra, int abi)
{
#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
	/* scripts get no network: TCP bind and connect are handled and no
	 * port is allowed (#16) */
	if (abi < 4)
		return;
	ra->handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
	    LANDLOCK_ACCESS_NET_CONNECT_TCP;
#endif
}

static void
script_net_rules(int rfd, int abi)
{
	(void)rfd; (void)abi;	/* nothing allowed */
}

static int
daemon_landlock(char *net, size_t netlen)
{
	static const char *ro[] = {
		"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
		"/etc", "/opt", "/proc", "/dev/urandom", "/dev/random",
		"/dev/zero", PATH_HONEYDDATA, PATH_HONEYDLIB, NULL
	};
	struct landlock_ruleset_attr ra;
	__u64 handled, rw;
	int abi, rfd, i;

	abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
	    LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 1)
		return (-1);

	handled = LANDLOCK_ACCESS_FS_EXECUTE |
	    LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
	    LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
	    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
	    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
	    LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
	    LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
	if (abi >= 2)
		handled |= LANDLOCK_ACCESS_FS_REFER;
#endif
	if (abi >= 3)
		handled |= LL_TRUNCATE;
	/* Writable dirs: no char/block device nodes, no cross-dir renames */
	rw = handled & ~(LANDLOCK_ACCESS_FS_MAKE_CHAR |
	    LANDLOCK_ACCESS_FS_MAKE_BLOCK);
#ifdef LANDLOCK_ACCESS_FS_REFER
	rw &= ~LANDLOCK_ACCESS_FS_REFER;
#endif

	memset(&ra, 0, sizeof(ra));
	ra.handled_access_fs = handled;
	snprintf(net, netlen, "none (needs Landlock ABI 4, kernel has %d)",
	    abi);
#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
	if (abi >= 4) {
		ra.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP;
		if (!daemon_connect_any)
			ra.handled_access_net |=
			    LANDLOCK_ACCESS_NET_CONNECT_TCP;
		snprintf(net, netlen, "TCP bind denied, TCP connect %s",
		    daemon_connect_any ? "unrestricted (dynamic proxy target)"
		    : "limited to the configured proxy ports");
	}
#else
	snprintf(net, netlen, "none (built without Landlock network headers)");
#endif
	rfd = syscall(SYS_landlock_create_ruleset, &ra, sizeof(ra), 0);
	if (rfd == -1)
		return (-1);

	for (i = 0; ro[i] != NULL; i++)
		ll_allow(rfd, ro[i], LL_RO, handled);
	for (i = 0; i < ndaemon_ro; i++)
		ll_allow(rfd, daemon_ro[i], LL_RO, handled);
	ll_allow(rfd, "/dev/null", LL_FILE, handled);
	for (i = 0; i < ndaemon_rw; i++) {
		if (sandbox_path_broad(daemon_rw[i])) {
			syslog(LOG_WARNING, "sandbox-daemon: refusing to make "
			    "%s writable (too broad)", daemon_rw[i]);
			continue;
		}
		ll_allow(rfd, daemon_rw[i], rw, handled);
	}
	for (i = 0; i < nwrite_paths; i++)
		ll_allow(rfd, write_paths[i], rw, handled);
#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
	if (abi >= 4 && !daemon_connect_any) {
		struct landlock_net_port_attr np;
		for (i = 0; i < ndaemon_ports; i++) {
			memset(&np, 0, sizeof(np));
			np.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP;
			np.port = daemon_ports[i];
			if (syscall(SYS_landlock_add_rule, rfd,
				LANDLOCK_RULE_NET_PORT, &np, 0) == -1)
				syslog(LOG_WARNING, "sandbox-daemon: landlock "
				    "rule for port %d: %s", daemon_ports[i],
				    strerror(errno));
		}
	}
#endif
	/* no_new_privs is normally set already; required when still root */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (syscall(SYS_landlock_restrict_self, rfd, 0) == -1) {
		close(rfd);
		return (-1);
	}
	close(rfd);
	return (abi);
}
#else
static int
daemon_landlock(char *net, size_t netlen)
{
	errno = ENOSYS;
	return (-1);
}
#endif /* HAVE_LINUX_LANDLOCK_H */

int
sandbox_daemon_landlock(void)
{
	char net[96];
	int abi;

	if (!honeyd_sandbox_daemon)
		return (0);
	if ((abi = daemon_landlock(net, sizeof(net))) < 0) {
		syslog(LOG_WARNING, "sandbox-daemon: Landlock unavailable "
		    "(%s); the daemon is NOT filesystem-restricted (seccomp "
		    "only)", strerror(errno));
		return (0);
	}
	syslog(LOG_NOTICE, "sandbox-daemon: Landlock ABI %d active: "
	    "%d read-only, %d writable paths; network: %s", abi,
	    ndaemon_ro, ndaemon_rw + nwrite_paths, net);
	{
		char w[2048];
		size_t l = 0;
		int i;

		w[0] = '\0';
		for (i = 0; i < ndaemon_rw + nwrite_paths && l < sizeof(w); i++)
			l += snprintf(w + l, sizeof(w) - l, " %s", i < ndaemon_rw ?
			    daemon_rw[i] : write_paths[i - ndaemon_rw]);
		syslog(LOG_NOTICE, "sandbox-daemon: Landlock writable:%s", w);
	}
	return (abi);
}

#if defined(__x86_64__)
#define SB_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SB_ARCH AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define SB_ARCH AUDIT_ARCH_ARM
#elif defined(__i386__)
#define SB_ARCH AUDIT_ARCH_I386
#endif

#ifdef SB_ARCH
static const int denied[] = {
#define D(x) __NR_##x,
#ifdef __NR_ptrace
	D(ptrace)
#endif
#ifdef __NR_process_vm_readv
	D(process_vm_readv) D(process_vm_writev)
#endif
#ifdef __NR_mount
	D(mount)
#endif
#ifdef __NR_umount2
	D(umount2)
#endif
#ifdef __NR_umount
	D(umount)
#endif
#ifdef __NR_pivot_root
	D(pivot_root)
#endif
#ifdef __NR_chroot
	D(chroot)
#endif
#ifdef __NR_unshare
	D(unshare)
#endif
#ifdef __NR_setns
	D(setns)
#endif
#ifdef __NR_kexec_load
	D(kexec_load)
#endif
#ifdef __NR_kexec_file_load
	D(kexec_file_load)
#endif
#ifdef __NR_init_module
	D(init_module)
#endif
#ifdef __NR_finit_module
	D(finit_module)
#endif
#ifdef __NR_delete_module
	D(delete_module)
#endif
#ifdef __NR_bpf
	D(bpf)
#endif
#ifdef __NR_perf_event_open
	D(perf_event_open)
#endif
#ifdef __NR_keyctl
	D(keyctl)
#endif
#ifdef __NR_add_key
	D(add_key)
#endif
#ifdef __NR_request_key
	D(request_key)
#endif
#ifdef __NR_reboot
	D(reboot)
#endif
#ifdef __NR_swapon
	D(swapon) D(swapoff)
#endif
#ifdef __NR_iopl
	D(iopl)
#endif
#ifdef __NR_ioperm
	D(ioperm)
#endif
#ifdef __NR_userfaultfd
	D(userfaultfd)
#endif
#ifdef __NR_open_by_handle_at
	D(open_by_handle_at)
#endif
#ifdef __NR_name_to_handle_at
	D(name_to_handle_at)
#endif
#ifdef __NR_acct
	D(acct)
#endif
#ifdef __NR_quotactl
	D(quotactl)
#endif
#ifdef __NR_fanotify_init
	D(fanotify_init)
#endif
#ifdef __NR_io_uring_setup
	D(io_uring_setup) D(io_uring_enter) D(io_uring_register)
#endif
#ifdef __NR_fsopen
	D(fsopen) D(fsmount) D(fspick) D(move_mount) D(open_tree)
#endif
#ifdef __NR_mount_setattr
	D(mount_setattr)
#endif
#ifdef __NR_settimeofday
	D(settimeofday)
#endif
#ifdef __NR_clock_settime
	D(clock_settime)
#endif
#ifdef __NR_adjtimex
	D(adjtimex)
#endif
#ifdef __NR_clock_adjtime
	D(clock_adjtime)
#endif
#undef D
};

static int
sandbox_seccomp(void)
{
	size_t n = sizeof(denied) / sizeof(denied[0]), i, k = 0;
	struct sock_filter f[8 + 2 * (sizeof(denied) / sizeof(denied[0]))];
	struct sock_fprog prog;

	f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    offsetof(struct seccomp_data, arch));
	f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
	    SB_ARCH, 1, 0);
	/* Foreign ABI (e.g. i386 on x86_64): a deny-list cannot cover it */
	f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_KILL_PROCESS);
	f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
	/* x32 syscalls alias the x86_64 numbers with bit 30 set */
	f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
	    0x40000000, 0, 1);
	f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_KILL_PROCESS);
#endif
	for (i = 0; i < n; i++) {
		f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		    denied[i], 0, 1);
		f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
		    SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
	}
	f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_ALLOW);

	prog.len = k;
	prog.filter = f;
	/* no_new_privs is already set by sandbox_verify_post() */
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	return (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0));
}
#else
static int
sandbox_seccomp(void)
{
	errno = ENOSYS;
	return (-1);
}
#endif /* SB_ARCH */

void
sandbox_script(char * const argv[])
{
	static int warned_ll, warned_sc;
	int abi;

	if (!honeyd_sandbox_scripts)
		return;

	/* Runs in the child after stderr was redirected to the script's
	 * pipe, so only failures are reported (they show up in the service
	 * log as well as syslog). */
	if ((abi = sandbox_landlock(argv)) < 0) {
		if (!warned_ll++)
			syslog(LOG_WARNING, "sandbox: Landlock unavailable "
			    "(%s); scripts are NOT filesystem-restricted",
			    strerror(errno));
	}

	if (sandbox_seccomp() == -1) {
		if (!warned_sc++)
			syslog(LOG_WARNING, "sandbox: seccomp unavailable "
			    "(%s); scripts are NOT syscall-filtered",
			    strerror(errno));
	}
}

#else /* !__linux__ */

void sandbox_daemon_allow_read(const char *path) { }
void sandbox_daemon_allow_write(const char *path) { }
void sandbox_daemon_allow_connect(int port) { }
int sandbox_daemon_landlock(void) { return (0); }

void sandbox_drop_caps_pre(void) { }
int sandbox_verify_post(uid_t uid, gid_t gid) { return (0); }
void
sandbox_script(char * const argv[])
{
	if (honeyd_sandbox_scripts)
		syslog(LOG_WARNING, "sandbox: --sandbox-scripts is only "
		    "implemented on Linux");
}

#endif /* __linux__ */
