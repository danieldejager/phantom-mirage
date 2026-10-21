/*
 * Copyright (c) 2026 Daniel de Jager
 * All rights reserved.
 *
 * Opt-in seccomp allowlist for the honeyd daemon (--sandbox-daemon, #16).
 *
 * Installed once, right after the daemon's privilege drop. Anything not
 * on the list raises SIGSYS: the daemon (and a forked child that has not
 * exec'd yet) logs "sandbox-daemon: denied syscall <nr>" and dies with
 * SIGSYS; an exec'd script or subsystem inherits the filter, dies with
 * SIGSYS and the daemon logs "... killed by SIGSYS". Foreign ABIs (i386,
 * x32 on x86_64) are killed outright. The list was built from strace of
 * the CI suites (see docs/sandboxing.md); it covers the daemon plus the
 * sh, Perl and Python 3 service scripts and subsystems it starts, because
 * children inherit the filter.
 *
 * Licensed under the GNU General Public License, version 2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "sandbox.h"

int honeyd_sandbox_daemon = 0;

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#define SD_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SD_ARCH AUDIT_ARCH_AARCH64
#endif
#endif

#ifdef SD_ARCH
static const int allowed[] = {
#define A(x) __NR_##x,
#include "sandbox_daemon_list.h"
#undef A
};

/* Async-signal-safe: write(2) and kill(2) are on the list. */
static void
sd_sigsys(int sig, siginfo_t *si, void *ctx)
{
	char buf[96], num[16];
	int n = si->si_syscall, i = sizeof(num);
	size_t len;
	const char *pre = "phantom-mirage: sandbox-daemon: denied syscall ";

	(void)sig; (void)ctx;
	num[--i] = '\0';
	if (n < 0)
		n = -n;
	do {
		num[--i] = '0' + n % 10;
		n /= 10;
	} while (n > 0 && i > 0);
	len = strlen(pre);
	memcpy(buf, pre, len);
	memcpy(buf + len, num + i, sizeof(num) - i - 1);
	len += sizeof(num) - i - 1;
	buf[len++] = '\n';
	(void)write(STDERR_FILENO, buf, len);
	/* best effort for daemons without a terminal; we die right after */
	syslog(LOG_CRIT, "%.*s", (int)len - 1, buf + 8);
	signal(SIGSYS, SIG_DFL);
	kill(getpid(), SIGSYS);
	_exit(128 + SIGSYS);
}

static int sd_quiet;

int
sandbox_daemon_child(void)
{
	sd_quiet = 1;
	return (sandbox_daemon());
}

int
sandbox_daemon(void)
{
	size_t n = sizeof(allowed) / sizeof(allowed[0]), i, k = 0;
	struct sock_filter f[8 + 2 * (sizeof(allowed) / sizeof(allowed[0]))];
	struct sock_fprog prog;
	struct sigaction sa;

	if (!honeyd_sandbox_daemon)
		return (0);

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sd_sigsys;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSYS, &sa, NULL) == -1)
		return (-1);

	f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    offsetof(struct seccomp_data, arch));
	f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
	    SD_ARCH, 1, 0);
	f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_KILL_PROCESS);
	f[k++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
	    offsetof(struct seccomp_data, nr));
#ifdef __x86_64__
	f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K,
	    0x40000000, 0, 1);
	f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_KILL_PROCESS);
#endif
	for (i = 0; i < n; i++) {
		f[k++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		    allowed[i], 0, 1);
		f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
		    SECCOMP_RET_ALLOW);
	}
	f[k++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
	    SECCOMP_RET_TRAP);

	prog.len = k;
	prog.filter = f;
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		return (-1);
#ifdef SANDBOX_DAEMON_LEARN
	/* strace collection build: report, do not filter */
	(void)prog;
#else
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == -1)
		return (-1);
#endif
	if (!sd_quiet)
		syslog(LOG_NOTICE, "sandbox-daemon: seccomp allowlist "
		    "active (%zu syscalls)", n);
	return (0);
}
#else
int
sandbox_daemon_child(void)
{
	return (sandbox_daemon());
}

int
sandbox_daemon(void)
{
	if (!honeyd_sandbox_daemon)
		return (0);
	errno = ENOSYS;
	return (-1);
}
#endif /* SD_ARCH */
