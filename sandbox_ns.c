/*
 * Copyright (c) 2026 Daniel de Jager
 * All rights reserved.
 *
 * --sandbox-scripts: per-script namespaces (#16).
 *
 * The daemon's own sandbox (seccomp allowlist and Landlock, both
 * inherited by its children) forbids unshare(2) and mount(2), so scripts
 * are not started by the daemon directly.  Right after the privilege drop
 * and before the daemon's filters, honeyd forks a small launcher.  For
 * every script, the daemon still forks a child as before (so pid
 * tracking, signals and reaping are unchanged); that child hands the
 * script's stdio descriptors, argv and environment to the launcher and
 * waits.  The launcher forks, enters new user, mount, PID, IPC and UTS
 * namespaces (and a network namespace unless the script is listed with
 * --sandbox-script-net), mounts a private /tmp, and runs the script as
 * pid 1 of its PID namespace under the script sandbox (Landlock and the
 * deny-list) plus, with --sandbox-daemon, the daemon's allowlist.  The
 * exit status goes back to the daemon's child, which exits the same
 * way.  If the daemon's child dies, the launcher kills the script.
 *
 * Without unprivileged user namespaces the launcher logs that once and
 * runs scripts without namespaces (same sandbox otherwise).
 *
 * Licensed under the GNU General Public License, version 2.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "sandbox.h"

void cmd_droppriv(uid_t, gid_t);

#define MAX_NET_SCRIPTS	32
static const char *net_scripts[MAX_NET_SCRIPTS];
static int nnet_scripts;

int
sandbox_add_net_script(const char *path)
{
	if (nnet_scripts >= MAX_NET_SCRIPTS || path[0] != '/')
		return (-1);
	net_scripts[nnet_scripts++] = path;
	return (0);
}

#ifdef __linux__

#include <sched.h>
#include <grp.h>
#include <sys/mount.h>
#include <sys/prctl.h>

#define NS_MAGIC	0x504d4e53	/* "PMNS" */
#define NS_MAXMSG	65536
#define NS_MAXJOBS	1024

struct ns_req {
	uint32_t magic;
	uint32_t uid, gid, nofiles;
	uint32_t net;		/* 1: keep the host network namespace */
	uint32_t argc, envc;
	/* then execcmd, argv[], env[] as NUL-terminated strings */
};

static int ns_ctl = -1;		/* daemon side of the launcher socket */

/* Writes a whole small file, for /proc/self/{setgroups,uid_map,gid_map} */
static int
ns_write(const char *path, const char *buf)
{
	int fd, len = strlen(buf), ok;

	if ((fd = open(path, O_WRONLY | O_CLOEXEC)) == -1)
		return (-1);
	ok = write(fd, buf, len) == len;
	close(fd);
	return (ok ? 0 : -1);
}

static void
ns_mirror_exit(int status)
{
	if (WIFSIGNALED(status)) {
		signal(WTERMSIG(status), SIG_DFL);
		kill(getpid(), WTERMSIG(status));
		_exit(128 + WTERMSIG(status));
	}
	_exit(WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE);
}

/* In the launcher's child: namespaces, private /tmp, then the script. */
static void
ns_run(struct ns_req *req, char *strs, int fd_io, int fd_err, int have_ns)
{
	char **argv, **envp, *execcmd, map[64];
	int flags, status;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	uint32_t i;
	struct rlimit rl;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	argv = calloc(req->argc + 1, sizeof(char *));
	envp = calloc(req->envc + 1, sizeof(char *));
	if (argv == NULL || envp == NULL)
		_exit(EXIT_FAILURE);
	execcmd = strs;
	strs += strlen(strs) + 1;
	for (i = 0; i < req->argc; i++, strs += strlen(strs) + 1)
		argv[i] = strs;
	for (i = 0; i < req->envc; i++, strs += strlen(strs) + 1)
		envp[i] = strs;

	setpriority(PRIO_PROCESS, 0, 10);
	if (geteuid() == 0 && req->uid != 0)
		cmd_droppriv(req->uid, req->gid);
	rl.rlim_cur = rl.rlim_max = req->nofiles;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		_exit(EXIT_FAILURE);

	uid = geteuid();
	gid = getegid();
	flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
	    CLONE_NEWUTS;
	if (!req->net)
		flags |= CLONE_NEWNET;
	if (have_ns && unshare(flags) == 0) {
		ns_write("/proc/self/setgroups", "deny");
		snprintf(map, sizeof(map), "%u %u 1", uid, uid);
		if (ns_write("/proc/self/uid_map", map) == -1)
			_exit(EXIT_FAILURE);
		snprintf(map, sizeof(map), "%u %u 1", gid, gid);
		if (ns_write("/proc/self/gid_map", map) == -1)
			_exit(EXIT_FAILURE);
		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1 ||
		    mount("tmpfs", "/tmp", "tmpfs",
			MS_NOSUID | MS_NODEV, "mode=1777,size=64m") == -1) {
			syslog(LOG_ERR, "sandbox: private /tmp for %s: %m",
			    execcmd);
			_exit(EXIT_FAILURE);
		}
		sethostname("phantom-mirage-script",
		    strlen("phantom-mirage-script"));
		sandbox_script_private_tmp = 1;

		/* the script becomes pid 1 of the new PID namespace */
		if ((pid = fork()) == -1)
			_exit(EXIT_FAILURE);
		if (pid > 0) {
			close(fd_io);
			close(fd_err);
			while (waitpid(pid, &status, 0) == -1 && errno == EINTR)
				;
			ns_mirror_exit(status);
		}
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		/* our own /proc; refused where /proc has masked paths */
		mount("proc", "/proc", "proc",
		    MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	}

	if (dup2(fd_io, 0) == -1 || dup2(fd_io, 1) == -1 ||
	    dup2(fd_err, 2) == -1)
		_exit(EXIT_FAILURE);
	if (fd_io > 2)
		close(fd_io);
	if (fd_err > 2)
		close(fd_err);

	sandbox_script(argv);
	/* the daemon's allowlist too, as if the daemon had forked it */
	if (sandbox_daemon_child() == -1)
		_exit(EXIT_FAILURE);
	execvpe(execcmd, argv, envp);
	syslog(LOG_ERR, "sandbox: execv(%s): %m", execcmd);
	_exit(EXIT_FAILURE);
}

/* Everything ns_run() needs: the namespaces, the id maps, a tmpfs */
static int
ns_probe(void)
{
	char map[64];
	pid_t pid;
	int status;
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if ((pid = fork()) == -1)
		return (errno);
	if (pid == 0) {
		if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
			CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET) == -1)
			_exit(errno & 0x7f);
		ns_write("/proc/self/setgroups", "deny");
		snprintf(map, sizeof(map), "%u %u 1", uid, uid);
		if (ns_write("/proc/self/uid_map", map) == -1)
			_exit(errno & 0x7f);
		snprintf(map, sizeof(map), "%u %u 1", gid, gid);
		if (ns_write("/proc/self/gid_map", map) == -1)
			_exit(errno & 0x7f);
		if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1 ||
		    mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
			"mode=1777,size=64m") == -1)
			_exit(errno & 0x7f);
		_exit(0);
	}
	if (waitpid(pid, &status, 0) == -1 || !WIFEXITED(status))
		return (EINVAL);
	return (WEXITSTATUS(status));
}

struct ns_job {
	pid_t pid;
	int chan;
};

static void
ns_launcher(int ctl, pid_t parent)
{
	static struct ns_job jobs[NS_MAXJOBS];
	static struct pollfd pfd[NS_MAXJOBS + 1];
	static char buf[NS_MAXMSG + 1];
	int njobs = 0, have_ns, err, i, n, status, j;
	pid_t pid;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	prctl(PR_SET_NAME, "pm-script-ns");
	if (getppid() != parent)
		_exit(0);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_DFL);
	/* nothing of the daemon's but the control socket and stdio */
	closelog();
	for (i = 3; i < 1024; i++)
		if (i != ctl)
			close(i);

	if ((err = ns_probe()) == 0) {
		have_ns = 1;
		syslog(LOG_NOTICE, "sandbox: scripts run in their own user, "
		    "mount, PID, IPC, UTS and network namespaces with a "
		    "private /tmp");
	} else {
		have_ns = 0;
		syslog(LOG_WARNING, "sandbox: unprivileged user namespaces "
		    "unavailable (%s); scripts run WITHOUT namespaces or a "
		    "private /tmp (Landlock and seccomp still apply)",
		    strerror(err));
	}

	for (;;) {
		pfd[0].fd = ctl;
		pfd[0].events = njobs < NS_MAXJOBS ? POLLIN : 0;
		for (i = 0; i < njobs; i++) {
			pfd[i + 1].fd = jobs[i].chan;
			pfd[i + 1].events = POLLIN;
		}
		n = poll(pfd, njobs + 1, 200);
		if (n == -1 && errno != EINTR)
			_exit(EXIT_FAILURE);

		/* reap: report the exit status to the daemon's child */
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
			for (i = 0; i < njobs; i++)
				if (jobs[i].pid == pid)
					break;
			if (i == njobs)
				continue;
			if (jobs[i].chan != -1) {
				(void)write(jobs[i].chan, &status,
				    sizeof(status));
				close(jobs[i].chan);
			}
			jobs[i] = jobs[--njobs];
		}
		if (n <= 0)
			continue;

		/* the daemon's child went away: kill the script */
		for (i = 0; i < njobs; i++) {
			for (j = 1; j <= njobs; j++)
				if (pfd[j].fd == jobs[i].chan)
					break;
			if (j > njobs || jobs[i].chan == -1 ||
			    !(pfd[j].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			kill(jobs[i].pid, SIGKILL);
			close(jobs[i].chan);
			jobs[i].chan = -1;
		}

		if (pfd[0].revents & (POLLHUP | POLLERR) &&
		    !(pfd[0].revents & POLLIN)) {
			/* the daemon is gone */
			for (i = 0; i < njobs; i++)
				kill(jobs[i].pid, SIGKILL);
			_exit(0);
		}
		if (pfd[0].revents & POLLIN) {
			struct msghdr msg;
			struct iovec iov;
			struct cmsghdr *cm;
			union {
				char buf[CMSG_SPACE(3 * sizeof(int))];
				struct cmsghdr align;
			} cbuf;
			int fds[3] = { -1, -1, -1 }, nfds = 0;
			struct ns_req req;
			ssize_t len;

			memset(&msg, 0, sizeof(msg));
			iov.iov_base = buf;
			iov.iov_len = NS_MAXMSG;
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = cbuf.buf;
			msg.msg_controllen = sizeof(cbuf.buf);
			len = recvmsg(ctl, &msg, MSG_CMSG_CLOEXEC);
			if (len == 0)
				continue;	/* EOF: handled via POLLHUP */
			if (len < 0)
				continue;
			for (cm = CMSG_FIRSTHDR(&msg); cm != NULL;
			    cm = CMSG_NXTHDR(&msg, cm))
				if (cm->cmsg_level == SOL_SOCKET &&
				    cm->cmsg_type == SCM_RIGHTS) {
					nfds = (cm->cmsg_len - CMSG_LEN(0)) /
					    sizeof(int);
					if (nfds > 3)
						nfds = 3;
					memcpy(fds, CMSG_DATA(cm),
					    nfds * sizeof(int));
				}
			buf[len] = '\0';
			memcpy(&req, buf, len >= (ssize_t)sizeof(req) ?
			    sizeof(req) : 0);
			if (nfds != 3 || len < (ssize_t)sizeof(req) ||
			    req.magic != NS_MAGIC || buf[len - 1] != '\0' ||
			    req.argc > 4096 || req.envc > 4096) {
				for (i = 0; i < nfds; i++)
					close(fds[i]);
				continue;
			}
			if ((pid = fork()) == 0) {
				close(ctl);
				for (i = 0; i < njobs; i++)
					if (jobs[i].chan != -1)
						close(jobs[i].chan);
				close(fds[2]);
				ns_run(&req, buf + sizeof(req), fds[0],
				    fds[1], have_ns);
			}
			close(fds[0]);
			close(fds[1]);
			if (pid == -1) {
				status = W_EXITCODE(EXIT_FAILURE, 0);
				(void)write(fds[2], &status, sizeof(status));
				close(fds[2]);
				continue;
			}
			jobs[njobs].pid = pid;
			jobs[njobs].chan = fds[2];
			njobs++;
		}
	}
}

void
sandbox_ns_start(void)
{
	int sv[2];
	pid_t pid, parent = getpid();

	if (!honeyd_sandbox_scripts)
		return;
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == -1) {
		syslog(LOG_WARNING, "sandbox: script launcher: socketpair: "
		    "%m; scripts run without namespaces");
		return;
	}
	if ((pid = fork()) == -1) {
		syslog(LOG_WARNING, "sandbox: script launcher: fork: %m; "
		    "scripts run without namespaces");
		close(sv[0]);
		close(sv[1]);
		return;
	}
	if (pid == 0) {
		close(sv[0]);
		ns_launcher(sv[1], parent);
		_exit(0);
	}
	close(sv[1]);
	ns_ctl = sv[0];
}

/*
 * In the daemon's forked child, after stdio has been set up and the
 * environment built: have the launcher run the script, wait for it and
 * exit the same way.  Returns only if there is no launcher.
 */
/* path appears in s as a whole word (delimited by blanks or quotes) */
static int
ns_has_word(const char *s, const char *path)
{
	size_t l = strlen(path);
	const char *p;

	for (p = s; (p = strstr(p, path)) != NULL; p++)
		if ((p == s || strchr(" \t'\"", p[-1]) != NULL) &&
		    (p[l] == '\0' || strchr(" \t'\"", p[l]) != NULL))
			return (1);
	return (0);
}

void
sandbox_ns_exec(const char *execcmd, char * const argv[], uid_t uid,
    gid_t gid, int nofiles)
{
	extern char **environ;
	static char buf[NS_MAXMSG];
	struct ns_req req;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cm;
	union {
		char buf[CMSG_SPACE(3 * sizeof(int))];
		struct cmsghdr align;
	} cbuf;
	size_t off = sizeof(req), l;
	int chan[2], fds[3], status, i, j;
	ssize_t n;

	if (ns_ctl == -1)
		return;
	/* this process now just waits for the script; keep pgrep -x
	 * phantom-mirage to the daemon */
	prctl(PR_SET_NAME, "pm-script-wait");

	memset(&req, 0, sizeof(req));
	req.magic = NS_MAGIC;
	req.uid = uid;
	req.gid = gid;
	req.nofiles = nofiles;
	for (i = 0; i < nnet_scripts; i++) {
		if (strcmp(execcmd, net_scripts[i]) == 0)
			req.net = 1;
		/* the command may also come as one "sh -c" string */
		for (j = 0; argv[j] != NULL; j++)
			if (ns_has_word(argv[j], net_scripts[i]))
				req.net = 1;
	}
#define PUT(s) do {							\
	l = strlen(s) + 1;						\
	if (off + l > sizeof(buf)) {					\
		syslog(LOG_ERR, "sandbox: %s: command line and "	\
		    "environment too large", execcmd);			\
		_exit(EXIT_FAILURE);					\
	}								\
	memcpy(buf + off, s, l);					\
	off += l;							\
} while (0)
	PUT(execcmd);
	for (i = 0; argv[i] != NULL; i++, req.argc++)
		PUT(argv[i]);
	for (i = 0; environ != NULL && environ[i] != NULL; i++, req.envc++)
		PUT(environ[i]);
#undef PUT
	memcpy(buf, &req, sizeof(req));

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, chan) == -1)
		_exit(EXIT_FAILURE);
	fds[0] = 0;			/* stdin == stdout: the connection */
	fds[1] = 2;			/* stderr: the service log */
	fds[2] = chan[1];
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = off;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf.buf;
	msg.msg_controllen = sizeof(cbuf.buf);
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cm), fds, sizeof(fds));
	if (sendmsg(ns_ctl, &msg, MSG_NOSIGNAL) == -1) {
		syslog(LOG_ERR, "sandbox: script launcher: %m");
		_exit(EXIT_FAILURE);
	}
	/* only the script may hold the connection now */
	close(chan[1]);
	close(ns_ctl);
	i = open("/dev/null", O_RDWR);
	dup2(i, 0);
	dup2(i, 1);
	dup2(i, 2);
	if (i > 2)
		close(i);

	do {
		n = read(chan[0], &status, sizeof(status));
	} while (n == -1 && errno == EINTR);
	if (n != sizeof(status))
		_exit(EXIT_FAILURE);
	ns_mirror_exit(status);
}

#else /* !__linux__ */

void sandbox_ns_start(void) { }
void
sandbox_ns_exec(const char *execcmd, char * const argv[], uid_t uid,
    gid_t gid, int nofiles)
{
}

#endif /* __linux__ */
