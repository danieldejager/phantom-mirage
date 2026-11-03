/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dnet.h>
#include <syslog.h>
#include <grp.h>
#include <pcap.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "subsystem.h"
#include "tcp.h"
#include "udp.h"
#include "fdpass.h"
#include "osfp.h"
#include "pyextend.h"
#include "honeyd_overload.h"
#include "util.h"

#include "interface.h"
#include "sandbox.h"

#include "atomicio.h"

extern struct callback cb_tcp;
extern struct callback cb_udp;

void
cmd_trigger_read(struct command *cmd, int size)
{
 	if (cmd->pfd == -1 || !cmd->fdconnected)
		return;
	if (size)
		TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));
}

void
cmd_trigger_write(struct command *cmd, int size)
{
 	if (cmd->pfd == -1 || !cmd->fdconnected)
		return;
	if (size)
		TRACE(event_get_fd(cmd->pwrite), event_add(cmd->pwrite, NULL));
}

/*
 * PM-SCR-152: script processes. Every script child forked by cmd_fork()
 * has an entry in a pid map from fork until honeyd_sigchld() reaps it,
 * so the live count is exact. "option honeyd max_script_procs N" caps
 * the live script processes (default HONEYD_MAX_SCRIPT_PROCS) and
 * "option honeyd max_script_procs_per_source N" caps those started for
 * one source address (default HONEYD_MAX_SCRIPT_PROCS_SOURCE); 0 means
 * no limit. UDP scripts may hold at most half of max_script_procs
 * (rounded up), so a sender that spoofs many UDP source addresses
 * cannot take every slot: TCP needs a completed handshake and keeps the
 * rest (PM-SCR-221, CWE-770). TCP scripts likewise hold at most half
 * (rounded up), so many real TCP sources cannot starve UDP (PM-SCR-234).
 * With an odd cap one slot is shared; with a cap of 1 nothing is
 * reserved. The entry remembers the command that owns the child, and
 * cmd_free() only signals a pid that is still in the map for that same
 * command, so a reaped (and possibly reused) pid is never signalled.
 */
struct scriptproc {
	SPLAY_ENTRY(scriptproc) node;
	pid_t pid;
	ip_addr_t src;
	int udp;		/* started for a UDP flow */
	struct command *cmd;	/* NULL once cmd_free() let go of it */
};

struct scriptsrc {
	SPLAY_ENTRY(scriptsrc) node;
	ip_addr_t addr;
	uint32_t nprocs;
};

static int
scriptproc_compare(struct scriptproc *a, struct scriptproc *b)
{
	return (a->pid < b->pid ? -1 : a->pid > b->pid);
}

static int
scriptsrc_compare(struct scriptsrc *a, struct scriptsrc *b)
{
	return (a->addr < b->addr ? -1 : a->addr > b->addr);
}

static SPLAY_HEAD(scriptproctree, scriptproc) scriptprocs =
    SPLAY_INITIALIZER(&scriptprocs);
static SPLAY_HEAD(scriptsrctree, scriptsrc) scriptsrcs =
    SPLAY_INITIALIZER(&scriptsrcs);
SPLAY_PROTOTYPE(scriptproctree, scriptproc, node, scriptproc_compare);
SPLAY_GENERATE(scriptproctree, scriptproc, node, scriptproc_compare);
SPLAY_PROTOTYPE(scriptsrctree, scriptsrc, node, scriptsrc_compare);
SPLAY_GENERATE(scriptsrctree, scriptsrc, node, scriptsrc_compare);

static uint32_t script_nprocs;
static uint32_t script_nudp;	/* of those, started for UDP flows */
uint32_t cmd_script_refused;	/* flows refused at the cap, ever */

static struct scriptsrc *
scriptsrc_find(ip_addr_t addr)
{
	struct scriptsrc tmp;

	tmp.addr = addr;
	return (SPLAY_FIND(scriptsrctree, &scriptsrcs, &tmp));
}

static struct scriptproc *
scriptproc_find(pid_t pid)
{
	struct scriptproc tmp;

	tmp.pid = pid;
	return (SPLAY_FIND(scriptproctree, &scriptprocs, &tmp));
}

/* Live script processes, all sources */
uint32_t
cmd_script_procs(void)
{
	return (script_nprocs);
}

/* Live script processes started for flows from this source */
uint32_t
cmd_script_source_procs(ip_addr_t addr)
{
	struct scriptsrc *ss = scriptsrc_find(addr);

	return (ss != NULL ? ss->nprocs : 0);
}

/* Live script processes started for UDP flows */
uint32_t
cmd_script_udp_procs(void)
{
	return (script_nudp);
}

/* True if a new script process for this source must be refused */
static int
cmd_script_full(ip_addr_t src, int udp)
{
	uint32_t max;

	max = honeyd_limit_option("max_script_procs",
	    HONEYD_MAX_SCRIPT_PROCS);
	if (max != 0 && script_nprocs >= max)
		return (1);
	/*
	 * Each protocol may hold at most half of the global cap, rounded
	 * up: spoofed UDP cannot take the TCP half (PM-SCR-221) and real
	 * TCP sources cannot take the UDP half (PM-SCR-234).
	 */
	if (max != 0 && udp && script_nudp >= max - max / 2)
		return (1);
	if (max != 0 && !udp && script_nprocs - script_nudp >= max - max / 2)
		return (1);
	max = honeyd_limit_option("max_script_procs_per_source",
	    HONEYD_MAX_SCRIPT_PROCS_SOURCE);
	if (max != 0 && cmd_script_source_procs(src) >= max)
		return (1);
	return (0);
}

/* True if a script for this flow would not be refused at the cap */
int
cmd_script_room(struct tuple *hdr)
{
	return (!cmd_script_full(hdr->ip_src, hdr->type == SOCK_DGRAM));
}

/* At most one log line per second, with the count since the last one */
static void
cmd_script_refuse(struct tuple *hdr)
{
	static time_t last;
	static uint32_t since;
	time_t now = time(NULL);

	cmd_script_refused++;
	since++;
	if (now == last)
		return;
	last = now;
	syslog(LOG_NOTICE, "script process cap reached (%u live): refused "
	    "%u flow(s), latest %s", script_nprocs, since,
	    honeyd_contoa(hdr));
	since = 0;
}

/* Called from honeyd_sigchld() for every reaped pid */
void
cmd_script_reaped(pid_t pid)
{
	struct scriptproc *sp;
	struct scriptsrc *ss;

	if ((sp = scriptproc_find(pid)) == NULL)
		return;
	SPLAY_REMOVE(scriptproctree, &scriptprocs, sp);
	script_nprocs--;
	if (sp->udp)
		script_nudp--;
	if ((ss = scriptsrc_find(sp->src)) != NULL && --ss->nprocs == 0) {
		SPLAY_REMOVE(scriptsrctree, &scriptsrcs, ss);
		free(ss);
	}
	free(sp);
}

/*
 * The flow is gone: kill the script and everything it started. The
 * child made itself a process group leader, and the group cannot be
 * reused while the leader is unreaped, which the map guarantees here.
 * The entry stays (and counts) until the child is reaped.
 */
static void
cmd_script_kill(struct command *cmd)
{
	struct scriptproc *sp;

	if (cmd->pid <= 0 || (sp = scriptproc_find(cmd->pid)) == NULL ||
	    sp->cmd != cmd)
		return;
	sp->cmd = NULL;
	if (killpg(sp->pid, SIGKILL) == -1)
		kill(sp->pid, SIGKILL);
}

void
cmd_free(struct command *cmd)
{
	/* event_free also deletes the event */
	if (cmd->pread != NULL) {
		TRACE(event_get_fd(cmd->pread), event_free(cmd->pread));
		cmd->pread = NULL;
	}

	if (cmd->pwrite != NULL) {
		TRACE(event_get_fd(cmd->pwrite), event_free(cmd->pwrite));
		cmd->pwrite = NULL;
	}

	if (cmd->peread != NULL) {
		TRACE(event_get_fd(cmd->peread), event_free(cmd->peread));
		cmd->peread = NULL;
	}

	cmd_script_kill(cmd);

	TRACE_RESET(cmd->pfd, close(cmd->pfd));
	cmd->pfd = -1;
	cmd->pid = -1;

	if (cmd->perrfd != -1) {
		TRACE_RESET(cmd->perrfd, close(cmd->perrfd));
		cmd->perrfd = -1;
	}

#ifdef HAVE_PYTHON
	if (cmd->state != NULL)
		pyextend_connection_end(cmd->state);
#endif
}

void
cmd_ready_fd(struct command *cmd, struct callback *cb, void *con)
{
	/* Free the connect event from cmd_proxy_connect before replacing it */
	if (cmd->pwrite != NULL) {
		TRACE(event_get_fd(cmd->pwrite), event_free(cmd->pwrite));
		cmd->pwrite = NULL;
	}
	TRACE(cmd->pfd,
		cmd->pread = event_new(libevent_base, cmd->pfd, EV_READ, cb->cb_read, con));
	TRACE(cmd->pfd,
		cmd->pwrite = event_new(libevent_base, cmd->pfd, EV_WRITE, cb->cb_write, con));
	cmd->fdconnected = 1;

	if (cmd->perrfd != -1) {
		TRACE(cmd->perrfd,
			cmd->peread = event_new(libevent_base, cmd->perrfd, EV_READ, cb->cb_eread, con));
	}
}

struct addrinfo *
cmd_proxy_getinfo(char *address, int type, short port)
{
	struct addrinfo ai, *aitop;
        char strport[NI_MAXSERV];

        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = type;
        ai.ai_flags = 0;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                warn("getaddrinfo: %s:%d", address, port);
                return (NULL);
        }

	return (aitop);
}

int
cmd_proxy_connect(struct tuple *hdr, struct command *cmd, struct addrinfo *ai,
    void *con)
{
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	char *host = ntop, *port = strport;
	struct callback *cb;
	struct timeval tv = {10, 0};
        int fd;
        
	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

        fd = socket(AF_INET, hdr->type, 0);
        if (fd == -1) {
                warn("socket");
                return (-1);
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
                warn("fcntl(O_NONBLOCK)");

        if (fcntl(fd, F_SETFD, 1) == -1)
                warn("fcntl(F_SETFD)");

	TRACE(fd, cmd->pfd = fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
		(*cb->cb_connect)(fd, EV_WRITE, con);
		return (0);
	}

	if (errno != EINPROGRESS) {
		warn("connect");
		cmd->pfd = -1;
		TRACE_RESET(fd, close(fd));
		return (-1);
	}

	TRACE(fd,cmd->pwrite = event_new(libevent_base, fd, EV_WRITE, cb->cb_connect, con));
	TRACE(event_get_fd(cmd->pwrite), event_add(cmd->pwrite, &tv));

	if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV) != 0) {

		host = "<hosterror>";
		port = "<porterror>";
	}
	syslog(LOG_INFO, "Connection established: %s -> proxy to %s:%s",
	    honeyd_contoa(hdr), host, port);


	return (0);
}

/*
 * Export a connection variable to a subsystem script.  PHANTOM_MIRAGE_*
 * is the current name; the legacy HONEYD_* name is set as well so
 * existing Honeyd service scripts keep working.
 */
static void
subsys_setenv(const char *suffix, const char *value)
{
	char name[64];

	snprintf(name, sizeof(name), "PHANTOM_MIRAGE_%s", suffix);
	setenv(name, value, 1);
	snprintf(name, sizeof(name), "HONEYD_%s", suffix);
	setenv(name, value, 1);
}

void
cmd_environment(struct template *tmpl, struct tuple *hdr)
{
	char line[256];
	struct addr addr;
	struct ip_hdr ip;
	char *os_name;

	if (tmpl->person != NULL) {
		snprintf(line, sizeof(line), "%s", tmpl->person->name);
		subsys_setenv("PERSONALITY", line);
	}

	if (hdr == NULL)
		return;
	     
	/* Determine the remote operating system */
	ip.ip_src = hdr->ip_src;
	os_name = honeyd_osfp_name(&ip);
	if (os_name != NULL) {
		subsys_setenv("REMOTE_OS", os_name);
	}

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src,IP_ADDR_LEN);
	snprintf(line, sizeof(line), "%s", addr_ntoa(&addr));
	subsys_setenv("IP_SRC", line);

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst,IP_ADDR_LEN);
	snprintf(line, sizeof(line), "%s", addr_ntoa(&addr));
	subsys_setenv("IP_DST", line);

	if (hdr->iface != NULL) {
		snprintf(line, sizeof(line), "%s", hdr->iface->if_ent.intf_name);
		subsys_setenv("INTERFACE", line);
	}

	snprintf(line, sizeof(line), "%s", tmpl->name);
	subsys_setenv("TEMPLATE_NAME", line);

	snprintf(line, sizeof(line), "%d", hdr->sport);
	subsys_setenv("SRC_PORT", line);

	snprintf(line, sizeof(line), "%d", hdr->dport);
	subsys_setenv("DST_PORT", line);
}

#define SETERROR(x) do { \
	snprintf x; \
	strlcat(error, errline, sizeof(error)); \
} while (0)

/* Drop the privileges and verify that they got dropped */

void
cmd_droppriv(uid_t uid, gid_t gid)
{
	static char error[1024];
	static char errline[256];

	error[0] = '\0';

	/* While still privileged: empty bounding/ambient capability sets */
	sandbox_drop_caps_pre();

	/* Lower privileges: supplementary groups, then gid, then uid */
#ifdef HAVE_SETGROUPS
	if (setgroups(1, &gid) == -1) {
		SETERROR((errline, sizeof(errline),
			     "%s: setgroups(%d) failed\n", __func__, gid));
		goto error;
	}
#endif
#ifdef __linux__
	/* Real, effective and saved IDs in one call */
	if (setresgid(gid, gid, gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setresgid(%d) failed\n", __func__, gid));
#elif defined(HAVE_SETREGID)
	if (setregid(gid, gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setregid(%d) failed\n", __func__, gid));
#endif
	if (setegid(gid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setegid(%d) failed\n", __func__, gid));
	if (setgid(gid) == -1)
		SETERROR((errline, sizeof(errline), 
			     "%s: setgid(%d) failed\n", __func__, gid));
#ifdef __linux__
	if (setresuid(uid, uid, uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setresuid(%d) failed\n", __func__, uid));
#elif defined(HAVE_SETREUID)
	if (setreuid(uid, uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setreuid(%d) failed\n", __func__, uid));
#endif
#ifdef __OpenBSD__
	if (seteuid(uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: seteuid(%d) failed\n", __func__, uid));
#endif
	if (setuid(uid) == -1)
		SETERROR((errline, sizeof(errline),
			     "%s: setuid(%d) failed\n", __func__, uid));

	if (getgid() != gid || getegid() != gid) {
		SETERROR((errline, sizeof(errline),
			     "%s: could not set gid to %d", __func__, gid));
		goto error;
	}

	if (getuid() != uid || geteuid() != uid) {
		SETERROR((errline, sizeof(errline),
			     "%s: could not set uid to %d", __func__, uid));
		goto error;
	}

	/* Make really sure that we dropped them */
	if (uid != 0 && (setuid(0) != -1 || seteuid(0) != -1)) {
		SETERROR((errline, sizeof(errline),
			     "%s: did not successfully drop privilege",
			     __func__));
		goto error;
	}
	if (gid != 0 && (setgid(0) != -1 || setegid(0) != -1)) {
		SETERROR((errline, sizeof(errline),
			     "%s: did not successfully drop privilege",
			     __func__));
		goto error;
	}

	/* no_new_privs; verify saved IDs and capabilities are gone (#16) */
	sandbox_verify_post(uid, gid);

	return;
 error:
 syslog(LOG_ERR, "%s", error);
 syslog(LOG_ERR,"%s: terminated",__func__);
 exit(EXIT_FAILURE);
}

int
cmd_setpriv(struct template *tmpl)
{
	extern uid_t honeyd_uid;
	extern gid_t honeyd_gid;
	uid_t uid = honeyd_uid;
	gid_t gid = honeyd_gid;
	int nofiles = 30;
	struct rlimit rl;

	/* Set our own priority low */
	setpriority(PRIO_PROCESS, 0, 10);

	if (tmpl->uid)
		uid = tmpl->uid;
	if (tmpl->gid)
		gid = tmpl->gid;
	if (tmpl->max_nofiles)
		nofiles = tmpl->max_nofiles;

	cmd_droppriv(uid, gid);

	/* Raising file descriptor limits */
	rl.rlim_cur = rl.rlim_max = nofiles;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
	{
		syslog(LOG_ERR, "setrlimit: %d, failed to set resource limit", nofiles);
		exit(EXIT_FAILURE);
	}

	return (0);
}

int
cmd_fork(struct tuple *hdr, struct command *cmd, struct template *tmpl,
    char *execcmd, char **argv, void *con)
{
	extern int honeyd_nchildren;
	int pair[2], perr[2];
	struct callback *cb;
	struct scriptproc *sp;
	struct scriptsrc *ss;
	sigset_t sigmask;
	/* SOCK_SEQPACKET keeps datagram boundaries for UDP scripts and,
	 * unlike SOCK_DGRAM, gives the script EOF when the flow ends */
	int type = hdr->type == SOCK_DGRAM ? SOCK_SEQPACKET : hdr->type;

	if (cmd_script_full(hdr->ip_src, hdr->type == SOCK_DGRAM)) {
		cmd_script_refuse(hdr);
		cmd->pfd = -1;
		return (CMD_FORK_CAP);
	}
	if ((sp = calloc(1, sizeof(*sp))) == NULL)
		return (-1);
	if ((ss = scriptsrc_find(hdr->ip_src)) == NULL) {
		if ((ss = calloc(1, sizeof(*ss))) == NULL) {
			free(sp);
			return (-1);
		}
		ss->addr = hdr->ip_src;
		SPLAY_INSERT(scriptsrctree, &scriptsrcs, ss);
	}
	/* counted from here on; undone by script_undo on failure */
	ss->nprocs++;

	if (socketpair(AF_UNIX, type, 0, pair) == -1)
		goto script_undo;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, perr) == -1) {
		TRACE_RESET(pair[0], close(pair[0]));
		TRACE_RESET(pair[1], close(pair[1]));
		goto script_undo;
	}

	/* Block SIGCHLD */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}

	cmd->pid = fork();
	if (cmd->pid == -1) {
		warn("fork");
		goto unmask_err;
	}

	if (cmd->pid == 0) {
		/* Own process group, so cmd_free() also kills what the
		 * script starts */
		setpgid(0, 0);

		/* Child privileges */
		sandbox_script_prepare(argv);
		cmd_setpriv(tmpl);

		/* Child */
		TRACE_RESET(pair[0], close(pair[0]));
		if (dup2(pair[1], fileno(stdout)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2 failed to copy descriptor",__func__);
			exit(EXIT_FAILURE);
		}
		if (dup2(pair[1], fileno(stdin)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}
		TRACE_RESET(pair[0], close(perr[0]));
		if (dup2(perr[1], fileno(stderr)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}

		TRACE_RESET(pair[1], close(pair[1]));
		TRACE_RESET(perr[1], close(perr[1]));

		cmd_environment(tmpl, hdr);
		/* --sandbox-scripts: own namespaces via the launcher */
		sandbox_ns_exec(execcmd, argv, geteuid(), getegid(),
		    tmpl->max_nofiles ? tmpl->max_nofiles : 30);
		sandbox_script(argv);

		if (execvp(execcmd, argv) == -1)
		{
			syslog(LOG_ERR, "%s: execv(%s): %s", __func__, execcmd, strerror(errno));
			exit(EXIT_FAILURE);
		}

		/* NOT REACHED */
	}

	/* Also from the parent, so the group exists before any kill;
	 * EACCES once the child has exec'd is fine, it did it itself */
	setpgid(cmd->pid, cmd->pid);
	sp->pid = cmd->pid;
	sp->src = hdr->ip_src;
	sp->udp = hdr->type == SOCK_DGRAM;
	sp->cmd = cmd;
	SPLAY_INSERT(scriptproctree, &scriptprocs, sp);
	script_nprocs++;
	if (sp->udp)
		script_nudp++;

	TRACE_RESET(pair[1], close(pair[1]));
	TRACE(pair[0], cmd->pfd = pair[0]);
	if (fcntl(cmd->pfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(cmd->pfd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	TRACE_RESET(perr[1], close(perr[1]));
	cmd->perrfd = perr[0];
	if (fcntl(cmd->perrfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(cmd->perrfd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

	cmd_ready_fd(cmd, cb, con);

	TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));
	TRACE(event_get_fd(cmd->peread), event_add(cmd->peread, NULL));

	honeyd_nchildren++;

	/*
	 * The child runs and is accounted for, so never unwind from here:
	 * that would close descriptors its events still use. Retry the
	 * unblock once so SIGCHLD (and so reaping) is not left blocked.
	 */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1)
			syslog(LOG_ERR, "%s: SIGCHLD stays blocked: %m",
			    __func__);
	}
	return (0);

	/* Error cleanup */
 unmask_err:
	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1)
		warn("sigprocmask");

 fork_err:
	TRACE_RESET(perr[0], close(perr[0]));
	TRACE_RESET(perr[1], close(perr[1]));
	TRACE_RESET(pair[0], close(pair[0]));
	TRACE_RESET(pair[1], close(pair[1]));
	cmd->pfd = -1;

 script_undo:
	if (--ss->nprocs == 0) {
		SPLAY_REMOVE(scriptsrctree, &scriptsrcs, ss);
		free(ss);
	}
	free(sp);
	cmd->pid = -1;
	cmd->pfd = -1;
	return (-1);
}

int
cmd_python(struct tuple *hdr, struct command *cmd, void *con)
{
	int pair[2];
	struct callback *cb;

	if (socketpair(AF_UNIX, hdr->type, 0, pair) == -1)
		return (-1);

	TRACE(pair[0], cmd->pfd = pair[0]);
	if (fcntl(cmd->pfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(cmd->pfd, F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	/* Python descriptors should not go across exec */
	if (fcntl(pair[1], F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	if (fcntl(pair[1], F_SETFL, O_NONBLOCK) == -1)
		warn("fcntl(F_SETFL)");

	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

	cmd_ready_fd(cmd, cb, con);

	TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));

	return (pair[1]);
}

int
cmd_subsystem(struct template *tmpl, struct subsystem *sub,
    char *execcmd, char **argv)
{
	extern int honeyd_nchildren;
	struct command *cmd = &sub->cmd;
	extern struct callback subsystem_cb;
	int pair[2];
	sigset_t sigmask;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (-1);

	/* Block SIGCHLD */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}

	cmd->pid = fork();
	if (cmd->pid == -1) {
		warn("fork");
		goto unmask_err;
	}

	if (cmd->pid == 0) {
		char magic_buf[12];
		int magic_fd;
		/* Set privileges */
		sandbox_script_prepare(argv);
		cmd_setpriv(tmpl);

		/* Child */
		TRACE_RESET(pair[0], close(pair[0]));
		/* Set the communication fd */
		if ((magic_fd = dup(pair[1])) == -1)
		{
			syslog(LOG_ERR, "%s: dup(%d): no magic failed to duplicate the pair", __func__, pair[1]);
			exit(EXIT_FAILURE);
		}
		snprintf(magic_buf, sizeof(magic_buf), "%d", magic_fd);
		setenv(SUBSYSTEM_MAGICFD, magic_buf, 1);
		if (dup2(fileno(stderr), fileno(stdout)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}
		if (dup2(fileno(stderr), fileno(stdin)) == -1)
		{
			syslog(LOG_ERR, "%s: dup2", __func__);
			exit(EXIT_FAILURE);
		}

		TRACE_RESET(pair[1], close(pair[1]));

		cmd_environment(tmpl, NULL);

		/* Setup the wrapper library */
		if (setenv("LD_PRELOAD", PATH_HONEYDLIB"/libphantom-mirage.so", 1) == -1)
		{
			syslog(LOG_ERR, "%s: setenv", __func__);
			exit(EXIT_FAILURE);
		}

		sandbox_script(argv);
		if (execv(execcmd, argv) == -1)
		{
			int e = errno, ea, eo, fd;
			char rp[PATH_MAX];
			ea = access(execcmd, X_OK) == -1 ? errno : 0;
			fd = open(execcmd, O_RDONLY | O_CLOEXEC);
			eo = fd == -1 ? errno : 0;
			if (fd != -1)
				close(fd);
			int ed, ee;
			fd = open("/usr/bin", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
			ed = fd == -1 ? errno : 0;
			if (fd != -1)
				close(fd);
			fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
			ee = fd == -1 ? errno : 0;
			if (fd != -1)
				close(fd);
			syslog(LOG_ERR, "%s: execv(%s): %s (realpath %s, "
			    "access X_OK: %s, open: %s, /usr/bin: %s, "
			    "/etc/passwd: %s, uid %d)", __func__,
			    execcmd, strerror(e),
			    realpath(execcmd, rp) ? rp : "?",
			    strerror(ea), strerror(eo), strerror(ed),
			    strerror(ee), (int)geteuid());
			exit(EXIT_FAILURE);
		}

		/* NOT REACHED */
	}

	TRACE_RESET(pair[1], close(pair[1]));
	TRACE(pair[0], cmd->pfd = pair[0]);
	if (fcntl(cmd->pfd, F_SETFD, 1) == -1)
		warn("fcntl(F_SETFD)");
	/* Control channel reads and writes are bounded, never blocking */
	if (fcntl(cmd->pfd, F_SETFL, O_NONBLOCK) == -1)
		syslog(LOG_ERR, "%s: fcntl(O_NONBLOCK): %s", __func__,
		    strerror(errno));

	cmd->perrfd = -1;
	cmd_ready_fd(cmd, &subsystem_cb, sub);

	TRACE(event_get_fd(cmd->pread), event_add(cmd->pread, NULL));

	honeyd_nchildren++;

	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1) {
		warn("sigprocmask");
		goto fork_err;
	}
	return (0);

	/* Error cleanup */
 unmask_err:
	/* Install old signal handler */
	if (sigprocmask(SIG_UNBLOCK, &sigmask, NULL) == -1)
		warn("sigprocmask");

 fork_err:
	TRACE_RESET(pair[0], close(pair[0]));
	TRACE_RESET(pair[1], close(pair[1]));
	cmd->pfd = -1;

	return (-1);
}

static void
cmd_subsystem_connect_cb(int fd, short what, void *arg)
{
	struct port_encapsulate *tmp = arg;
	struct tuple *hdr = tmp->hdr;
	struct command *cmd = tmp->cmd;
	struct port *port = tmp->port;
	void *con = tmp->con;

	/*
	 * The callback owns tmp once it fires: unlink it from the port and
	 * the connection and free it (and its event) before acting, so
	 * nothing below can reach it again.
	 */
	port_encapsulation_free(tmp);

	/*
	 * CWE-252/CWE-404: a connection the subsystem never got fails now.
	 * A UDP flow is freed rather than left to its idle timeout; for
	 * TCP, tcp_connectfail only releases the buffers, sends no reset
	 * and leaves the connection to its TCP timeout.
	 */
	if (what != EV_WRITE ||
	    cmd_subsystem_connect(hdr, cmd, port, con) == -1) {
		if (hdr->type == SOCK_STREAM)
			tcp_connectfail(con);
		else
			udp_free(con);
	}
}

/* Send errors after which nothing was written and the channel is fine */
static int
cmd_subsystem_send_transient(int error)
{
	switch (error) {
	case ETIMEDOUT:		/* EAGAIN until the deadline */
	case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
	case ENOBUFS:
	case ENOMEM:
	case ETOOMANYREFS:
	case EINTR:
		return (1);
	default:
		return (0);
	}
}

/*
 * Closes a port channel that can no longer be trusted to be in frame and
 * fails the connections waiting on it (UDP flows are freed; TCP ones go
 * through tcp_connectfail and wait for their TCP timeout).  The subsystem may bind the port
 * again; until then connects to it are refused.
 */
static void
cmd_subsystem_reset_port(struct port *port)
{
	struct port_encapsulate *tmp;
	struct tuple *hdr;
	void *con;

	while ((tmp = TAILQ_FIRST(&port->pending)) != NULL) {
		hdr = tmp->hdr;
		con = tmp->con;
		port_encapsulation_free(tmp);
		if (hdr == NULL)
			continue;
		if (hdr->type == SOCK_STREAM)
			tcp_connectfail(con);
		else
			udp_free(con);
	}

	if (port->sub_fd != -1) {
		syslog(LOG_WARNING, "%s: closing out of frame channel to "
		    "subsystem \"%s\"", __func__, port->sub->cmdstring);
		TRACE(port->sub_fd, fdshare_close(port->sub_fd));
		port->sub_fd = -1;
	}
}

int
cmd_subsystem_schedule_connect(struct tuple *hdr, struct command *cmd,
    struct port *port, void *con)
{
	struct port_encapsulate *tmp;
	struct subsystem *sub = port->sub;

	/* The channel was closed after an error */
	if (port->sub_fd == -1)
		return (-1);

	if ((tmp = calloc(1, sizeof(*tmp))) == NULL)
		return (-1);

	tmp->hdr = hdr;
	tmp->cmd = cmd;
	tmp->port = port;
	tmp->con = con;

	TRACE(port->sub_fd,
	    tmp->ev = event_new(libevent_base, port->sub_fd, EV_WRITE,
		cmd_subsystem_connect_cb, tmp));
	if (tmp->ev == NULL) {
		free(tmp);
		return (-1);
	}

	/* Tell the connection that it has a pending connection */
	hdr->pending = tmp;
	TAILQ_INSERT_TAIL(&port->pending, tmp, next);

	TRACE(event_get_fd(tmp->ev),
		event_add(tmp->ev, NULL));

	syslog(LOG_DEBUG,
	    "Scheduling connection establishment: %s -> subsystem \"%s\"",
	    honeyd_contoa(hdr), sub->cmdstring);

	return (0);
}

int
cmd_subsystem_connect(struct tuple *hdr, struct command *cmd,
    struct port *port, void *con)
{
	struct callback *cb;
	struct subsystem *sub = port->sub;
	struct bundle bundle;
	struct addr src, dst;
	int pair[2];
        
	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

        if (socketpair(AF_LOCAL, hdr->type, 0, pair) == -1) {
                warn("%s: socketpair: %s", __func__, sub->cmdstring);
                return (-1);
        }

        if (fcntl(pair[0], F_SETFL, O_NONBLOCK) == -1)
                warn("fcntl(O_NONBLOCK)");

        if (fcntl(pair[0], F_SETFD, 1) == -1)
                warn("fcntl(F_SETFD)");

	TRACE(pair[0], cmd->pfd = pair[0]);

	/* Prepare sockaddr for both src and destination */
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_src,IP_ADDR_LEN);
	addr_ntos(&src, (struct sockaddr *)&bundle.src);
	bundle.src.sin_port = htons(hdr->sport);
	addr_pack(&dst, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst,IP_ADDR_LEN);
	addr_ntos(&dst, (struct sockaddr *)&bundle.dst);
	bundle.dst.sin_port = htons(hdr->dport);

	if (send_fd_timed(port->sub_fd, pair[1], &bundle, sizeof(bundle),
	    SUBSYSTEM_IO_TIMEOUT) == -1) {
		int serrno = errno;

		TRACE_RESET(pair[0], close(pair[0]));
		TRACE_RESET(pair[1], close(pair[1]));
		cmd->pfd = -1;
		/*
		 * CWE-664/CWE-755: a partial send (reported as EPIPE) leaves
		 * the channel out of frame, and a hard error leaves it
		 * unusable, so it is closed.  A transient error sent
		 * nothing; only this connection fails and the channel is
		 * kept, so a connect flood cannot deny the port for good.
		 */
		if (!cmd_subsystem_send_transient(serrno))
			cmd_subsystem_reset_port(port);
		return (-1);
	}

	/* After transfering the file descriptor, we may close it */
	TRACE_RESET(pair[1], close(pair[1]));

	/* We are connected now */
	(*cb->cb_connect)(pair[0], EV_WRITE, con);

	syslog(LOG_INFO, "Connection established: %s -> subsystem \"%s\"",
	    honeyd_contoa(hdr), sub->cmdstring);

	return (0);
}

/*
 * Called when the 3-way handshake for a connection initiated by a
 * subsystem completed successfully.
 */

int
cmd_subsystem_localconnect(struct tuple *hdr, struct command *cmd,
    struct port *port, void *con)
{
	struct callback *cb;
	struct subsystem *sub = port->sub;
	struct sockaddr_in si;
	struct addr src;
	int fd;
        
	if (hdr->type == SOCK_STREAM)
		cb = &cb_tcp;
	else
		cb = &cb_udp;

	/*
	 * If we do not have a control file descriptor for this connection,
	 * then get it now.  The control file descriptor will give us the
	 * fd that is used for the real communication.
	 */
	if (port->sub_fd == -1) {
		char res;

		fd = receive_fd_timed(sub->cmd.pfd, NULL, NULL,
		    SUBSYSTEM_IO_TIMEOUT);
		if (fd == -1)
			syslog(LOG_ERR, "%s: receive_fd: %s", __func__,
			    strerror(errno));
		else {
			TRACE(fd, port->sub_fd = fdshare_dup(fd));
			if (port->sub_fd == -1) {
				/* CWE-252/CWE-775: not shared, close it */
				syslog(LOG_ERR, "%s: fdshare_dup failed",
				    __func__);
				TRACE_RESET(fd, close(fd));
				fd = -1;
			}
		}

		/* Confirm success of failure */
		res = fd == -1 ? -1 : 0;
		TRACE(sub->cmd.pfd,
		    atomicio_timed(vwrite, sub->cmd.pfd, &res, 1,
		    SUBSYSTEM_IO_TIMEOUT));
		if (fd == -1)
			return (-1);
	}

	/* Get another fd on this special thingy */
	fd = receive_fd_timed(port->sub_fd, NULL, NULL, SUBSYSTEM_IO_TIMEOUT);
	if (fd == -1) {
		TRACE(port->sub_fd, fdshare_close(port->sub_fd));
		port->sub_fd = -1;
		syslog(LOG_ERR, "%s: receive_fd: %s", __func__,
		    strerror(errno));
		return (-1);
	}

	/* receive_fd_timed already made fd non blocking */

        if (fcntl(fd, F_SETFD, 1) == -1)
                warn("%s: fcntl(F_SETFD)", __func__);

	TRACE(fd, cmd->pfd = fd);

	/* Prepare sockaddr */
	addr_pack(&src, ADDR_TYPE_IP, IP_ADDR_BITS, &hdr->ip_dst, IP_ADDR_LEN);
	addr_ntos(&src, (struct sockaddr *)&si);
	si.sin_port = htons(hdr->dport);

	/* Write the bound socket address to the other side */
	if (atomicio_timed(vwrite, port->sub_fd, &si, sizeof(si),
	    SUBSYSTEM_IO_TIMEOUT) != sizeof(si)) {
		TRACE(port->sub_fd, fdshare_close(port->sub_fd));
		port->sub_fd = -1;
		TRACE_RESET(cmd->pfd, close(cmd->pfd));
		cmd->pfd = -1;
		return (-1);
	}

	/* Now we may close the special thingy */
	TRACE(port->sub_fd, fdshare_close(port->sub_fd));
	port->sub_fd = -1;

	/* We are connected now */
	(*cb->cb_connect)(fd, EV_WRITE, con);

	syslog(LOG_INFO, "Connection established: subsystem \"%s\" -> %s",
	    sub->cmdstring, honeyd_contoa(hdr));

	return (0);
}
