/*
 * Copyright (c) 2001, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <grp.h>

#include "config.h"

#include <event.h>
#include <dnet.h>

#include "honeyd.h"
#include "ui.h"
#include "parser.h"
#ifdef HAVE_PYTHON
#include "pyextend.h"
#endif

char *ui_file = UI_FIFO;

/* Peers allowed on the control socket besides root (see ui_init) */
static uid_t ui_owner_uid;
static gid_t ui_allowed_gid;
static int ui_have_group;

#define PROMPT		"phantom-mirage-ctl> "
#define WHITESPACE	" \t"

char *strnsep(char **, char *);

int ui_command_help(struct evbuffer *, char *);
int ui_command_python(struct evbuffer *, char *);

struct ui_command {
	char *cmd;
	char *short_help;
	char *long_help;
	int (*func)(struct evbuffer *, char *);
};

struct ui_command commands[] = {
	{
		"help",
		"help\t\t outputs a command help\n",
		"help [command]\n",
		ui_command_help
	},
	{
		"!",
		"!\t\t runs a Python command in the daemon environment\n",
		"! <command >",
		ui_command_python
	},
	{
		"delete",
		"delete\t\t removes configured templates and ports\n",
		"delete <template|template proto port number>\n",
	},
	{
		"list",
		"list\t\t lists configured templates or subsystems\n",
		"list <template [pattern]|subsystem [pattern]>\n",
	},
	{
		NULL, NULL, NULL, NULL
	}
};

char tmpbuf[1024];

char *
make_prompt(void)
{
	static char tmp[128];
	extern int honeyd_nconnects;
	extern int honeyd_nchildren;
	extern int honeyd_nudp;
	extern uint32_t honeyd_udp_evicted;
	extern int arp_external_count(void);
	extern uint32_t arp_pending_rejected(void), arp_external_evicted(void);

	snprintf(tmp, sizeof(tmp), "%dC %dU %uE %dA %uR %uV %dP %s",
	    honeyd_nconnects, honeyd_nudp, honeyd_udp_evicted,
	    arp_external_count(), arp_pending_rejected(),
	    arp_external_evicted(), honeyd_nchildren, PROMPT);

	return (tmp);
}

int
ui_write_prompt(struct uiclient *client)
{
	char *tmp = make_prompt();

	evbuffer_add(client->outbuf, tmp, strlen(tmp));
	event_add(client->ev_write, NULL);

	return (0);
}

int
ui_buffer_prompt(struct uiclient *client)
{
	char *tmp = make_prompt();

	evbuffer_add(client->outbuf, tmp, strlen(tmp));
	return (0);
}

void
ui_dead(struct uiclient *client)
{
	syslog(LOG_NOTICE, "%s: ui on fd %d is gone", __func__, client->fd);

	event_free(client->ev_read);	/* also deletes them */
	event_free(client->ev_write);

	close(client->fd);
	evbuffer_free(client->inbuf);
	evbuffer_free(client->outbuf);
	free(client);
}

int
ui_command_python(struct evbuffer *buf, char *line)
{
#ifndef HAVE_PYTHON
	const char *error_python = 
	    "Error: Phantom Mirage has been compiled without Python support.\n";
	evbuffer_add(buf, error_python, strlen(error_python));
#else
	pyextend_run(buf, line);
#endif
	return (0);
}

int
ui_command_help(struct evbuffer *buf, char *line)
{
	char output[1024];
	struct ui_command *cmd;
	char *command;

	command = strnsep(&line, WHITESPACE);
	if (command != NULL && strlen(command)) {
		for (cmd = commands; cmd->cmd; cmd++) {
			/* Find out what command was sent.  */
			if (strcasecmp(cmd->cmd, command) == 0)
				break;
		}
		if (cmd->cmd == NULL) {
			snprintf(output, sizeof(output),
			    "Error: unknown command \"%s\"\n", command);
			evbuffer_add(buf, output, strlen(output));
			return (0);
		}
		evbuffer_add(buf, cmd->long_help, strlen(cmd->long_help));
	
	} else {
		for (cmd = commands; cmd->cmd; cmd++)
			evbuffer_add(buf,
			    cmd->short_help, strlen(cmd->short_help));
	}

	return (0);
}

void
ui_handle_command(struct evbuffer *buf, char *original)
{
	char output[1024];
	char *command, *line = original;
	struct ui_command *cmd;

	command = strnsep(&line, WHITESPACE);
	if (!strlen(command))
		return;

	for (cmd = commands; cmd->cmd; cmd++) {
		/* Find out what command was sent.  */
		if (strcasecmp(cmd->cmd, command) == 0)
			break;
	}
	
	if (cmd->func == NULL) {
		/* Restore the original line and send it to the parser */
		if (line != NULL)
			original[strlen(command)] = ' ';
		parse_line(buf, original);
		return;
	}

	if ((*cmd->func)(buf, line) == -1) {
		snprintf(output, sizeof(output), "%s%s",
			 "ui_handle_command: missing arguments\n",
			 cmd->short_help);
		evbuffer_add(buf, output, strlen(output));
	}

	return;
}

void
ui_writer(int fd, short what, void *arg)
{
	struct uiclient *client = arg;
	struct evbuffer *buffer = client->outbuf;
	int n;

	n = evbuffer_write(buffer, fd);
	if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
			goto schedule;
		ui_dead(client);
		return;
	} else if (n == 0) {
		ui_dead(client);
		return;
	}

	evbuffer_drain(buffer, n);

 schedule:
	if (evbuffer_get_length(buffer))
		event_add(client->ev_write, NULL);
}

void
ui_handler(int fd, short what, void *arg)
{
	struct uiclient *client = arg;
	struct evbuffer *mybuf = client->inbuf;

	if (evbuffer_read(mybuf, fd, -1) <= 0)
	{
		ui_dead(client);
		return;
	}

	size_t length;
	char *line;

	line = evbuffer_readln(mybuf, &length, EVBUFFER_EOL_LF);
	while(line != NULL)
	{
		ui_handle_command(client->outbuf, line);

		evbuffer_drain(mybuf, length);
		line = evbuffer_readln(mybuf, &length, EVBUFFER_EOL_LF);
	}

	ui_write_prompt(client);
	event_add(client->ev_read, NULL);
}

void
ui_greeting(struct uiclient *client)
{
	struct timeval tv;
	extern struct timeval honeyd_uptime;

	gettimeofday(&tv, NULL);
	timersub(&tv, &honeyd_uptime, &tv);
	evbuffer_add_printf(client->outbuf,
	    PRODUCT_NAME " %s Management Console (based on Honeyd)\n"
	    "Copyright (c) 2004 Niels Provos.  All rights reserved.\n"
	    "See LICENSE for licensing information.\n"
	    "Up for %ld seconds.\n",
	    VERSION, tv.tv_sec);
}

void
ui_new(int fd, short what, void *arg)
{
	int newfd;
	struct uiclient *client;

	if ((newfd = accept(fd, NULL, NULL)) == -1) {
		warn("%s: accept", __func__);
		return;
	}

#ifdef SO_PEERCRED
	{
		struct ucred cred;
		socklen_t len = sizeof(cred);

		/* Only root, our own uid or the configured group may talk
		 * to the control socket. */
		if (getsockopt(newfd, SOL_SOCKET, SO_PEERCRED, &cred,
			&len) == -1 || len != sizeof(cred)) {
			syslog(LOG_WARNING, "%s: SO_PEERCRED: %m; "
			    "rejecting ui connection", __func__);
			close(newfd);
			return;
		}
		if (cred.uid != 0 && cred.uid != ui_owner_uid &&
		    !(ui_have_group && cred.gid == ui_allowed_gid)) {
			syslog(LOG_WARNING, "%s: rejected ui connection from "
			    "pid %ld uid %ld gid %ld", __func__, (long)cred.pid,
			    (long)cred.uid, (long)cred.gid);
			close(newfd);
			return;
		}
	}
#endif

	if ((client = calloc(1, sizeof(struct uiclient))) == NULL) {
		warn("%s: calloc", __func__);
		close(newfd);
		return;
	}

	client->fd = newfd;
	client->inbuf = evbuffer_new();
	client->outbuf = evbuffer_new();

	if (client->inbuf == NULL || client->outbuf == NULL)
	{
		syslog(LOG_ERR, "%s: evbuffer_new",__func__);
		exit(EXIT_FAILURE);
	}

	syslog(LOG_NOTICE, "%s: New ui connection on fd %d", __func__, newfd);

	client->ev_read = event_new(libevent_base, newfd, EV_READ, ui_handler, client);
	event_priority_set(client->ev_read, 0);
	event_add(client->ev_read, NULL);

	client->ev_write = event_new(libevent_base, newfd, EV_WRITE, ui_writer, client);
	event_priority_set(client->ev_write, 0);

	ui_greeting(client);
	ui_write_prompt(client);
}

/*
 * Create (or validate) the socket directory: a real directory, not a
 * symlink, owned by us, mode 0700 (0750 with the ui group).
 */
static void
ui_init_dir(const char *dir, mode_t mode, gid_t gid)
{
	struct stat st;
	int fd;

	if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
		syslog(LOG_ERR, "%s: mkdir %s: %m", __func__, dir);
		exit(EXIT_FAILURE);
	}
	fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd == -1 || fstat(fd, &st) == -1) {
		syslog(LOG_ERR, "%s: open %s: %m", __func__, dir);
		exit(EXIT_FAILURE);
	}
	if (st.st_uid != geteuid()) {
		syslog(LOG_ERR, "%s: %s is owned by uid %ld, not us; refusing",
		    __func__, dir, (long)st.st_uid);
		exit(EXIT_FAILURE);
	}
	if (st.st_gid != gid && fchown(fd, -1, gid) == -1) {
		syslog(LOG_ERR, "%s: chown %s: %m", __func__, dir);
		exit(EXIT_FAILURE);
	}
	if ((st.st_mode & 07777) != mode && fchmod(fd, mode) == -1) {
		syslog(LOG_ERR, "%s: chmod %s: %m", __func__, dir);
		exit(EXIT_FAILURE);
	}
	close(fd);
}

void
ui_init(void)
{
	struct stat st;
	struct sockaddr_un ifsun;
	int ui_socket;
	mode_t dir_mode = 0700, sock_mode = 0600, omask;
	gid_t gid = getegid();
	const char *group = pm_getenv("UI_GROUP");

	ui_owner_uid = geteuid();
	if (group != NULL && *group != '\0') {
		struct group *gr = getgrnam(group);
		if (gr == NULL) {
			syslog(LOG_ERR, "%s: unknown group %s=%s", __func__,
			    UI_GROUP_ENV, group);
			exit(EXIT_FAILURE);
		}
		gid = gr->gr_gid;
		ui_allowed_gid = gid;
		ui_have_group = 1;
		dir_mode = 0750;
		sock_mode = 0660;
	}

	if (strcmp(ui_file, UI_FIFO) == 0)
		ui_init_dir(UI_DIR, dir_mode, gid);

	/* Only ever replace a stale socket; lstat does not follow links */
	if (lstat(ui_file, &st) == 0) {
		if (!S_ISSOCK(st.st_mode)) {
			syslog(LOG_ERR, "%s: %s exists and is not a socket; "
			    "refusing to replace it", __func__, ui_file);
			exit(EXIT_FAILURE);
		}
		if (unlink(ui_file) == -1) {
			syslog(LOG_ERR, "%s: unlink %s: %m", __func__, ui_file);
			exit(EXIT_FAILURE);
		}
	} else if (errno != ENOENT) {
		syslog(LOG_ERR, "%s: lstat %s: %m", __func__, ui_file);
		exit(EXIT_FAILURE);
	}

        ui_socket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ui_socket == -1)
        {
        	syslog(LOG_ERR, "%s: socket", __func__);
        	exit(EXIT_FAILURE);
        }
        if (setsockopt(ui_socket, SOL_SOCKET, SO_REUSEADDR,
                       &ui_socket, sizeof (ui_socket)) == -1)
        {
        	syslog(LOG_ERR, "%s: setsockopt", __func__);
        	exit(EXIT_FAILURE);
        }

        memset(&ifsun, 0, sizeof (ifsun));
        ifsun.sun_family = AF_UNIX;
        strlcpy(ifsun.sun_path, ui_file, sizeof(ifsun.sun_path));
#ifdef HAVE_SUN_LEN
        ifsun.sun_len = strlen(ifsun.sun_path);
#endif /* HAVE_SUN_LEN */
	/* No window where the socket is more open than sock_mode */
	omask = umask(~sock_mode & 0777);
        if (bind(ui_socket, (struct sockaddr *)&ifsun, sizeof (ifsun)) == -1)
        {
        	syslog(LOG_ERR, "%s: bind error: %s", __func__, strerror(errno));
        	exit(EXIT_FAILURE);
        }
	umask(omask);
	if (chown(ui_file, -1, gid) == -1 || chmod(ui_file, sock_mode) == -1) {
		syslog(LOG_ERR, "%s: chown/chmod %s: %m", __func__, ui_file);
		exit(EXIT_FAILURE);
	}

        if (listen(ui_socket, 5) == -1)
        {
        	syslog(LOG_ERR, "%s: listen error: %s", __func__, strerror(errno));
        	exit(EXIT_FAILURE);
        }

	struct event *ev_accept = event_new(libevent_base, ui_socket, EV_READ | EV_PERSIST, ui_new, NULL);
	event_priority_set(ev_accept, 0);
	event_add(ev_accept, NULL);
}
