/*
 * PM-SCR-007, command.c: cmd_free() only called event_del() on the read,
 * write and stderr events that cmd_ready_fd() creates for a scripted or
 * proxied TCP or UDP connection, so each connection leaked up to three
 * events. cmd_ready_fd() also overwrote the connect event that
 * cmd_proxy_connect() leaves in cmd->pwrite.
 *
 * The descriptors are local pipes and socketpairs. The proxy case puts
 * an event in cmd->pwrite the way cmd_proxy_connect() does, since the
 * harness stubs connect().
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "fuzz_common.h"
#include "evcount.h"

extern struct event_base *libevent_base;
extern struct callback cb_tcp;
void cmd_ready_fd(struct command *, struct callback *, void *);

#define ROUNDS	100

static void
setup(struct command *cmd, int with_err)
{
	int sv[2], pe[2];

	memset(cmd, 0, sizeof(*cmd));
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		abort();
	close(sv[1]);
	cmd->pfd = sv[0];
	cmd->perrfd = -1;
	if (with_err) {
		if (pipe(pe) == -1)
			abort();
		close(pe[1]);
		cmd->perrfd = pe[0];
	}
}

int
main(void)
{
	struct command cmd;
	int i, base;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(NULL);

	/* Script with stdout and stderr: pread, pwrite and peread */
	base = ev_live;
	for (i = 0; i < ROUNDS; i++) {
		setup(&cmd, 1);
		cmd_ready_fd(&cmd, &cb_tcp, NULL);
		event_add(cmd.pread, NULL);
		cmd_free(&cmd);
	}
	ev_check("script", ROUNDS, ev_live - base, 0);

	/* Proxy: connect event in pwrite, then cmd_ready_fd, then free */
	base = ev_live;
	for (i = 0; i < ROUNDS; i++) {
		setup(&cmd, 0);
		cmd.pwrite = event_new(libevent_base, cmd.pfd, EV_WRITE,
		    cb_tcp.cb_connect, NULL);
		cmd_ready_fd(&cmd, &cb_tcp, NULL);
		cmd_free(&cmd);
	}
	ev_check("proxy", ROUNDS, ev_live - base, 0);

	if (ev_fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: cmd_free_ev\n");
	return (0);
}
