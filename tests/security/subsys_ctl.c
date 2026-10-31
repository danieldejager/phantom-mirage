/*
 * PM-SCR-111, subsystem.c, command.c, fdpass.c: a subsystem could stop
 * the whole daemon over its control channel. SUB_CONNECT from an
 * unknown source address called exit(), SUB_CONNECT on a port bound by
 * someone else hit an assert, a shared SUB_LISTEN on a port missing
 * from one template called exit(), receive_fd() and send_fd() exited on
 * EOF or EPIPE, and a short or missing message on the non blocking
 * control socket spun forever.
 *
 * The descriptors a subsystem passes back were left blocking, so a
 * subsystem that withheld the per connection descriptor, or did not
 * drain its listen descriptor, still blocked the daemon.
 *
 * Each case runs as its own process (argv[1]) under a watchdog alarm,
 * so a spin shows up as a failure. The subsystem side is a local
 * socketpair driven by the harness; nothing is forked.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <dnet.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "fdpass.h"
#include "fuzz_common.h"

extern struct callback subsystem_cb;
void cmd_ready_fd(struct command *, struct callback *, void *);
void subsystem_read(int, short, void *);
struct port *port_insert(struct template *, int, int, struct action *);
struct subsystem *template_subsystem_find(const char *);
int cmd_subsystem_localconnect(struct tuple *, struct command *,
    struct port *, void *);
int cmd_subsystem_connect(struct tuple *, struct command *, struct port *,
    void *);

static const char config[] =
	"create default\n"
	"set default default tcp action block\n"
	"create linux\n"
	"bind 10.0.0.2 linux\n"
	"bind 10.0.0.3 linux\n"
	"add 10.0.0.2 subsystem \"/bin/true\"\n";

static struct subsystem *sub;
static struct template *tmpl, *tmpl2;
static int peer;

static void
setup(void)
{
	int sv[2];

	fuzz_honeyd_init(config);
	tmpl = template_find("10.0.0.2");
	tmpl2 = template_find("10.0.0.3");
	sub = template_subsystem_find("/bin/true");
	if (tmpl == NULL || tmpl2 == NULL || sub == NULL) {
		printf("FAIL: setup\n");
		exit(1);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		abort();
	/* As cmd_subsystem() leaves it: non blocking */
	if (fcntl(sv[0], F_SETFL, O_NONBLOCK) == -1)
		abort();
	sub->cmd.pfd = sv[0];
	sub->cmd.perrfd = -1;
	cmd_ready_fd(&sub->cmd, &subsystem_cb, sub);
	peer = sv[1];
}

static void
mkcmd(struct subsystem_command *c, enum subcmd what, int type,
    const char *lsrc, int lport, const char *rdst, int rport)
{
	struct sockaddr_in *l = (struct sockaddr_in *)&c->sockaddr;
	struct sockaddr_in *r = (struct sockaddr_in *)&c->rsockaddr;

	memset(c, 0, sizeof(*c));
	c->domain = AF_INET;
	c->type = type;
	c->command = what;
	c->len = c->rlen = sizeof(struct sockaddr_in);
	l->sin_family = r->sin_family = AF_INET;
	inet_pton(AF_INET, lsrc, &l->sin_addr);
	l->sin_port = htons(lport);
	inet_pton(AF_INET, rdst, &r->sin_addr);
	r->sin_port = htons(rport);
}

static void
put(struct subsystem_command *c, size_t len)
{
	if (write(peer, c, len) != (ssize_t)len)
		abort();
}

/* Run one command and return the last reply byte */
static int
run(void)
{
	char buf[16];
	ssize_t n;

	subsystem_read(sub->cmd.pfd, EV_READ, sub);
	n = read(peer, buf, sizeof(buf));
	for (ssize_t i = 0; i < n; i++)
		printf("reply byte %d\n", buf[i]);
	return (n > 0 ? buf[n - 1] : -2);
}

static int
expect(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	return (ok ? 0 : 1);
}

int
main(int argc, char **argv)
{
	struct subsystem_command c;
	struct action act;
	struct port *p;
	const char *t = argc > 1 ? argv[1] : "";
	int sv[2], fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	alarm(10);

	if (strcmp(t, "fdpass_eof") == 0) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
			abort();
		close(sv[1]);
		fd = receive_fd(sv[0], NULL, NULL);
		if (expect(fd == -1, "receive_fd on EOF returns -1"))
			return (1);
		fd = send_fd(sv[0], 0, NULL, 0);
		close(sv[0]);
		return (expect(fd == -1, "send_fd on EPIPE returns -1"));
	}

	setup();
	memset(&act, 0, sizeof(act));
	act.status = PORT_OPEN;

	if (strcmp(t, "connect_unknown_src") == 0) {
		mkcmd(&c, SUB_CONNECT, SOCK_STREAM, "10.9.9.9", 0,
		    "192.0.2.1", 80);
		put(&c, sizeof(c));
		return (expect(run() == -1, "unknown source refused"));
	}
	if (strcmp(t, "connect_foreign_port") == 0) {
		/* Port 6000 exists but no subsystem bound it */
		if (port_insert(tmpl, IP_PROTO_TCP, 6000, &act) == NULL)
			abort();
		mkcmd(&c, SUB_CONNECT, SOCK_STREAM, "10.0.0.2", 6000,
		    "192.0.2.1", 80);
		put(&c, sizeof(c));
		return (expect(run() == -1, "foreign port refused"));
	}
	if (strcmp(t, "listen_shared_missing") == 0) {
		/* Bound on the template the lookup starts from only */
		subsystem_insert_template(sub, tmpl2);
		p = port_insert(SPLAY_ROOT(&sub->root)->tmpl, IP_PROTO_TCP,
		    7000, &act);
		if (p == NULL)
			abort();
		p->sub = sub;
		mkcmd(&c, SUB_LISTEN, SOCK_STREAM, "0.0.0.0", 7000,
		    "0.0.0.0", 0);
		put(&c, sizeof(c));
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
			abort();
		if (send_fd(peer, sv[1], NULL, 0) == -1)
			abort();
		close(sv[1]);
		fd = run();
		close(sv[0]);
		return (expect(fd != -1 && fd != -2,
		    "listen succeeds on the bound template"));
	}
	if (strcmp(t, "connect_no_fd") == 0) {
		/* Valid connect, then the subsystem never sends the fd */
		mkcmd(&c, SUB_CONNECT, SOCK_STREAM, "10.0.0.2", 0,
		    "192.0.2.1", 80);
		put(&c, sizeof(c));
		return (expect(run() == -1, "missing descriptor times out"));
	}
	if (strcmp(t, "short_command") == 0) {
		/* Half a command, then silence: the subsystem is dropped */
		mkcmd(&c, SUB_CONNECT, SOCK_STREAM, "10.0.0.2", 0,
		    "192.0.2.1", 80);
		put(&c, sizeof(c) / 2);
		subsystem_read(sub->cmd.pfd, EV_READ, sub);
		return (expect(template_subsystem_find("/bin/true") == NULL,
		    "short command drops the subsystem"));
	}
	if (strcmp(t, "localconnect_no_fd") == 0) {
		/* Control descriptor arrives, the second one never does */
		struct tuple hdr;
		struct command cmd;

		if ((p = port_insert(tmpl, IP_PROTO_TCP, 8000, &act)) == NULL)
			abort();
		p->sub = sub;
		p->sub_fd = -1;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
			abort();
		if (send_fd(peer, sv[1], NULL, 0) == -1)
			abort();
		close(sv[1]);
		memset(&hdr, 0, sizeof(hdr));
		hdr.type = SOCK_STREAM;
		memset(&cmd, 0, sizeof(cmd));
		cmd.pfd = cmd.perrfd = -1;
		fd = cmd_subsystem_localconnect(&hdr, &cmd, p, NULL);
		close(sv[0]);
		return (expect(fd == -1, "withheld descriptor times out"));
	}
	if (strcmp(t, "listen_full") == 0) {
		/* A listen descriptor whose peer never drains it */
		struct tuple hdr;
		struct command cmd;
		char junk[4096];

		if ((p = port_insert(tmpl, IP_PROTO_TCP, 9000, &act)) == NULL)
			abort();
		p->sub = sub;
		mkcmd(&c, SUB_LISTEN, SOCK_STREAM, "10.0.0.2", 9000,
		    "0.0.0.0", 0);
		put(&c, sizeof(c));
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
			abort();
		if (send_fd(peer, sv[1], NULL, 0) == -1)
			abort();
		/* Fill it without changing its blocking mode */
		memset(junk, 0, sizeof(junk));
		while (send(sv[1], junk, sizeof(junk), MSG_DONTWAIT) > 0)
			;
		close(sv[1]);
		if (run() == -1 || p->sub_fd == -1) {
			printf("FAIL: listen not set up\n");
			return (1);
		}
		memset(&hdr, 0, sizeof(hdr));
		hdr.type = SOCK_STREAM;
		memset(&cmd, 0, sizeof(cmd));
		cmd.pfd = cmd.perrfd = -1;
		fd = cmd_subsystem_connect(&hdr, &cmd, p, NULL);
		close(sv[0]);
		return (expect(fd == -1 && cmd.pfd == -1,
		    "undrained listen descriptor times out"));
	}
	printf("FAIL: unknown case %s\n", t);
	return (1);
}
