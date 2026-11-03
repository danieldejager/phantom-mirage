/*
 * PM-SCR-112, PM-SCR-193, subsystem.c, config.c, honeyd.c: a subsystem
 * port carries one back pointer (sub_conport) to the connection that
 * uses it and one shared descriptor (sub_fd).
 *
 * connect_shared: two SUB_CONNECT commands from the same bound local
 * port both succeeded. The second overwrote sub_conport and sub_fd, so
 * when the port went away only the newer connection was told; freeing
 * the older one ran port_free() on freed memory.
 *
 * connect_listening: SUB_CONNECT from a port that is listening replaced
 * the listen descriptor and leaked its reference.
 *
 * connect_fail_bound: a SUB_CONNECT that failed after the connection
 * was created freed the port the subsystem had bound, through tcp_free(),
 * so the subsystem's binding vanished under it.
 *
 * listen_twice: a second SUB_LISTEN on a listening port overwrote
 * sub_fd and the first reference was never released; a successful
 * SUB_LISTEN replied with the low byte of a descriptor number instead
 * of 0.
 *
 * Each case runs as its own process (argv[1]) under a 10 s alarm. The
 * subsystem side is a local socketpair; nothing is forked or sent.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
#include "util.h"
#include "fuzz_common.h"

extern struct callback subsystem_cb;
extern struct conlru tcplru;
void cmd_ready_fd(struct command *, struct callback *, void *);
void subsystem_read(int, short, void *);
void subsystem_readyport(struct port *, struct subsystem *,
    struct template *);
struct subsystem *template_subsystem_find(const char *);

static const char config[] =
	"create default\n"
	"set default default tcp action block\n"
	"create linux\n"
	"bind 10.0.0.2 linux\n"
	"add 10.0.0.2 subsystem \"/bin/true\"\n";

static struct subsystem *sub;
static struct template *tmpl;
static int peer;

static void
setup(void)
{
	int sv[2];

	fuzz_honeyd_init(config);
	tmpl = template_find("10.0.0.2");
	sub = template_subsystem_find("/bin/true");
	if (tmpl == NULL || sub == NULL) {
		printf("FAIL: setup\n");
		exit(1);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		abort();
	if (fcntl(sv[0], F_SETFL, O_NONBLOCK) == -1)
		abort();
	sub->cmd.pfd = sv[0];
	sub->cmd.perrfd = -1;
	cmd_ready_fd(&sub->cmd, &subsystem_cb, sub);
	peer = sv[1];
}

static void
mkcmd(struct subsystem_command *c, enum subcmd what, int lport, int rport)
{
	struct sockaddr_in *l = (struct sockaddr_in *)&c->sockaddr;
	struct sockaddr_in *r = (struct sockaddr_in *)&c->rsockaddr;

	memset(c, 0, sizeof(*c));
	c->domain = AF_INET;
	c->type = SOCK_STREAM;
	c->command = what;
	c->len = c->rlen = sizeof(struct sockaddr_in);
	l->sin_family = r->sin_family = AF_INET;
	inet_pton(AF_INET, "10.0.0.2", &l->sin_addr);
	l->sin_port = htons(lport);
	inet_pton(AF_INET, "192.0.2.1", &r->sin_addr);
	r->sin_port = htons(rport);
}

/*
 * Send one command, optionally followed by a descriptor, run it and
 * return the last reply byte. *keep gets our end of the descriptor.
 */
static int
run(enum subcmd what, int lport, int rport, int withfd, int *keep)
{
	struct subsystem_command c;
	char buf[16];
	ssize_t n;
	int sv[2];

	mkcmd(&c, what, lport, rport);
	if (write(peer, &c, sizeof(c)) != (ssize_t)sizeof(c))
		abort();
	if (withfd) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
			abort();
		if (send_fd(peer, sv[1], NULL, 0) == -1)
			abort();
		close(sv[1]);
		*keep = sv[0];
	}
	subsystem_read(sub->cmd.pfd, EV_READ, sub);
	n = read(peer, buf, sizeof(buf));
	return (n > 0 ? buf[n - 1] : -2);
}

static struct port *
bound(int number)
{
	struct action act;
	struct port *p;

	memset(&act, 0, sizeof(act));
	act.status = PORT_RESERVED;
	if ((p = port_insert(tmpl, IP_PROTO_TCP, number, &act)) == NULL)
		abort();
	subsystem_readyport(p, sub, tmpl);
	return (p);
}

static int
expect(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	return (ok ? 0 : 1);
}

/* Free every TCP connection, oldest last, as idle expiry would */
static void
free_all(void)
{
	struct tuple *hdr;

	while ((hdr = TAILQ_FIRST(&tcplru)) != NULL)
		tcp_free((struct tcp_con *)hdr);
}

int
main(int argc, char **argv)
{
	const char *t = argc > 1 ? argv[1] : "";
	struct port *p;
	int a = -1, b = -1, r1, r2, fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	alarm(10);
	setup();

	if (strcmp(t, "connect_shared") == 0) {
		p = bound(5000);
		r1 = run(SUB_CONNECT, 5000, 80, 1, &a);
		r2 = run(SUB_CONNECT, 5000, 81, 1, &b);
		printf("replies %d %d\n", r1, r2);
		/* The subsystem closes the binding, then both flows end */
		if (run(SUB_CLOSE, 5000, 0, 0, NULL) == -2)
			abort();
		free_all();
		close(a);
		if (b != -1)
			close(b);
		return (expect(r1 == 0 && r2 == -1,
		    "second connect from a used port refused") |
		    expect(port_find(tmpl, IP_PROTO_TCP, 5000) == NULL,
		    "port gone after close"));
	}
	if (strcmp(t, "connect_listening") == 0) {
		p = bound(5100);
		if (run(SUB_LISTEN, 5100, 0, 1, &a) != 0)
			printf("listen reply not 0\n");
		fd = p->sub_fd;
		r1 = run(SUB_CONNECT, 5100, 80, 1, &b);
		free_all();
		r2 = expect(r1 == -1 && p->sub_fd == fd &&
		    fdshare_inspect(fd) == 1,
		    "connect from a listening port refused, listen fd kept");
		close(a);
		close(b);
		return (r2);
	}
	if (strcmp(t, "connect_fail_bound") == 0) {
		p = bound(5200);
		/* The subsystem never sends the per connection descriptor */
		r1 = run(SUB_CONNECT, 5200, 80, 0, NULL);
		p = port_find(tmpl, IP_PROTO_TCP, 5200);
		r2 = expect(r1 == -1 && p != NULL && p->sub == sub &&
		    p->sub_conport == NULL && TAILQ_EMPTY(&tcplru),
		    "failed connect keeps the binding");
		if (p == NULL)
			return (1);
		/* The binding still works: a real connect succeeds */
		r1 = run(SUB_CONNECT, 5200, 80, 1, &a);
		free_all();
		close(a);
		return (r2 | expect(r1 == 0, "binding usable afterwards"));
	}
	if (strcmp(t, "listen_twice") == 0) {
		p = bound(5300);
		r1 = run(SUB_LISTEN, 5300, 0, 1, &a);
		fd = p->sub_fd;
		r2 = run(SUB_LISTEN, 5300, 0, 1, &b);
		printf("replies %d %d fd %d now %d\n", r1, r2, fd, p->sub_fd);
		r1 = expect(r1 == 0, "listen replies 0") |
		    expect(r2 == -1 && p->sub_fd == fd &&
		    fdshare_inspect(fd) == 1,
		    "second listen refused, first reference kept");
		/* Closing the port releases the only reference */
		run(SUB_CLOSE, 5300, 0, 0, NULL);
		r1 |= expect(fcntl(fd, F_GETFD) == -1,
		    "listen fd closed with the port");
		close(a);
		close(b);
		return (r1);
	}
	printf("FAIL: unknown case %s\n", t);
	return (1);
}
