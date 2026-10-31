/*
 * honeyd.c tcp_new() (Low, CWE-476/CWE-252, reachable by a remote SYN):
 * the connection timeout and retransmit timers from evtimer_new() were
 * not checked before connection_insert(), so a NULL timer sat on a live,
 * counted connection and later reached evtimer_add() and event_free().
 *
 * Now tcp_new() frees the connection and any first timer when either
 * fails and returns NULL before it is inserted or counted in
 * honeyd_nconnects. Callers (the SYN path and the subsystem connect
 * path) already handle NULL.
 *
 * event_new (evtimer_new is a macro for it) is wrapped for the daemon
 * objects (-Wl,--wrap=event_new): the Nth call from now fails once.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "interface.h"
#include "subsystem.h"
#include "fuzz_common.h"

extern int honeyd_nconnects;
extern struct conlru tcplru;

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
static int fail_at;

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	if (fail_at > 0 && --fail_at == 0)
		return (NULL);
	return (__real_event_new(b, fd, what, cb, arg));
}

static const char config[] =
	"create linux\n"
	"add linux tcp port 80 open\n"
	"bind 10.0.0.2 linux\n";

static int fails;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

static int
live_tcp(void)
{
	struct tuple *t;
	int n = 0;

	TAILQ_FOREACH(t, &tcplru, next)
		n++;
	return (n);
}

int
main(void)
{
	struct ip_hdr ip;
	struct tcp_hdr tcp;
	struct tcp_con *c;
	int which, n0, l0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);

	memset(&ip, 0, sizeof(ip));
	memset(&tcp, 0, sizeof(tcp));
	ip.ip_src = htonl(0x0b000001);
	ip.ip_dst = htonl(0x0a000002);
	tcp.th_sport = htons(4000);
	tcp.th_dport = htons(80);
	tcp.th_flags = TH_SYN;

	n0 = honeyd_nconnects;
	l0 = live_tcp();
	for (which = 1; which <= 2; which++) {
		fail_at = which;
		c = tcp_new(&fuzz_iface, &ip, &tcp, INITIATED_BY_EXTERNAL);
		fail_at = 0;
		printf("tcp_new, timer %d fails\n", which);
		check(c == NULL, "tcp_new returns NULL");
		check(honeyd_nconnects == n0, "honeyd_nconnects unchanged");
		check(live_tcp() == l0, "nothing added to tcplru");
		if (fails)
			return (1);	/* base: a counted flow with a NULL timer */
	}

	c = tcp_new(&fuzz_iface, &ip, &tcp, INITIATED_BY_EXTERNAL);
	check(c != NULL && c->conhdr.timeout != NULL &&
	    c->retrans_timeout != NULL, "next tcp_new works");
	check(honeyd_nconnects == n0 + 1 && live_tcp() == l0 + 1, "counted once");
	if (c != NULL)
		tcp_free(c);
	check(honeyd_nconnects == n0 && live_tcp() == l0, "freed again");

	if (fails)
		return (1);
	printf("PASS: tcp_new_timer\n");
	return (0);
}
