/*
 * honeyd.c honeyd_delay_packet() (Low, CWE-476/CWE-252): the timer for
 * a delayed packet came from an unchecked evtimer_new() and went straight
 * to evtimer_add(), so a failure crashed the daemon and the packet copy,
 * template reference and delay record were never released.
 *
 * Now the packet is dropped with LOG_ERR and everything the callback
 * would have freed is freed: the packet copy (or a caller's packet
 * handed over with DELAY_FREEPKT), the template reference and the delay
 * record.
 *
 * event_new (evtimer_new is a macro for it) is wrapped for the daemon
 * objects (-Wl,--wrap=event_new) and made to fail once. Packets larger
 * than HONEYD_MTU are malloc'ed by the pool, so pool->nalloc shows a
 * leaked copy; LeakSanitizer stays on as well.
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
#include "pool.h"
#include "fuzz_common.h"

extern struct pool *pool_pkt, *pool_delay;
extern struct spoof no_spoof;
void honeyd_delay_packet(struct template *, const struct interface *,
    struct ip_hdr *, u_int, const struct addr *, const struct addr *, int,
    int, struct spoof);

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
static int fail_event_new;

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	if (fail_event_new) {
		fail_event_new = 0;
		return (NULL);
	}
	return (__real_event_new(b, fd, what, cb, arg));
}

static const char config[] =
	"create linux\n"
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
freelist(struct pool *p)
{
	struct pool_entry *e;
	int n = 0;

	SLIST_FOREACH(e, &p->entries, next)
		n++;
	return (n);
}

#define BIG	(HONEYD_MTU + 500)

int
main(void)
{
	static u_char buf[BIG];
	struct ip_hdr *ip = (struct ip_hdr *)buf, *own;
	struct template *tmpl;
	int ref, na, nd;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}
	ip_pack_hdr(ip, 0, BIG, 1, 0, 64, IP_PROTO_UDP,
	    htonl(0x0a000002), htonl(0x0b000001));

	/* Prime the delay pool so its free list is stable */
	nd = freelist(pool_delay);
	if (nd == 0) {
		pool_free(pool_delay, pool_alloc(pool_delay));
		nd = freelist(pool_delay);
	}

	/* Case 1: honeyd_delay_packet makes its own copy of the packet */
	ref = tmpl->refcnt;
	na = pool_pkt->nalloc;
	fail_event_new = 1;
	honeyd_delay_packet(tmpl, NULL, ip, BIG, NULL, NULL, 10, 0, no_spoof);
	fail_event_new = 0;
	check(tmpl->refcnt == ref, "template reference released");
	check(pool_pkt->nalloc == na, "packet copy freed");
	check(freelist(pool_delay) == nd, "delay record back in its pool");

	/* Case 2: caller hands over its packet with DELAY_FREEPKT */
	own = pool_alloc_size(pool_pkt, BIG);
	memcpy(own, ip, BIG);
	fail_event_new = 1;
	honeyd_delay_packet(tmpl, NULL, own, BIG, NULL, NULL, 10,
	    DELAY_FREEPKT, no_spoof);
	fail_event_new = 0;
	check(tmpl->refcnt == ref, "template reference released");
	check(pool_pkt->nalloc == na, "handed over packet freed");
	check(freelist(pool_delay) == nd, "delay record back in its pool");

	if (fails)
		return (1);
	printf("PASS: delay_timer\n");
	return (0);
}
