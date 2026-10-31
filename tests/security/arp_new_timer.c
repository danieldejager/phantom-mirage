/*
 * arp.c arp_new() (Low, CWE-476/CWE-252): the two evtimer_new() results
 * were not checked, and the entry was already in the address trees
 * when they were made. A NULL timer then reached evtimer_add() in
 * arp_request() and event_free() in arp_free().
 *
 * Now arp_new() makes both timers first, frees the entry and the first
 * timer when either fails, and returns NULL before the entry is in any
 * tree. arp_request() then fails its callback once (so a queued packet
 * is freed) and counts nothing against the PM-SCR-139 ARP caps.
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
#include "interface.h"
#include "arp.h"
#include "fuzz_common.h"

int arp_pending_count(void) __attribute__((weak));
int arp_external_count(void) __attribute__((weak));

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
static int fail_at;	/* 0: never; N: the Nth call from now fails */

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	if (fail_at > 0 && --fail_at == 0)
		return (NULL);
	return (__real_event_new(b, fd, what, cb, arg));
}

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static int fails, calls, failed;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

static void
cb(struct arp_req *req, int success, void *arg)
{
	calls++;
	if (!success)
		failed++;
}

static void
ipaddr(uint32_t ip, struct addr *a)
{
	ip = htonl(ip);
	addr_pack(a, ADDR_TYPE_IP, IP_ADDR_BITS, &ip, IP_ADDR_LEN);
}

static int
pending(void)
{
	return (arp_pending_count != NULL ? arp_pending_count() : 0);
}

static int
external(void)
{
	return (arp_external_count != NULL ? arp_external_count() : 0);
}

int
main(void)
{
	struct addr src_pa, src_ha, a;
	struct arp_req *req;
	int which, np, ne;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	ipaddr(0x0a000002, &src_pa);
	addr_pton("00:11:22:33:44:55", &src_ha);

	/* arp_new directly: first timer fails, then second timer fails */
	for (which = 1; which <= 2; which++) {
		ipaddr(0x0a000064 + which, &a);
		fail_at = which;
		req = arp_new(&fuzz_iface, &src_pa, &src_ha, &a, NULL);
		fail_at = 0;
		printf("arp_new, timer %d fails\n", which);
		check(req == NULL, "arp_new returns NULL");
		check(arp_find(&a) == NULL, "entry not in the address tree");
		if (fails)
			return (1);	/* base: a live entry with a NULL timer */
	}

	/* arp_request: nothing counted, callback fails exactly once */
	np = pending();
	ne = external();
	ipaddr(0x0a0000c8, &a);
	fail_at = 2;
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb, NULL);
	fail_at = 0;
	check(calls == 1 && failed == 1, "callback ran once with failure");
	check(arp_find(&a) == NULL, "no entry left for the address");
	check(pending() == np && external() == ne, "ARP cap counts unchanged");

	/* Success path still works and frees cleanly */
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb, NULL);
	req = arp_find(&a);
	check(req != NULL && req->active != NULL && req->discover != NULL,
	    "next arp_request creates an entry with both timers");
	check(pending() == np + 1 && external() == ne + 1, "counted once");
	if (req != NULL)
		arp_free(req);
	check(pending() == np && external() == ne, "uncounted on free");

	if (fails)
		return (1);
	printf("PASS: arp_new_timer\n");
	return (0);
}
