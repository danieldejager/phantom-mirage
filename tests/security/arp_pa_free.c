/*
 * arp_free() removed its node from the protocol address tree by key.
 * A request created while another entry for the same address is still
 * in the tree is not inserted (SPLAY_INSERT refuses the duplicate).
 * Freeing that request later removed whichever live entry then held
 * the address, so the address could no longer be found.
 *
 * Reached through arp_request() with a callback that requests the same
 * address again when it is evicted at the entry cap. The daemon's own
 * callback, honeyd_ether_send_cb(), does not re-enter, so the guard is
 * defence in depth for the daemon. eth_send is stubbed.
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

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static struct addr src_pa, src_ha;
static int again;

static void
nop(struct arp_req *req, int success, void *arg)
{
}

static void request(const char *, void (*)(struct arp_req *, int, void *));

/* On eviction, ask for the same address again once */
static void
reenter(struct arp_req *req, int success, void *arg)
{
	if (!success && !again++)
		request("10.0.0.70", nop);
}

static void
request(const char *s, void (*cb)(struct arp_req *, int, void *))
{
	struct addr a;

	addr_aton(s, &a);
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb, NULL);
}

int
main(void)
{
	struct addr x;
	struct arp_req *live;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();
	addr_aton("10.0.0.2", &src_pa);
	addr_aton("02:00:00:00:00:02", &src_ha);
	addr_aton("10.0.0.70", &x);

	/* A(x) and Z pending; Y evicts A, whose callback creates B(x) */
	arp_set_limits(0, 2);
	request("10.0.0.70", reenter);
	request("10.0.0.71", nop);
	request("10.0.0.72", nop);
	printf("after eviction: entry for x %s\n",
	    arp_find(&x) != NULL ? "present" : "absent");

	/* C(x) goes into the tree; B is not in it */
	arp_set_limits(0, 0);
	request("10.0.0.70", nop);
	live = arp_find(&x);
	if (live == NULL) {
		printf("FAIL: no entry for x\n");
		return (1);
	}

	/* Entry cap 3: B, the oldest, is evicted and freed */
	arp_set_limits(0, 3);
	request("10.0.0.73", nop);
	arp_set_limits(0, 0);

	if (arp_find(&x) != live) {
		printf("FAIL: freeing a request outside the tree removed the "
		    "live entry for x\n");
		return (1);
	}
	printf("OK\n");
	return (0);
}
