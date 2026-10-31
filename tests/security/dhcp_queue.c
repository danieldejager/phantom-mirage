/*
 * New Medium finding from the review of PR 199, dhcpclient.c and config.c:
 * the DHCP discover queue holds raw struct template pointers. A template
 * queued by the "dhcp" config statement (parse.y) or by a failed renewal
 * (dhcp_template_new) was never taken off the queue when it was freed, so
 * the next dhcp_send_discover(), run when the template ahead of it gives
 * up, dequeued the freed template and passed it to _dhcp_getconf: a heap
 * use after free. dhcp_req_free() now removes the template from the queue
 * and template_deallocate() always calls it.
 *
 * Two templates are queued the way parse.y does it. The first one starts
 * its discovery, the second one is freed while still queued, and then the
 * first one runs out of retries, which pops the next queue entry exactly
 * like the real timeout path. eth_send is stubbed, nothing leaves the
 * process.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "interface.h"
#include "dhcpclient.h"
#include "fuzz_common.h"
#include "evcount.h"

void template_post_arp(struct template *, struct addr *);

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n"
	"bind 10.0.0.3 linux\n";

static struct template *
setup(const char *ip, const char *mac)
{
	struct template *tmpl;
	struct addr addr;

	if ((tmpl = template_find(ip)) == NULL)
		return (NULL);
	tmpl->ethernet_addr = calloc(1, sizeof(struct addr));
	addr_aton(mac, tmpl->ethernet_addr);
	tmpl->inter = &fuzz_iface;
	addr_aton(ip, &addr);
	template_post_arp(tmpl, &addr);
	return (tmpl);
}

int
main(void)
{
	struct template *a, *b;
	struct dhcpclient_req *req;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	a = setup("10.0.0.2", "02:00:00:00:00:02");
	b = setup("10.0.0.3", "02:00:00:00:00:03");
	if (a == NULL || b == NULL) {
		printf("FAIL: templates not found\n");
		return (1);
	}

	/* As parse.y does for each "dhcp" statement, then honeyd.c starts */
	queue_dhcp_discover(a);
	queue_dhcp_discover(b);
	dhcp_send_discover();
	if ((req = a->dhcp_req) == NULL || req->timeoutEv == NULL) {
		printf("FAIL: first template did not start DHCP\n");
		return (1);
	}

	/* Free the queued template the way a config reload or remove does */
	b->refcnt = 1;
	template_free(b);
	printf("freed queued template, live events %d\n", ev_live);

	/* The first template runs out of retries and pops the next entry */
	req->ntries = 11;	/* NTRIES + 1 */
	event_active(req->timeoutEv, EV_TIMEOUT, 1);
	fuzz_drain_events();

	/* The queue must now be empty: nothing else may be dequeued */
	for (i = 0; i < 2; i++)
		dhcp_send_discover();

	printf("PASS: dhcp_queue\n");
	return (0);
}
