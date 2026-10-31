/*
 * An ARP reply rewrote the MAC of an external (discovered) entry. That
 * entry is not in the hardware address splay tree, but arp_free() did
 * SPLAY_FIND and then SPLAY_REMOVE by its MAC. A LAN host replying
 * with the MAC of one of honeyd's own (ARP_INTERNAL) entries made the
 * expiry of the external entry remove the internal node, so lookups by
 * that MAC (the DHCP path) failed afterwards.
 *
 * Resolve an outside IP, feed a reply carrying the internal MAC, free
 * the external entry as arp_timeout() does, then look up the internal
 * entry by MAC and by IP.
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

int
main(void)
{
	u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
	struct pcap_pkthdr h;
	struct addr pa, ha, ext, src;
	struct arp_req *req, *ereq;
	int fail = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();

	/* honeyd's own emulated host */
	addr_aton("10.0.0.77", &pa);
	addr_aton("02:00:00:00:77:01", &ha);
	req = arp_new(&fuzz_iface, NULL, NULL, &pa, &ha);
	req->flags |= ARP_INTERNAL;

	/* an outside host being resolved */
	addr_aton("10.0.0.88", &ext);
	addr_aton("10.0.0.2", &src);
	arp_request(&fuzz_iface, &src, &fuzz_iface.if_ent.intf_link_addr,
	    &ext, NULL, NULL);
	if ((ereq = arp_find(&ext)) == NULL) {
		printf("FAIL: no external entry\n");
		return (1);
	}

	/* the outside host answers with the internal entry's MAC */
	memset(pkt, 0, sizeof(pkt));
	eth_pack_hdr(pkt, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    ha.addr_eth, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(pkt + ETH_HDR_LEN, ARP_OP_REPLY, ha.addr_eth,
	    ext.addr_ip, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    src.addr_ip);
	memset(&h, 0, sizeof(h));
	h.caplen = h.len = sizeof(pkt);
	arp_recv_cb((u_char *)&fuzz_iface, &h, pkt);
	printf("external entry MAC after reply: %s\n", addr_ntoa(&ereq->ha));

	/* expiry: arp_timeout() calls arp_free() */
	arp_free(ereq);

	if (arp_find(&ha) != req) {
		printf("FAIL: lookup by MAC no longer finds internal entry\n");
		fail = 1;
	}
	if (arp_find(&pa) != req) {
		printf("FAIL: lookup by IP no longer finds internal entry\n");
		fail = 1;
	}
	if (arp_find(&ext) != NULL) {
		printf("FAIL: external entry still findable by IP\n");
		fail = 1;
	}
	if (!fail)
		printf("internal entry intact\n");
	arp_free(req);
	return (fail);
}
