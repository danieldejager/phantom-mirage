/*
 * PM-SCR-010: an ARP reply whose sender IP matched one of honeyd's own
 * (ARP_INTERNAL) entries overwrote that entry's MAC before the internal
 * check. The entry stayed in the hardware address splay tree under its
 * old position, so lookups by the original MAC failed afterwards.
 *
 * One forged reply goes into arp_recv_cb() on the fake interface; the
 * entry's MAC and its lookup by MAC must be unchanged.
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
	struct addr pa, ha, evil, them;
	struct arp_req *req;
	int fail = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();

	addr_aton("10.0.0.77", &pa);
	addr_aton("02:00:00:00:77:01", &ha);
	addr_aton("02:00:00:00:66:01", &evil);
	addr_aton("10.0.0.99", &them);
	req = arp_new(&fuzz_iface, NULL, NULL, &pa, &ha);
	req->flags |= ARP_INTERNAL;

	memset(pkt, 0, sizeof(pkt));
	eth_pack_hdr(pkt, ETH_ADDR_BROADCAST, evil.addr_eth, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(pkt + ETH_HDR_LEN, ARP_OP_REPLY, evil.addr_eth,
	    pa.addr_ip, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    them.addr_ip);
	memset(&h, 0, sizeof(h));
	h.caplen = h.len = sizeof(pkt);
	arp_recv_cb((u_char *)&fuzz_iface, &h, pkt);

	printf("entry MAC after forged reply: %s\n", addr_ntoa(&req->ha));
	if (addr_cmp(&req->ha, &ha) != 0) {
		printf("FAIL: internal entry MAC overwritten\n");
		fail = 1;
	}
	if (arp_find(&ha) != req) {
		printf("FAIL: lookup by original MAC no longer finds entry\n");
		fail = 1;
	}
	if (arp_find(&pa) != req) {
		printf("FAIL: lookup by IP no longer finds entry\n");
		fail = 1;
	}
	arp_free(req);
	return (fail);
}
