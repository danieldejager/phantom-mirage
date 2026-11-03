/*
 * ARP callback must run once per request. A pending request used to
 * run its callback on every ARP reply for its address, and again on a
 * reply that came after the request had already failed. The callback
 * used for outgoing packets, honeyd_ether_send_cb(), sends and then
 * frees the queued packet, so the second run read, sent and freed a
 * packet that was already freed.
 *
 * "twice": queue a packet with honeyd_send_ethernet(), then feed two
 * ARP replies for the same address into arp_recv_cb().
 * "late": queue a packet, let the discovery timer give up (failure
 * callback), then feed one late ARP reply.
 * The packet is sized off the pool so pool_free() really frees it.
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
#include "pool.h"
#include "fuzz_common.h"

extern struct pool *pool_pkt;
extern struct event_base *libevent_base;
void honeyd_send_ethernet(struct interface *, struct addr *, struct addr *,
    struct addr *, struct ip_hdr *, u_int);

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static void
reply(struct addr *from_pa, struct addr *from_ha, struct addr *to_pa)
{
	u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
	struct pcap_pkthdr h;

	memset(pkt, 0, sizeof(pkt));
	eth_pack_hdr(pkt, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    from_ha->addr_eth, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(pkt + ETH_HDR_LEN, ARP_OP_REPLY, from_ha->addr_eth,
	    from_pa->addr_ip, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    to_pa->addr_ip);
	memset(&h, 0, sizeof(h));
	h.caplen = h.len = sizeof(pkt);
	arp_recv_cb((u_char *)&fuzz_iface, &h, pkt);
}

int
main(int argc, char **argv)
{
	struct addr src_pa, src_ha, dst_pa, dst_ha;
	struct ip_hdr *ip;
	struct arp_req *req;
	int late = argc > 1 && strcmp(argv[1], "late") == 0;
	u_int iplen = IP_HDR_LEN + 8;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();

	addr_aton("10.0.0.2", &src_pa);
	addr_aton("02:00:00:00:00:02", &src_ha);
	addr_aton("10.0.0.50", &dst_pa);
	addr_aton("02:00:00:00:50:01", &dst_ha);

	ip = pool_alloc_size(pool_pkt, 64);
	memset(ip, 0, 64);
	ip_pack_hdr(ip, 0, iplen, 1, 0, 64, IP_PROTO_UDP,
	    src_pa.addr_ip, dst_pa.addr_ip);
	honeyd_send_ethernet(&fuzz_iface, &src_pa, &src_ha, &dst_pa, ip,
	    iplen);
	req = arp_find(&dst_pa);
	if (req == NULL) {
		printf("FAIL: no pending ARP request\n");
		return (1);
	}

	if (late) {
		/* Two retries 0.5s apart, then the failure callback */
		struct timeval tv = {1, 700000};
		event_base_loopexit(libevent_base, &tv);
		event_base_dispatch(libevent_base);
		printf("request gave up, cnt %d\n", req->cnt);
		reply(&dst_pa, &dst_ha, &src_pa);
	} else {
		reply(&dst_pa, &dst_ha, &src_pa);
		printf("first reply handled\n");
		reply(&dst_pa, &dst_ha, &src_pa);
	}
	printf("second callback opportunity handled\n");
	if (req->cb != NULL || req->arg != NULL) {
		printf("FAIL: callback still armed after it ran\n");
		return (1);
	}
	return (0);
}
