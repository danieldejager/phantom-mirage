/*
 * honeyd_ether_send_cb() ignored its success argument. When an ARP
 * request for a queued packet failed (discovery gave up, or the entry
 * was evicted at the entry cap) on a request with an interface, the
 * packet was sent anyway to req->ha, which is still the broadcast MAC.
 * On failure the packet must be dropped, freed exactly once, and
 * nothing sent; on success it is sent once to the resolved MAC.
 *
 * eth_send is stubbed and recorded: nothing leaves the process. Queued
 * packets are sized off the pool so pool_free() really frees them and
 * LeakSanitizer reports one that is not freed.
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

static struct addr src_pa, src_ha;
static int nip, nbcast;
static u_char lastdst[ETH_ADDR_LEN];

/* Count IP frames; ARP requests are broadcast by design */
static void
record(const void *buf, size_t len)
{
	const struct eth_hdr *eth = buf;

	if (len < ETH_HDR_LEN || ntohs(eth->eth_type) != ETH_TYPE_IP)
		return;
	nip++;
	memcpy(lastdst, &eth->eth_dst, ETH_ADDR_LEN);
	if (memcmp(&eth->eth_dst, ETH_ADDR_BROADCAST, ETH_ADDR_LEN) == 0)
		nbcast++;
}

static void
queue_to(const char *dst)
{
	struct addr pa;
	struct ip_hdr *ip;
	u_int iplen = IP_HDR_LEN + 8;

	addr_aton(dst, &pa);
	ip = pool_alloc_size(pool_pkt, 64);
	memset(ip, 0, 64);
	ip_pack_hdr(ip, 0, iplen, 1, 0, 64, IP_PROTO_UDP,
	    src_pa.addr_ip, pa.addr_ip);
	honeyd_send_ethernet(&fuzz_iface, &src_pa, &src_ha, &pa, ip, iplen);
}

static void
reply(const char *pa_s, const char *ha_s)
{
	u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
	struct pcap_pkthdr h;
	struct addr pa, ha;

	addr_aton(pa_s, &pa);
	addr_aton(ha_s, &ha);
	memset(pkt, 0, sizeof(pkt));
	eth_pack_hdr(pkt, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    ha.addr_eth, ETH_TYPE_ARP);
	arp_pack_hdr_ethip(pkt + ETH_HDR_LEN, ARP_OP_REPLY, ha.addr_eth,
	    pa.addr_ip, fuzz_iface.if_ent.intf_link_addr.addr_eth,
	    src_pa.addr_ip);
	memset(&h, 0, sizeof(h));
	h.caplen = h.len = sizeof(pkt);
	arp_recv_cb((u_char *)&fuzz_iface, &h, pkt);
}

static int
expect(const char *what, int want_ip, int want_bcast)
{
	int bad = nip != want_ip || nbcast != want_bcast;

	printf("%s: %d IP frames sent, %d to the broadcast MAC%s\n", what,
	    nip, nbcast, bad ? " FAIL" : "");
	nip = nbcast = 0;
	return (bad);
}

int
main(void)
{
	struct timeval tv = {1, 700000};
	int fail = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();
	fuzz_eth_send_hook = record;
	addr_aton("10.0.0.2", &src_pa);
	addr_aton("02:00:00:00:00:02", &src_ha);

	/* Success path: one frame to the resolved MAC */
	queue_to("10.0.0.50");
	reply("10.0.0.50", "02:00:00:00:50:01");
	fail |= expect("ARP reply", 1, 0);
	if (memcmp(lastdst, "\x02\x00\x00\x00\x50\x01", ETH_ADDR_LEN) != 0) {
		printf("FAIL reply: wrong destination MAC\n");
		fail = 1;
	}
	queue_to("10.0.0.50");		/* resolved entry, sent at once */
	fail |= expect("resolved entry", 1, 0);

	/* Discovery gives up: two retries 0.5 s apart, then failure */
	queue_to("10.0.0.51");
	event_base_loopexit(libevent_base, &tv);
	event_base_dispatch(libevent_base);
	fail |= expect("ARP discovery failed", 0, 0);

	/* Entry cap of one: the pending entry is evicted with failure */
	arp_set_limits(0, 1);
	queue_to("10.0.0.52");
	queue_to("10.0.0.53");
	fail |= expect("pending entry evicted", 0, 0);
	arp_set_limits(0, 0);

	printf(fail ? "FAIL\n" : "OK\n");
	return (fail);
}
