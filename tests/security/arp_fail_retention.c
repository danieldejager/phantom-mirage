/*
 * PM-SCR-151, arp.c: an ARP request that got no answer left its failed
 * entry in the table for the full 600 s lifetime of a resolved entry.
 * honeyd_send_ethernet() drops every packet for an address whose entry
 * is not resolved, so one unanswered request blackholed that address
 * for ten minutes and failed entries piled up toward the entry cap.
 *
 * The test resolves one address and lets another fail discovery, then
 * reads the remaining time on each entry's expiry timer: the failed
 * entry must expire within ARP_FAIL_RETENTION (30 s), the resolved one
 * keeps the 600 s lifetime. It then fires the failed entry's expiry and
 * checks that a new request for the address resolves. eth_send is
 * stubbed: nothing leaves the process.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "interface.h"
#include "arp.h"
#include "fuzz_common.h"

extern struct event_base *libevent_base;

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static struct addr src_pa, src_ha;
static int ncalls, nok, bad;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		bad++;
}

static void
cb(struct arp_req *req, int success, void *arg)
{
	ncalls++;
	if (success)
		nok++;
}

static void
request(const char *ip)
{
	struct addr a;

	addr_aton(ip, &a);
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb, NULL);
}

static void
reply(const char *ip, const char *mac)
{
	u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
	struct pcap_pkthdr h;
	struct addr pa, ha;

	addr_aton(ip, &pa);
	addr_aton(mac, &ha);
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

static void
run_for(long usec)
{
	struct timeval tv = {usec / 1000000, usec % 1000000};

	event_base_loopexit(libevent_base, &tv);
	event_base_dispatch(libevent_base);
}

/* Seconds until the entry's expiry timer fires, -1 if none */
static long
expires_in(const char *ip)
{
	struct timeval when, now;
	struct arp_req *r;
	struct addr a;

	addr_aton(ip, &a);
	if ((r = arp_find(&a)) == NULL ||
	    !evtimer_pending(r->active, &when))
		return (-1);
	gettimeofday(&now, NULL);
	return (when.tv_sec - now.tv_sec);
}

int
main(void)
{
	struct addr a;
	struct arp_req *r;
	long ok_left, fail_left;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(10);
	fuzz_honeyd_init(config);
	addr_aton("10.0.0.2", &src_pa);
	addr_aton("02:00:00:00:00:02", &src_ha);

	request("10.0.0.50");
	reply("10.0.0.50", "02:00:00:00:00:50");
	request("10.0.0.51");
	/* Two retransmits 500 ms apart, then the failure callback */
	run_for(1800000);
	check(ncalls == 2 && nok == 1, "one resolved, one failed");

	ok_left = expires_in("10.0.0.50");
	fail_left = expires_in("10.0.0.51");
	printf("resolved expires in %ld s, failed in %ld s\n",
	    ok_left, fail_left);
	check(ok_left > 590 && ok_left <= 600,
	    "resolved entry keeps the 600 s lifetime");
	check(fail_left >= 0 && fail_left <= 30,
	    "failed entry expires within 30 s");

	/* Expire the failed entry, then the address resolves again */
	addr_aton("10.0.0.51", &a);
	if ((r = arp_find(&a)) != NULL) {
		event_active(r->active, EV_TIMEOUT, 1);
		run_for(10000);
	}
	check(arp_find(&a) == NULL, "failed entry gone after expiry");
	request("10.0.0.51");
	reply("10.0.0.51", "02:00:00:00:00:51");
	r = arp_find(&a);
	check(r != NULL && r->cnt == ARP_REQUEST_SUCESS && nok == 2,
	    "retry after expiry resolves");
	check(arp_external_count() == 2, "entry count matches");

	return (bad ? 1 : 0);
}
