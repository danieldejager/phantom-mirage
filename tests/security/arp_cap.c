/*
 * PM-SCR-139 (ARP): state created by arp_request() had no cap. Pending
 * requests are capped (reject new, failure callback once) and counted
 * entries are capped (evict oldest, failure callback once if still
 * pending, then free). Internal entries are never counted or evicted.
 *
 * Modes:
 *   evict    evicted entry is pending; its queued packet goes through
 *            honeyd_ether_send_cb() once (leaks stay on); an internal
 *            entry survives a flood of 10000 requests
 *   reject   default pending cap 256: request 257 and later are refused,
 *            counted, and their callback runs once with failure
 *   order    entry cap 8: entries are evicted oldest first
 *   count    counters stay >= 0 and match the live entries across the
 *            reply, discovery failure, timeout and eviction paths
 *   option   "option honeyd max_arp_pending 4" and max_arp_entries 8
 *            from the configuration take effect
 *   reenter  callbacks that call arp_request() again during rejection
 *            and eviction (ASan catches any use after free)
 *
 * The new arp.c symbols are weak so the test links on a tree without
 * the caps and fails there. eth_send is stubbed: nothing leaves the
 * process.
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

void arp_set_limits(int, int) __attribute__((weak));
int arp_pending_count(void) __attribute__((weak));
int arp_external_count(void) __attribute__((weak));
uint32_t arp_pending_rejected(void) __attribute__((weak));
uint32_t arp_external_evicted(void) __attribute__((weak));

#define NMAX	10000
#define IP(i)	(0x0a000000 + 100 + (i))	/* 10.0.0.100 and up */

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static struct addr src_pa, src_ha;
static int calls[NMAX], fails[NMAX], fails_total, depth;
static int fails_check;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails_check++;
}

static int
have_caps(void)
{
	return (arp_set_limits != NULL && arp_pending_count != NULL &&
	    arp_external_count != NULL && arp_pending_rejected != NULL &&
	    arp_external_evicted != NULL);
}

static void
ipaddr(int i, struct addr *a)
{
	uint32_t ip = htonl(IP(i));
	addr_pack(a, ADDR_TYPE_IP, IP_ADDR_BITS, &ip, IP_ADDR_LEN);
}

static void
cb(struct arp_req *req, int success, void *arg)
{
	int i = (int)(intptr_t)arg;

	calls[i]++;
	if (!success) {
		fails[i]++;
		fails_total++;
	}
}

static void
request(int i)
{
	struct addr a;

	ipaddr(i, &a);
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb, (void *)(intptr_t)i);
}

static int
live(int i)
{
	struct addr a;
	struct arp_req *r;

	ipaddr(i, &a);
	r = arp_find(&a);
	return (r != NULL && !(r->flags & ARP_INTERNAL));
}

static int
live_total(int n)
{
	int i, c = 0;

	for (i = 0; i < n; i++)
		c += live(i);
	return (c);
}

static int
pending_total(int n)
{
	struct addr a;
	struct arp_req *r;
	int i, c = 0;

	for (i = 0; i < n; i++) {
		ipaddr(i, &a);
		if ((r = arp_find(&a)) != NULL && r->cb != NULL)
			c++;
	}
	return (c);
}

static void
reply(int i)
{
	u_char pkt[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
	struct pcap_pkthdr h;
	struct addr pa, ha;
	char mac[32];

	ipaddr(i, &pa);
	snprintf(mac, sizeof(mac), "02:00:00:00:%02x:%02x",
	    (i >> 8) & 0xff, i & 0xff);
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

static int
counters_ok(int n)
{
	int ok = arp_pending_count() >= 0 && arp_external_count() >= 0 &&
	    arp_external_count() == live_total(n) &&
	    arp_pending_count() == pending_total(n);
	if (!ok)
		printf("  counters: pending %d/%d external %d/%d\n",
		    arp_pending_count(), pending_total(n),
		    arp_external_count(), live_total(n));
	return (ok);
}

static int
mode_evict(void)
{
	struct addr ipa, iha, a;
	struct ip_hdr *ip;
	u_int iplen = IP_HDR_LEN + 8;
	int i;

	arp_set_limits(0, 4);
	addr_aton("10.0.0.60", &ipa);
	addr_aton("02:00:00:00:60:01", &iha);
	check(arp_new(&fuzz_iface, NULL, NULL, &ipa, &iha) != NULL,
	    "internal entry created");
	arp_find(&ipa)->flags |= ARP_INTERNAL;

	/* Five queued packets, cap 4: the first, still pending, goes */
	for (i = 0; i < 5; i++) {
		ipaddr(i, &a);
		ip = pool_alloc_size(pool_pkt, 64);
		memset(ip, 0, 64);
		ip_pack_hdr(ip, 0, iplen, 1, 0, 64, IP_PROTO_UDP,
		    src_pa.addr_ip, a.addr_ip);
		honeyd_send_ethernet(&fuzz_iface, &src_pa, &src_ha, &a, ip,
		    iplen);
	}
	check(!live(0), "oldest pending entry evicted");
	check(live_total(5) == 4, "4 entries live");
	check(arp_external_evicted() == 1, "evicted counter is 1");

	/* Flood; the internal entry must survive */
	for (i = 5; i < NMAX; i++)
		request(i);
	check(arp_find(&ipa) != NULL &&
	    (arp_find(&ipa)->flags & ARP_INTERNAL), "internal entry survives");
	check(live_total(NMAX) == 4, "still 4 entries after the flood");
	check(counters_ok(NMAX), "counters match the live entries");

	/* Let the remaining packets fail and free normally */
	run_for(1700000);
	check(counters_ok(NMAX), "counters match after discovery failure");
	return (0);
}

static int
mode_reject(void)
{
	int i;

	arp_set_limits(0, 100000);
	for (i = 0; i < 300; i++)
		request(i);
	check(arp_pending_count() == 256, "256 pending");
	check(live_total(300) == 256, "256 entries live");
	check(arp_pending_rejected() == 44, "44 rejected and counted");
	for (i = 0; i < 300; i++)
		if (calls[i] != (i < 256 ? 0 : 1) ||
		    fails[i] != (i < 256 ? 0 : 1))
			break;
	check(i == 300, "each rejected callback ran once with failure");
	run_for(1700000);
	for (i = 0; i < 300 && calls[i] == 1; i++)
		;
	check(i == 300, "every callback ran exactly once in the end");
	check(arp_pending_count() == 0, "no pending left");
	check(counters_ok(300), "counters match");
	return (0);
}

static int
mode_order(void)
{
	int i, j, ok = 1;

	arp_set_limits(0, 8);
	for (i = 0; i < 20; i++) {
		request(i);
		for (j = 0; j <= i; j++)
			if (live(j) != (j > i - 8))
				ok = 0;
	}
	check(ok, "only the newest 8 live after each request");
	check(arp_external_evicted() == 12, "12 evicted");
	check(fails_total == 12, "12 evicted pending callbacks failed once");
	check(counters_ok(20), "counters match");
	return (0);
}

static int
mode_count(void)
{
	struct addr a;
	struct arp_req *r;
	int i;

	arp_set_limits(0, 50);
	for (i = 0; i < 40; i++)
		request(i);
	for (i = 0; i < 20; i++)
		reply(i);		/* resolved */
	check(counters_ok(60), "after replies");
	run_for(1700000);		/* 20 to 39 fail, stay as remembered */
	check(counters_ok(60), "after discovery failure");
	for (i = 0; i < 10; i++) {	/* expire 0 to 9 through the timeout */
		ipaddr(i, &a);
		if ((r = arp_find(&a)) != NULL)
			event_active(r->active, EV_TIMEOUT, 1);
	}
	run_for(1000);
	check(arp_external_count() == 30, "30 live after 10 timeouts");
	check(counters_ok(60), "after timeouts");
	for (i = 40; i < 60; i++)	/* 50 cap: 0 evictions until 50 */
		request(i);
	check(arp_external_evicted() == 0, "no eviction below the cap");
	for (i = 0; i < 10; i++)	/* re-request 0 to 9: evicts 10 */
		request(i);
	check(arp_external_evicted() == 10, "10 evicted at the cap");
	check(counters_ok(60), "after eviction");
	run_for(1700000);
	check(counters_ok(60), "at the end");
	for (i = 0; i < 60; i++)
		if (calls[i] > 2)
			break;
	check(i == 60, "no callback ran more than once per request");
	return (0);
}

/* Failure callback that asks for two more addresses */
static void
cb_reenter(struct arp_req *req, int success, void *arg)
{
	int i = (int)(intptr_t)arg;
	struct addr a;

	calls[i]++;
	if (success || depth > 3 || i + 2 >= NMAX)
		return;
	depth++;
	ipaddr(i + 1000, &a);
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb_reenter,
	    (void *)(intptr_t)((i + 1000) % NMAX));
	ipaddr(i + 2000, &a);
	arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb_reenter,
	    (void *)(intptr_t)((i + 2000) % NMAX));
	depth--;
}

static int
mode_reenter(void)
{
	struct addr a;
	int i;

	arp_set_limits(4, 6);
	for (i = 0; i < 200; i++) {
		ipaddr(i, &a);
		arp_request(&fuzz_iface, &src_pa, &src_ha, &a, cb_reenter,
		    (void *)(intptr_t)i);
	}
	run_for(1700000);
	check(arp_pending_count() >= 0 && arp_pending_count() <= 4,
	    "pending within the cap");
	check(arp_external_count() <= 6 &&
	    arp_external_count() == live_total(NMAX),
	    "entries within the cap and counted");
	check(arp_pending_rejected() > 0 && arp_external_evicted() > 0,
	    "both rejection and eviction happened");
	return (0);
}

static const char config_option[] =
	"option honeyd max_arp_pending 4\n"
	"option honeyd max_arp_entries 8\n"
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static int
mode_option(void)
{
	int i;

	for (i = 0; i < 20; i++)
		request(i);
	check(arp_pending_count() == 4, "4 pending at the configured cap");
	check(arp_pending_rejected() == 16, "16 rejected");
	run_for(1700000);
	for (i = 20; i < 40; i += 4) {
		int j;
		for (j = i; j < i + 4; j++)
			request(j);
		run_for(1700000);
	}
	check(live_total(40) == 8, "8 entries live at the configured cap");
	check(arp_external_evicted() == 16, "16 evicted");
	check(counters_ok(40), "counters match");
	return (0);
}

int
main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "";

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(strcmp(m, "option") == 0 ? config_option : config);
	fuzz_drain_events();
	addr_aton("10.0.0.2", &src_pa);
	addr_aton("02:00:00:00:00:02", &src_ha);

	if (!have_caps()) {
		printf("FAIL: arp caps not present\n");
		return (1);
	}
	if (strcmp(m, "evict") == 0)
		mode_evict();
	else if (strcmp(m, "reject") == 0)
		mode_reject();
	else if (strcmp(m, "order") == 0)
		mode_order();
	else if (strcmp(m, "count") == 0)
		mode_count();
	else if (strcmp(m, "option") == 0)
		mode_option();
	else if (strcmp(m, "reenter") == 0)
		mode_reenter();
	else
		return (2);
	if (fails_check)
		return (1);
	printf("PASS: arp_cap %s\n", m);
	return (0);
}
