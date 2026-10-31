/*
 * Helpers for the PM-SCR-139 UDP flow cap tests: build spoofed UDP and
 * ICMP frames for honeyd_recv_cb() on the fake interface from
 * fuzz/fuzz_common.c, and look at the live UDP state. ip_send and
 * eth_send are stubbed, so nothing leaves the process.
 *
 * honeyd_nudp and honeyd_udp_evicted are weak so the tests still build
 * against a tree without the cap and fail there instead.
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
#include "fuzz_common.h"

#ifndef HONEYD_MAX_UDP
#define HONEYD_MAX_UDP	32000
#endif

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
extern struct conlru udplru;
extern int honeyd_nudp __attribute__((weak));
extern uint32_t honeyd_udp_evicted __attribute__((weak));

static int nicmp;

static void __attribute__((unused))
count_icmp(const void *p, size_t len)
{
	const struct ip_hdr *ip = p;

	if (len >= IP_HDR_LEN && ip->ip_p == IP_PROTO_ICMP)
		nicmp++;
}

static void
feed(const u_char *frame, size_t len)
{
	struct pcap_pkthdr h;

	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = len;
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, frame);
}

/* One 4 byte UDP datagram from src:sport to dst:53 */
static void
send_udp(uint32_t src, uint16_t sport, uint32_t dst)
{
	u_char pkt[14 + 20 + 8 + 4];
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, 1, 0, 64, IP_PROTO_UDP,
	    htonl(src), htonl(dst));
	udp_pack_hdr(udp, sport, 53, 12);
	ip_checksum(ip, sizeof(pkt) - 14);
	feed(pkt, sizeof(pkt));
}

/* ICMP port unreachable from src quoting a reply dst:53 -> src:sport */
static void __attribute__((unused))
send_unreach(uint32_t src, uint16_t sport, uint32_t dst)
{
	u_char pkt[14 + 20 + 8 + 20 + 8];
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct icmp_hdr *icmp = (struct icmp_hdr *)(ip + 1);
	struct ip_hdr *rip = (struct ip_hdr *)((u_char *)icmp + 8);
	struct udp_hdr *rudp = (struct udp_hdr *)(rip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(rip, 0, 28, 1, 0, 64, IP_PROTO_UDP, htonl(dst),
	    htonl(src));
	udp_pack_hdr(rudp, 53, sport, 8);
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, 2, 0, 64, IP_PROTO_ICMP,
	    htonl(src), htonl(dst));
	icmp->icmp_type = ICMP_UNREACH;
	icmp->icmp_code = ICMP_UNREACH_PORT;
	ip_checksum(ip, sizeof(pkt) - 14);
	feed(pkt, sizeof(pkt));
}

static int
live_udp(void)
{
	struct tuple *t;
	int n = 0;

	TAILQ_FOREACH(t, &udplru, next)
		n++;
	return (n);
}

static struct udp_con * __attribute__((unused))
find_udp(uint32_t src, uint16_t sport)
{
	struct tuple *t;

	TAILQ_FOREACH(t, &udplru, next)
		if (t->ip_src == htonl(src) && t->sport == sport)
			return ((struct udp_con *)t);
	return (NULL);
}

static int fails;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}
