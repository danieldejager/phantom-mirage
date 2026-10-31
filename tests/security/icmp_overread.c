/*
 * ICMP over-reads (R2-2).
 *
 * PM-SCR-002: an ICMP timestamp request shorter than the 20 byte
 * timestamp message is read past its end, and the reply carries stale
 * pool bytes as padding and a receive timestamp in host byte order.
 * PM-SCR-003: an ICMP port unreachable is parsed for a quoted IP and
 * UDP header that may not be there, and the UDP header is located with
 * the outer IP header length.
 * PM-SCR-006: the ICMP error quote length from the personality (IPL and
 * RIPL) is not bounded by the received datagram or the packet buffer.
 *
 * Frames go into honeyd_recv_cb() on the fake interface from
 * fuzz/fuzz_common.c. ip_send is stubbed and only recorded here, so
 * nothing leaves the process.
 *
 * PM-SCR-138: with DAT bad the personality zeroes the first UDP payload
 * byte even when the datagram has no payload, one byte past the end.
 *
 * Usage: icmp_overread tstamp|unreach|quote|dat
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
#include <time.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "personality.h"
#include "pool.h"
#include "interface.h"
#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
extern struct pool *pool_pkt;

static const char config[] =
	"create linux\n"
	"set linux personality \"Linux 2.6.32\"\n"
	"set linux default icmp action open\n"
	"set linux default udp action reset\n"
	"bind 10.0.0.2 linux\n";

static u_char sent[2048];
static size_t sentlen;
static int nsent;

static void
record(const void *buf, size_t len)
{
	nsent++;
	sentlen = len < sizeof(sent) ? len : sizeof(sent);
	memcpy(sent, buf, sentlen);
}

static void
inject(u_char *pkt, size_t len)
{
	struct pcap_pkthdr h;
	u_char *copy = malloc(len);	/* exact size for ASan */

	memcpy(copy, pkt, len);
	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = len;
	nsent = 0;
	sentlen = 0;
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, copy);
	fuzz_drain_events();
	free(copy);
}

static size_t
frame(u_char *pkt, int proto, const u_char *body, size_t blen)
{
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + ETH_HDR_LEN);
	size_t iplen = IP_HDR_LEN + blen;

	memset(pkt, 0, ETH_HDR_LEN + iplen);
	memcpy(pkt, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x08", 12);
	pkt[12] = 0x08;
	memcpy(ip + 1, body, blen);
	ip_pack_hdr(ip, 0, iplen, 1, 0, 64, proto, htonl(0x0b000001),
	    htonl(0x0a000002));
	ip_checksum(ip, iplen);
	return (ETH_HDR_LEN + iplen);
}

/* Leave a recognisable pattern in the next free packet slot */
static void
poison_pool(void)
{
	u_char *p = pool_alloc(pool_pkt);

	memset(p, 0xa5, HONEYD_MTU);
	pool_free(pool_pkt, p);
}

static int
tstamp(void)
{
	struct template *t;
	u_char body[20], pkt[128];
	struct tm *tm;
	time_t now;
	uint32_t rx, ms;
	size_t i;
	int fail = 0;

	if ((t = template_find("10.0.0.2")) == NULL || t->person == NULL ||
	    t->person->xp_fprint == NULL)
		abort();
	t->person->xp_fprint->flags.icmp_timestamp_reply = 1;

	/* Short request: type, code, checksum, id and seq only */
	memset(body, 0, sizeof(body));
	body[0] = ICMP_TSTAMP;
	body[5] = 1;
	body[7] = 1;
	poison_pool();
	inject(pkt, frame(pkt, IP_PROTO_ICMP, body, 8));
	printf("short request: %d replies\n", nsent);
	if (nsent != 0) {
		printf("FAIL short request answered\n");
		fail = 1;
	}

	/* Full request with originate timestamp 0 */
	poison_pool();
	inject(pkt, frame(pkt, IP_PROTO_ICMP, body, 20));
	if (nsent != 1 || sentlen < IP_HDR_LEN + 20) {
		printf("FAIL full request: %d replies\n", nsent);
		return (1);
	}
	printf("full request: reply %zu bytes, padding", sentlen);
	for (i = IP_HDR_LEN + 20; i < sentlen; i++) {
		printf(" %02x", sent[i]);
		if (sent[i] != 0)
			fail = 2;
	}
	printf("\n");
	if (fail == 2)
		printf("FAIL stale bytes in reply padding\n");

	/* Receive timestamp: ms since midnight, network byte order */
	memcpy(&rx, sent + IP_HDR_LEN + 12, 4);
	now = time(NULL);
	tm = localtime(&now);
	ms = (tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec) * 1000;
	printf("receive timestamp %u, expected about %u\n", ntohl(rx), ms);
	if (ntohl(rx) > ms || ms - ntohl(rx) > 5000) {
		printf("FAIL receive timestamp byte order\n");
		fail = 1;
	}
	return (fail);
}

static void
unreach(const u_char *quote, size_t qlen)
{
	u_char body[64], pkt[128];

	memset(body, 0, sizeof(body));
	body[0] = ICMP_UNREACH;
	body[1] = ICMP_UNREACH_PORT;
	memcpy(body + 8, quote, qlen);
	inject(pkt, frame(pkt, IP_PROTO_ICMP, body, 8 + qlen));
}

static int
unreach_short(void)
{
	u_char q[24];
	struct ip_hdr *rip = (struct ip_hdr *)q;

	memset(q, 0, sizeof(q));
	unreach(q, 0);
	printf("unreachable with no quote: no crash\n");

	ip_pack_hdr(rip, 0, 28, 1, 0, 64, IP_PROTO_UDP, htonl(0x0a000002),
	    htonl(0x0b000001));
	unreach(q, IP_HDR_LEN);
	printf("unreachable quoting an IP header only: no crash\n");

	rip->ip_hl = 6;		/* 24 byte header, still no UDP header */
	unreach(q, 24);
	printf("unreachable quoting IP options only: no crash\n");
	return (0);
}

static int
quote_case(int quotelen, int riplen)
{
	struct template *t;
	struct persudp *u;
	u_char body[12], pkt[128];
	size_t qlen;

	if ((t = template_find("10.0.0.2")) == NULL || t->person == NULL)
		abort();
	u = &t->person->udptest;
	u->response = 1;
	u->dat = RVAL_OKAY;
	u->quotelen = quotelen;
	u->riplen = riplen;

	memset(body, 0, sizeof(body));
	udp_pack_hdr((struct udp_hdr *)body, 1024, 4444, sizeof(body));
	poison_pool();
	inject(pkt, frame(pkt, IP_PROTO_UDP, body, sizeof(body)));
	if (nsent != 1) {
		printf("IPL %d RIPL %d: %d replies\n", quotelen, riplen, nsent);
		return (nsent > 1);
	}
	qlen = sentlen - IP_HDR_LEN - ICMP_HDR_LEN - 4;
	printf("IPL %d RIPL %d: reply %zu bytes, quote %zu of %zu received\n",
	    quotelen, riplen, sentlen, qlen, IP_HDR_LEN + sizeof(body));
	if (sentlen > HONEYD_MTU || qlen > IP_HDR_LEN + sizeof(body)) {
		printf("FAIL quote longer than the received datagram\n");
		return (1);
	}
	return (0);
}

static int
quote(void)
{
	int fail = 0;

	fail |= quote_case(0xffff, 0);
	fail |= quote_case(0xffff, 1400);
	fail |= quote_case(0xffff, 3000);
	fail |= quote_case(-28, 0);
	return (fail);
}

/* Payloadless UDP to a closed port with DAT bad (PM-SCR-138) */
static int
dat(void)
{
	struct template *t;
	struct persudp *u;
	u_char body[UDP_HDR_LEN], pkt[128];

	if ((t = template_find("10.0.0.2")) == NULL || t->person == NULL)
		abort();
	u = &t->person->udptest;
	u->response = 1;
	u->dat = RVAL_BAD;
	u->quotelen = 0xffff;
	u->riplen = 0;

	udp_pack_hdr((struct udp_hdr *)body, 1024, 4444, sizeof(body));
	inject(pkt, frame(pkt, IP_PROTO_UDP, body, sizeof(body)));
	printf("payloadless UDP with DAT bad: %d replies\n", nsent);
	return (nsent != 1);
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 2)
		return (2);
	fuzz_honeyd_init(config);
	fuzz_ip_send_hook = record;
	if (strcmp(argv[1], "tstamp") == 0)
		rc = tstamp();
	else if (strcmp(argv[1], "unreach") == 0)
		rc = unreach_short();
	else if (strcmp(argv[1], "quote") == 0)
		rc = quote();
	else if (strcmp(argv[1], "dat") == 0)
		rc = dat();
	else
		return (2);
	printf(rc ? "FAIL\n" : "OK\n");
	return (rc);
}
