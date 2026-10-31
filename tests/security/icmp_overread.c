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
 * PM-SCR-146: with UCK set the UDP checksum is written even when the
 * datagram is shorter than the UDP header.
 *
 * PM-SCR-141: the timestamp reply copied the request receive field into
 * its transmit field and counted milliseconds from local midnight.
 *
 * Usage: icmp_overread tstamp|unreach|quote|dat|uck
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
void icmp_error_send(struct template *, struct addr *, uint8_t, uint8_t,
    struct ip_hdr *, struct spoof);
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

/* ms since midnight UTC, and the distance from it modulo one day */
static uint32_t
utc_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return ((uint32_t)((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000));
}

static int
near(uint32_t got, uint32_t want)
{
	uint32_t d = got > want ? got - want : want - got;

	if (d > 86400000 / 2)
		d = 86400000 - (d % 86400000);
	return (got < 86400000 && d <= 5000);
}

static int
tstamp_check(const char *what)
{
	uint32_t rx, tx, ms = utc_ms();
	int fail = 0;

	memcpy(&rx, sent + IP_HDR_LEN + 12, 4);
	memcpy(&tx, sent + IP_HDR_LEN + 16, 4);
	printf("%s: receive %u transmit %u, UTC about %u\n", what,
	    ntohl(rx), ntohl(tx), ms);
	if (!near(ntohl(rx), ms)) {
		printf("FAIL receive timestamp not UTC ms since midnight\n");
		fail = 1;
	}
	if (!near(ntohl(tx), ms)) {
		printf("FAIL transmit timestamp not UTC ms since midnight\n");
		fail = 1;
	}
	return (fail);
}

static int
tstamp(void)
{
	struct template *t;
	u_char body[20], pkt[128];
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

	/*
	 * Receive and transmit timestamps: ms since midnight UTC, network
	 * byte order (PM-SCR-002, PM-SCR-141). The test runs with a local
	 * zone eleven hours off UTC so local midnight time is caught.
	 */
	fail |= tstamp_check("originate 0");

	/* Non zero originate and request fields must not leak through */
	memcpy(body + 8, "\x01\x02\x03\x04", 4);
	memcpy(body + 12, "\x7f\x7e\x7d\x7c", 4);
	memcpy(body + 16, "\x55\x55\x55\x55", 4);
	poison_pool();
	inject(pkt, frame(pkt, IP_PROTO_ICMP, body, 20));
	if (nsent != 1 || sentlen < IP_HDR_LEN + 20) {
		printf("FAIL second request: %d replies\n", nsent);
		return (1);
	}
	if (memcmp(sent + IP_HDR_LEN + 8, "\x01\x02\x03\x04", 4) != 0) {
		printf("FAIL originate timestamp not echoed\n");
		fail = 1;
	}
	fail |= tstamp_check("originate set");
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
	struct ip_hdr *ip;
	struct addr src;
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
	if (nsent != 1)
		return (1);

	/* Non zero RIPL rewrites ip_len before the DAT check (PM-SCR-146) */
	u->riplen = 1000;
	inject(pkt, frame(pkt, IP_PROTO_UDP, body, sizeof(body)));
	printf("payloadless UDP with DAT bad, RIPL +1000: %d replies\n", nsent);
	if (nsent != 1)
		return (1);
	u->riplen = -20;
	inject(pkt, frame(pkt, IP_PROTO_UDP, body, sizeof(body)));
	printf("payloadless UDP with DAT bad, RIPL -20: %d replies\n", nsent);
	if (nsent != 1)
		return (1);

	/* The same datagram in an exact size buffer, so ASan sees a write */
	ip = calloc(1, IP_HDR_LEN + UDP_HDR_LEN);
	ip_pack_hdr(ip, 0, IP_HDR_LEN + UDP_HDR_LEN, 1, 0, 64, IP_PROTO_UDP,
	    htonl(0x0b000001), htonl(0x0a000002));
	udp_pack_hdr((struct udp_hdr *)(ip + 1), 1024, 4444, UDP_HDR_LEN);
	ip_checksum(ip, IP_HDR_LEN + UDP_HDR_LEN);
	addr_pton("10.0.0.2", &src);
	u->riplen = 1000;
	nsent = 0;
	icmp_error_send(t, &src, ICMP_UNREACH, ICMP_UNREACH_PORT, ip,
	    no_spoof);
	printf("exact size payloadless UDP, DAT bad, RIPL +1000: %d replies\n",
	    nsent);
	free(ip);
	u->riplen = 0;
	return (nsent != 1);
}

/*
 * A UDP datagram shorter than its 8 byte header reaches the ICMP error
 * path from honeyd_delay_cb (time exceeded or unreachable route) with
 * UCK set: the checksum is written past the received bytes (PM-SCR-146).
 * The datagram sits in an exact size buffer so ASan sees the write.
 */
static int
uck(void)
{
	struct template *t;
	struct persudp *u;
	struct ip_hdr *ip;
	struct addr src;
	size_t len;
	int fail = 0;

	if ((t = template_find("10.0.0.2")) == NULL || t->person == NULL)
		abort();
	u = &t->person->udptest;
	u->response = 1;
	u->dat = RVAL_OKAY;
	u->uck = RVAL_BAD;
	u->uckVal = 0x1234;
	u->quotelen = 0xffff;
	addr_pton("10.0.0.2", &src);

	for (len = IP_HDR_LEN; len <= IP_HDR_LEN + UDP_HDR_LEN; len++) {
		ip = calloc(1, len);
		ip_pack_hdr(ip, 0, len, 1, 0, 1, IP_PROTO_UDP,
		    htonl(0x0b000001), htonl(0x0a000002));
		ip_checksum(ip, IP_HDR_LEN);
		u->riplen = (len & 1) ? 1000 : 0;
		nsent = 0;
		icmp_error_send(t, &src, ICMP_TIMEXCEED,
		    ICMP_TIMEXCEED_INTRANS, ip, no_spoof);
		printf("UDP of %zu bytes with UCK set, RIPL %d: %d replies\n",
		    len, u->riplen, nsent);
		if (nsent != 1)
			fail = 1;
		if (len == IP_HDR_LEN + UDP_HDR_LEN &&
		    memcmp((u_char *)ip + IP_HDR_LEN + 6, "\x12\x34", 2) != 0) {
			printf("FAIL full UDP header: checksum not rewritten\n");
			fail = 1;
		}
		free(ip);
	}
	u->uck = RVAL_OKAY;
	return (fail);
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
	else if (strcmp(argv[1], "uck") == 0)
		rc = uck();
	else
		return (2);
	printf(rc ? "FAIL\n" : "OK\n");
	return (rc);
}
