/*
 * PM-SCR-001: ICMP address mask and information requests to a template
 * whose personality has no xprobe fingerprint dereference NULL.
 * PM-SCR-004: a packet routed to an external (bound) template is queued
 * with DELAY_ETHERNET but a NULL template, which honeyd_delay_cb
 * dereferences.
 *
 * Frames go into honeyd_recv_cb() on the fake interface from
 * fuzz/fuzz_common.c; ip_send and eth_send are stubbed, so nothing
 * leaves the process.
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
#include "personality.h"
#include "interface.h"
#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"set default default icmp action open\n"
	"create linux\n"
	"set linux personality \"Linux 2.6.32\"\n"
	"set linux default icmp action open\n"
	"create ext\n"
	"set ext default udp action reset\n"
	"add ext udp port 53 open\n"
	"bind 10.0.0.2 linux\n"
	"bind 10.0.0.9 ext\n"
	"route entry 10.0.0.1 network 10.0.0.0/16\n"
	"route 10.0.0.1 link 10.0.0.0/24\n";

static void
inject(u_char *pkt, size_t len)
{
	struct pcap_pkthdr h;
	u_char *copy = malloc(len);	/* exact size for ASan */

	memcpy(copy, pkt, len);
	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = len;
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, copy);
	fuzz_drain_events();
	free(copy);
}

static size_t
frame(u_char *pkt, uint32_t dst, int proto, const u_char *body, size_t blen)
{
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + ETH_HDR_LEN);
	size_t iplen = IP_HDR_LEN + blen;

	memset(pkt, 0, ETH_HDR_LEN + iplen);
	memcpy(pkt, "\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x08", 12);
	pkt[12] = 0x08;
	memcpy(ip + 1, body, blen);
	ip_pack_hdr(ip, 0, iplen, 1, 0, 64, proto, htonl(0x0b000001),
	    htonl(dst));
	ip_checksum(ip, iplen);
	return (ETH_HDR_LEN + iplen);
}

static void
icmp_req(int type, size_t blen)
{
	u_char body[64], pkt[128];

	memset(body, 0, sizeof(body));
	body[0] = type;
	body[5] = 1;		/* id 1 */
	body[7] = 1;		/* seq 1 */
	inject(pkt, frame(pkt, 0x0a000002, IP_PROTO_ICMP, body, blen));
}

int
main(void)
{
	struct template *t;
	u_char body[12], pkt[128];
	struct udp_hdr *u = (struct udp_hdr *)body;

	fuzz_honeyd_init(config);

	/* PM-SCR-001: personality without an xprobe fingerprint */
	if ((t = template_find("10.0.0.2")) == NULL || t->person == NULL)
		abort();
	t->person->xp_fprint = NULL;
	icmp_req(ICMP_MASK, 12);
	printf("icmp mask request: no crash\n");
	icmp_req(ICMP_INFO, 8);
	printf("icmp info request: no crash\n");

	/*
	 * PM-SCR-004: "bind 10.0.0.9 to fuzz0" needs a real interface in
	 * parse.y, so mark the template external here instead.
	 */
	if ((t = template_find("10.0.0.9")) == NULL)
		abort();
	t->flags |= TEMPLATE_EXTERNAL;
	t->inter = &fuzz_iface;
	memset(body, 0, sizeof(body));
	udp_pack_hdr(u, 1024, 53, sizeof(body));
	inject(pkt, frame(pkt, 0x0a000009, IP_PROTO_UDP, body, sizeof(body)));
	printf("routed packet to external template: no crash\n");
	return (0);
}
