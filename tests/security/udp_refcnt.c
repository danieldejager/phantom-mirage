/*
 * PM-SCR-025: every UDP or TCP flow takes a reference on its template,
 * and the counter was 16 bits wide. 65536 flows to one template wrapped
 * it and hit the assert in template_ref().
 *
 * 70000 UDP flows from distinct sources go into honeyd_recv_cb() on the
 * fake interface from fuzz/fuzz_common.c; ip_send and eth_send are
 * stubbed, so nothing leaves the process.
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

#ifndef TEMPLATE_MAX_REFCNT
#define TEMPLATE_MAX_REFCNT	65535
#endif

#define NFLOWS	70000

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"create linux\n"
	"set linux default udp action reset\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	u_char pkt[14 + 20 + 8 + 4];
	struct pcap_pkthdr h;
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);
	struct template *tmpl;
	int i;

	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}

	for (i = 0; i < NFLOWS; i++) {
		memset(pkt, 0, sizeof(pkt));
		pkt[12] = 0x08;
		ip_pack_hdr(ip, 0, sizeof(pkt) - 14, i, 0, 64, IP_PROTO_UDP,
		    htonl(0x0b000000 + i), htonl(0x0a000002));
		udp_pack_hdr(udp, 1024 + (i % 60000), 53, 12);
		ip_checksum(ip, sizeof(pkt) - 14);
		memset(&h, 0, sizeof(h));
		gettimeofday(&h.ts, NULL);
		h.caplen = h.len = sizeof(pkt);
		honeyd_recv_cb((u_char *)&fuzz_iface, &h, pkt);
	}

	printf("%d flows sent, no abort, refcnt %u\n", NFLOWS,
	    (unsigned)tmpl->refcnt);
	if (tmpl->refcnt > TEMPLATE_MAX_REFCNT) {
		printf("FAIL: flows past the limit were accepted\n");
		return (1);
	}
	printf("flows past the limit refused\n");
	return (0);
}
