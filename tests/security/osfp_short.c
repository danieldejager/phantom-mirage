/*
 * PM-SCR-026: condition_match_osfp() (a "source os" condition on a
 * dynamic template) hands every packet to honeyd_osfp_match(), which
 * read a TCP header and up to 40 bytes of options after the IP header
 * without checking the protocol or the packet length.
 *
 * Each packet is heap allocated at its exact length so AddressSanitizer
 * reports any read past it.
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
#include "pfvar.h"
#include "osfp.h"
#include "condition.h"
#include "fuzz_common.h"

static void
try(const char *what, u_char proto, size_t iplen, int th_off)
{
	u_char *pkt = calloc(1, iplen);
	struct ip_hdr *ip = (struct ip_hdr *)pkt;
	pf_osfp_t fp = 0;

	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_p = proto;
	ip->ip_ttl = 64;
	ip->ip_len = htons(iplen);
	if (iplen >= IP_HDR_LEN + 14) {
		struct tcp_hdr *tcp = (struct tcp_hdr *)(pkt + IP_HDR_LEN);
		tcp->th_flags = TH_SYN;
		tcp->th_off = th_off;
	}
	condition_match_osfp(NULL, ip, iplen, &fp);
	printf("%s: ok\n", what);
	free(pkt);
}

int
main(void)
{
	fuzz_honeyd_init(NULL);
	try("udp, one payload byte", IP_PROTO_UDP, IP_HDR_LEN + 1, 0);
	try("tcp, header cut short", IP_PROTO_TCP, IP_HDR_LEN + 14, 5);
	try("tcp, th_off past packet", IP_PROTO_TCP, IP_HDR_LEN + 20, 15);
	try("tcp, valid syn", IP_PROTO_TCP, IP_HDR_LEN + 20, 5);
	return (0);
}
