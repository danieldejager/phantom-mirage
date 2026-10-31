/*
 * honeyd.c tcp_send() (Low, CWE-476/CWE-252, CWE-401): when no
 * personality matched a SYN reply, the default MSS option came from an
 * unchecked malloc() that was written at once and never freed, so every
 * such SYN|ACK leaked it and a failed malloc wrote through NULL.
 *
 * Now the option lives on the stack of tcp_send(); there is nothing to
 * check or free and the reply is unchanged (it still carries MSS).
 *
 * A SYN to an open port of a template without a personality goes into
 * honeyd_recv_cb() on the fake interface from fuzz/fuzz_common.c;
 * ip_send is stubbed, so nothing leaves the process.
 *
 * Modes:
 *   leak   LeakSanitizer stays on: base leaks the option per reply
 *   fail   malloc is wrapped (-Wl,--wrap=malloc) and fails every
 *          request of sizeof(struct tcp_option) while the SYN is
 *          handled: base writes through NULL
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
#include "personality.h"
#include "interface.h"
#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

static int fail_opt, nfailed, synack, mss;

void *__real_malloc(size_t);

void *
__wrap_malloc(size_t n)
{
	if (fail_opt && n == sizeof(struct tcp_option)) {
		nfailed++;
		return (NULL);
	}
	return (__real_malloc(n));
}

static const char config[] =
	"create linux\n"
	"add linux tcp port 80 open\n"
	"bind 10.0.0.2 linux\n";

static void
sent(const void *p, size_t len)
{
	const struct ip_hdr *ip = p;
	const struct tcp_hdr *tcp;
	const u_char *o;

	if (len < IP_HDR_LEN + TCP_HDR_LEN || ip->ip_p != IP_PROTO_TCP)
		return;
	tcp = (const struct tcp_hdr *)((const u_char *)p + (ip->ip_hl << 2));
	if ((tcp->th_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK))
		return;
	synack++;
	o = (const u_char *)(tcp + 1);
	if (tcp->th_off > 5 && o[0] == TCP_OPT_MSS)
		mss++;
}

static void
syn(uint16_t sport)
{
	u_char pkt[14 + 20 + 20];
	struct pcap_pkthdr h;
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, sport, 0, 64, IP_PROTO_TCP,
	    htonl(0x0b000001), htonl(0x0a000002));
	tcp_pack_hdr(tcp, sport, 80, 1000, 0, TH_SYN, 8192, 0);
	ip_checksum(ip, sizeof(pkt) - 14);
	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = sizeof(pkt);
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, pkt);
}

int
main(int argc, char **argv)
{
	int failmode = argc > 1 && strcmp(argv[1], "fail") == 0;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_ip_send_hook = sent;

	for (i = 0; i < 4; i++) {
		fail_opt = failmode;
		syn(2000 + i);
		fail_opt = 0;
	}
	printf("4 SYNs: %d SYN|ACK, %d with MSS, %d mallocs failed\n",
	    synack, mss, nfailed);
	if (synack != 4 || mss != 4) {
		printf("FAIL: expected 4 SYN|ACK replies carrying MSS\n");
		return (1);
	}
	printf("PASS: tcp_send_mss %s\n", failmode ? "fail" : "leak");
	return (0);
}
