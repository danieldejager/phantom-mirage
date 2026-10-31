/*
 * PM-SCR-025 / PM-SCR-135: the only flow cap was a fixed per template
 * reference limit, so one source could take every flow a template
 * allowed and starve all other sources.
 *
 * SYNs go into honeyd_recv_cb() on the fake interface from
 * fuzz/fuzz_common.c; ip_send and eth_send are stubbed, so nothing
 * leaves the process. Checks:
 *  1. source A gets at most 1000 concurrent TCP flows (default cap);
 *  2. source B is still accepted while A is refused;
 *  3. after A's flows end, A can connect again;
 *  4. "option honeyd max_template_flows N" caps the template.
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
#include "parser.h"
#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
extern int honeyd_nconnects;
extern struct conlru tcplru;

#define SRC_A	0x0b000001
#define SRC_B	0x0b000002
#define SRC_C	0x0b000003

static const char config[] =
	"create default\n"
	"set default default tcp action block\n"
	"create linux\n"
	"set linux default tcp action reset\n"
	"add linux tcp port 80 open\n"
	"bind 10.0.0.2 linux\n";

static void
syn(uint32_t src, uint16_t sport)
{
	u_char pkt[14 + 20 + 20];
	struct pcap_pkthdr h;
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, sport, 0, 64, IP_PROTO_TCP,
	    htonl(src), htonl(0x0a000002));
	tcp_pack_hdr(tcp, sport, 80, 1000, 0, TH_SYN, 8192, 0);
	ip_checksum(ip, sizeof(pkt) - 14);
	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = sizeof(pkt);
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, pkt);
}

static int
count_from(uint32_t src)
{
	struct tuple *t;
	int n = 0;

	TAILQ_FOREACH(t, &tcplru, next)
		if (t->ip_src == htonl(src))
			n++;
	return (n);
}

static void
end_flows_from(uint32_t src)
{
	struct tuple *t, *nt;

	for (t = TAILQ_FIRST(&tcplru); t != NULL; t = nt) {
		nt = TAILQ_NEXT(t, next);
		if (t->ip_src == htonl(src))
			tcp_free((struct tcp_con *)t);
	}
}

int
main(void)
{
	struct template *tmpl;
	struct evbuffer *out;
	char line[128];
	unsigned int r0, per;
	int i, n, fail = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}

	for (i = 0; i < 1001; i++)
		syn(SRC_A, 2000 + i);
	n = count_from(SRC_A);
	printf("source A: 1001 SYNs, %d flows\n", n);
	if (n != 1000) {
		printf("FAIL: source A not capped at 1000\n");
		fail = 1;
	}

	syn(SRC_B, 2000);
	n = count_from(SRC_B);
	printf("source B: 1 SYN, %d flows\n", n);
	if (n != 1) {
		printf("FAIL: source B refused\n");
		fail = 1;
	}

	end_flows_from(SRC_A);
	printf("source A flows ended, %d left\n", count_from(SRC_A));
	syn(SRC_A, 9000);
	n = count_from(SRC_A);
	printf("source A: new SYN, %d flows\n", n);
	if (n != 1) {
		printf("FAIL: source A not accepted after its flows ended\n");
		fail = 1;
	}

	/*
	 * Template cap: one flow from C shows how many references a flow
	 * takes; set the cap to allow exactly one more flow. Delivery holds
	 * one extra reference on the template while a packet is
	 * dispatched, so that reference counts against the cap too.
	 */
	r0 = tmpl->refcnt;
	syn(SRC_C, 3000);
	per = tmpl->refcnt - r0;
	snprintf(line, sizeof(line),
	    "option honeyd max_template_flows %u\n",
	    tmpl->refcnt + per + 1);
	out = evbuffer_new();
	if (per == 0 || parse_line(out, line) == -1) {
		printf("FAIL: setup (refs per flow %u)\n", per);
		return (1);
	}
	evbuffer_free(out);
	for (i = 1; i < 5; i++)
		syn(SRC_C, 3000 + i);
	n = count_from(SRC_C);
	printf("template cap one more flow: source C 5 SYNs, %d flows\n", n);
	if (n != 2) {
		printf("FAIL: max_template_flows not applied\n");
		fail = 1;
	}

	if (fail)
		return (1);
	printf("PASS: per source and template flow caps\n");
	return (0);
}
