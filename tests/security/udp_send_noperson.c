/*
 * PM-SCR-220 (CWE-476): udp_send read the reply TTL from
 * tmpl->person->udptest.ttl without checking that the flow has a
 * template or that the template has a personality. A template created
 * without "set ... personality" sends UDP replies from scripts and
 * subsystems, so the reply dereferenced a NULL personality. The reply
 * now uses honeyd_ttl (HONEYD_DFL_TTL, 64), the same default the TCP and
 * ICMP reply paths use.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "hooks.h"
#include "fuzz_common.h"

static const char config[] =
	"create plain\n"
	"bind 10.0.0.2 plain\n";

static int sent, ttl, fails;

/* The outgoing packet hook sees the reply before it is routed */
static void
hook(struct tuple *hdr, u_char *pkt, u_int len, void *arg)
{
	const struct ip_hdr *ip = (const struct ip_hdr *)pkt;

	if (len < IP_HDR_LEN || ip->ip_p != IP_PROTO_UDP)
		return;
	sent++;
	ttl = ip->ip_ttl;
}

static void
one(struct template *tmpl, const char *name)
{
	struct ip_hdr ip;
	struct udp_hdr udp;
	struct udp_con *c;
	u_char data[4] = "abc";

	memset(&ip, 0, sizeof(ip));
	memset(&udp, 0, sizeof(udp));
	ip.ip_src = htonl(0x0a000009);
	ip.ip_dst = htonl(0x0a000002);
	udp.uh_sport = htons(4000);
	udp.uh_dport = htons(53);
	if ((c = udp_new(&ip, &udp, 0)) == NULL) {
		printf("FAIL: %s: udp_new\n", name);
		exit(1);
	}
	c->tmpl = tmpl;
	sent = ttl = 0;
	if (udp_send(c, data, sizeof(data)) != sizeof(data)) {
		printf("FAIL: %s: udp_send\n", name);
		fails++;
	}
	printf("%s: sent %d ttl %d\n", name, sent, ttl);
	if (sent != 1 || ttl != HONEYD_DFL_TTL) {
		printf("FAIL: %s: ttl %d, want %d\n", name, ttl,
		    HONEYD_DFL_TTL);
		fails++;
	}
	c->tmpl = NULL;
	udp_free(c);
}

int
main(void)
{
	struct template *tmpl;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	hooks_add_packet_hook(IP_PROTO_UDP, HD_OUTGOING, hook, NULL);
	if ((tmpl = template_find("10.0.0.2")) == NULL ||
	    tmpl->person != NULL) {
		printf("FAIL: setup\n");
		return (1);
	}
	one(tmpl, "no personality");
	one(NULL, "no template");
	if (fails)
		return (1);
	printf("PASS: udp_send_noperson\n");
	return (0);
}
