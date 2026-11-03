/*
 * New Low finding from the review of PR 197, dhcpclient.c and config.c:
 * template_free() called dhcp_abort(), which only unschedules the request
 * timeout timer, and then freed the dhcpclient_req. The request timeout,
 * renewal and renewal timeout timers were never event_freed, so they
 * leaked, and a still scheduled renewal timer could fire against the
 * freed template. dhcp_req_free() now deletes and frees all three.
 *
 * The template gets all three timers the way dhcp_timer.c does it: a
 * request, an ACK, a fired renewal and its ACK. Then it is freed and no
 * event created on its behalf may be left. eth_send is stubbed, so
 * nothing leaves the process.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "interface.h"
#include "dhcpclient.h"
#include "fuzz_common.h"
#include "evcount.h"

int _dhcp_getconf(struct template *);
void template_post_arp(struct template *, struct addr *);

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n";

static size_t
ack(u_char *buf, uint32_t xid, const struct addr *ea)
{
	struct eth_hdr *eth = (struct eth_hdr *)buf;
	struct ip_hdr *ip = (struct ip_hdr *)(eth + 1);
	struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);
	struct dhcp_msg *msg = (struct dhcp_msg *)(udp + 1);
	u_char *p = (u_char *)(msg + 1);
	uint32_t lease = htonl(3600);
	size_t iplen;

	memset(buf, 0, 1024);
	msg->dh_op = DH_BOOTREPLY;
	msg->dh_xid = xid;
	msg->dh_yiaddr = htonl(0x0a000002);
	memcpy(msg->dh_chaddr, &ea->addr_eth, ETH_ADDR_LEN);
	*p++ = DH_MSGTYPE; *p++ = 1; *p++ = DH_MSGTYPE_ACK;
	*p++ = DH_LEASETIME; *p++ = 4; memcpy(p, &lease, 4); p += 4;
	*p++ = 0xff;
	p += 4;		/* padding */
	iplen = p - (u_char *)ip;
	memcpy(&eth->eth_dst, &ea->addr_eth, ETH_ADDR_LEN);
	eth->eth_type = htons(ETH_TYPE_IP);
	ip_pack_hdr(ip, 0, iplen, 1, 0, 64, IP_PROTO_UDP,
	    htonl(0x0a000001), htonl(0x0a000002));
	udp_pack_hdr(udp, 67, 68, iplen - IP_HDR_LEN);
	ip_checksum(ip, iplen);
	return (iplen);
}

static void
recv_ack(struct template *tmpl)
{
	u_char buf[1024];
	size_t len = ack(buf, tmpl->dhcp_req->xid, tmpl->ethernet_addr);

	dhcp_recv_cb((struct eth_hdr *)buf,
	    (struct ip_hdr *)(buf + ETH_HDR_LEN), len);
}

int
main(void)
{
	struct template *tmpl;
	struct dhcpclient_req *req;
	struct addr ip;
	static const char *names[3] = {
		"timeoutEv", "renewEv", "renewTimeoutEv"
	};
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}
	tmpl->ethernet_addr = calloc(1, sizeof(struct addr));
	addr_aton("02:00:00:00:00:02", tmpl->ethernet_addr);
	tmpl->inter = &fuzz_iface;
	addr_aton("10.0.0.2", &ip);
	template_post_arp(tmpl, &ip);

	_dhcp_getconf(tmpl);
	req = tmpl->dhcp_req;
	req->state = DHREQ_STATE_WAITACK;
	recv_ack(tmpl);
	if (req->renewEv == NULL) {
		printf("FAIL: no renewal timer\n");
		return (1);
	}
	event_active(req->renewEv, EV_TIMEOUT, 1);
	fuzz_drain_events();
	recv_ack(tmpl);
	if (req->timeoutEv == NULL || req->renewTimeoutEv == NULL ||
	    req->state != DHREQ_STATE_GOTACK) {
		printf("FAIL: setup did not reach a renewed lease\n");
		return (1);
	}
	if (!event_pending(req->renewEv, EV_TIMEOUT, NULL)) {
		printf("FAIL: renewal timer not scheduled\n");
		return (1);
	}
	ev_watch[0] = req->timeoutEv;
	ev_watch[1] = req->renewEv;
	ev_watch[2] = req->renewTimeoutEv;

	/* Free the template the way a config reload or remove does */
	tmpl->refcnt = 1;
	template_free(tmpl);
	for (i = 0; i < 3; i++) {
		printf("%s: %s\n", names[i],
		    ev_watch_freed[i] ? "freed" : "still live");
		if (!ev_watch_freed[i])
			ev_fail = 1;
	}

	if (ev_fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: dhcp_free\n");
	return (0);
}
