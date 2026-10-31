/*
 * PM-SCR-007, dhcpclient.c: every DHCP request allocated a new timeout
 * timer, every ACK with a lease allocated a new renewal timer and every
 * renewal allocated a new renewal timeout timer. The old pointers were
 * overwritten, so a template leaked one timer per request, per ACK and
 * per renewal. After the fix each timer is created once and reused.
 *
 * The template's interface is the fake one from fuzz/fuzz_common.c and
 * eth_send is stubbed, so nothing leaves the process. ACKs are handed to
 * dhcp_recv_cb() as the packet dispatcher would and the renewal timer is
 * fired with event_active.
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

#define ROUNDS	50

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n";

/* An Ethernet frame with a DHCP ACK for xid and a one hour lease */
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

int
main(void)
{
	struct template *tmpl;
	struct dhcpclient_req *req;
	u_char buf[1024];
	struct addr ip;
	size_t len;
	int i, base;

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

	/* Repeated requests (each one aborts the one in progress) */
	base = ev_live;
	for (i = 0; i < ROUNDS; i++)
		_dhcp_getconf(tmpl);
	ev_check("request", ROUNDS, ev_live - base, 1);

	/*
	 * Renewal cycles. The first ACK arrives while waiting for an ACK; its
	 * address is already taken by this template, so it only sets the
	 * renewal timer. Then each round fires the renewal timer and ACKs
	 * the renewal.
	 */
	req = tmpl->dhcp_req;
	req->state = DHREQ_STATE_WAITACK;
	base = ev_live;
	len = ack(buf, req->xid, tmpl->ethernet_addr);
	dhcp_recv_cb((struct eth_hdr *)buf,
	    (struct ip_hdr *)(buf + ETH_HDR_LEN), len);
	for (i = 0; i < ROUNDS; i++) {
		if (req->renewEv == NULL) {
			printf("FAIL renew: no renewal timer\n");
			return (1);
		}
		event_active(req->renewEv, EV_TIMEOUT, 1);
		fuzz_drain_events();
		if (req->state != DHREQ_STATE_RENEWAL) {
			printf("FAIL renew: renewal did not start\n");
			return (1);
		}
		len = ack(buf, req->xid, tmpl->ethernet_addr);
		dhcp_recv_cb((struct eth_hdr *)buf,
		    (struct ip_hdr *)(buf + ETH_HDR_LEN), len);
		if (req->state != DHREQ_STATE_GOTACK) {
			printf("FAIL renew: ACK not taken\n");
			return (1);
		}
	}
	/* One renewal timer and one renewal timeout timer may stay */
	ev_check("renew", ROUNDS, ev_live - base, 2);

	if (ev_fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: dhcp_timer\n");
	return (0);
}
