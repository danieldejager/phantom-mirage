/*
 * PM-SCR-148, dhcpclient.c: dhcp_abort deleted only the request timeout
 * timer. A renewal timer or renewal timeout timer scheduled before the
 * abort stayed pending, so a stale renewal could fire later. After the
 * fix no DHCP timer of the template is pending after an abort.
 *
 * The template's interface is the fake one from fuzz/fuzz_common.c and
 * eth_send is stubbed, so nothing leaves the process.
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
#include "interface.h"
#include "dhcpclient.h"
#include "fuzz_common.h"

int _dhcp_getconf(struct template *);
void template_post_arp(struct template *, struct addr *);

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

static int
pending(const char *what, struct event *ev)
{
	int p = ev != NULL && evtimer_pending(ev, NULL);

	printf("  %s: %s\n", what, p ? "pending" : "not pending");
	return (p);
}

static int
check(struct dhcpclient_req *req, const char *when)
{
	int n = 0;

	printf("after abort %s\n", when);
	n += pending("timeout", req->timeoutEv);
	n += pending("renewal", req->renewEv);
	n += pending("renewal timeout", req->renewTimeoutEv);
	if (n)
		printf("FAIL %s: %d timers still scheduled\n", when, n);
	return (n != 0);
}

int
main(void)
{
	struct template *tmpl;
	struct dhcpclient_req *req;
	u_char buf[1024];
	struct addr ip;
	size_t len;
	int fail = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL)
		abort();
	tmpl->ethernet_addr = calloc(1, sizeof(struct addr));
	addr_aton("02:00:00:00:00:02", tmpl->ethernet_addr);
	tmpl->inter = &fuzz_iface;
	addr_aton("10.0.0.2", &ip);
	template_post_arp(tmpl, &ip);

	/* A lease: the ACK schedules the renewal timer */
	_dhcp_getconf(tmpl);
	req = tmpl->dhcp_req;
	req->state = DHREQ_STATE_WAITACK;
	len = ack(buf, req->xid, tmpl->ethernet_addr);
	dhcp_recv_cb((struct eth_hdr *)buf,
	    (struct ip_hdr *)(buf + ETH_HDR_LEN), len);
	if (!pending("renewal before abort", req->renewEv))
		abort();
	dhcp_abort(tmpl);
	fail |= check(req, "with a renewal pending");

	/* A renewal in progress: its timeout timer is scheduled */
	req->state = DHREQ_STATE_WAITACK;
	len = ack(buf, req->xid, tmpl->ethernet_addr);
	dhcp_recv_cb((struct eth_hdr *)buf,
	    (struct ip_hdr *)(buf + ETH_HDR_LEN), len);
	event_active(req->renewEv, EV_TIMEOUT, 1);
	fuzz_drain_events();
	if (req->state != DHREQ_STATE_RENEWAL ||
	    !pending("renewal timeout before abort", req->renewTimeoutEv))
		abort();
	dhcp_abort(tmpl);
	fail |= check(req, "with a renewal in progress");

	/* A new request after the abort still works */
	_dhcp_getconf(tmpl);
	if (!pending("timeout of the new request", req->timeoutEv))
		fail = 1;

	printf(fail ? "FAIL\n" : "OK\n");
	return (fail);
}
