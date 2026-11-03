/*
 * PM-SCR-007: free paths called evtimer_del(), which only unschedules a
 * timer. The struct event from evtimer_new() was never freed, so every
 * TCP connection, delayed packet, fragment queue, ARP entry, OS
 * fingerprint cache entry and stats object leaked one or two events.
 *
 * event_new and event_free are wrapped to count live events. Each case
 * creates the object, lets it end through its normal path (timeouts are
 * fired with event_active, no waiting), and checks that the number of
 * live events is back where it started. Packets go into
 * honeyd_recv_cb() on the fake interface from fuzz/fuzz_common.c;
 * ip_send and eth_send are stubbed, so nothing leaves the process.
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
#include "arp.h"
#include "osfp.h"
#include "stats.h"
#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
extern struct event_base *libevent_base;
extern struct conlru tcplru;
void honeyd_tcp_timeout(int, short, void *);
extern void (*honeyd_delay_callback)(int, short, void *);
void ip_fragment_timeout(int, short, void *);
void honeyd_osfp_timeout(int, short, void *);
struct stats *stats_new(const struct tuple *);
void honeyd_delay_packet(struct template *, const struct interface *,
    struct ip_hdr *, u_int, const struct addr *, const struct addr *, int,
    int, struct spoof);

#define MAXEV	8192
static struct {
	struct event *ev;
	event_callback_fn cb;
	int fired;
} evs[MAXEV];
static int live;

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
void __real_event_free(struct event *);

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	struct event *ev = __real_event_new(b, fd, what, cb, arg);
	int i;

	if (ev == NULL)
		return (NULL);
	live++;
	for (i = 0; i < MAXEV; i++)
		if (evs[i].ev == NULL) {
			evs[i].ev = ev;
			evs[i].cb = cb;
			evs[i].fired = 0;
			break;
		}
	return (ev);
}

void
__wrap_event_free(struct event *ev)
{
	int i;

	live--;
	for (i = 0; i < MAXEV; i++)
		if (evs[i].ev == ev)
			evs[i].ev = NULL;
	__real_event_free(ev);
}

/*
 * Fire every live timer with callback cb once, as if it had expired.
 * A timer that was fired and is still allocated is not fired again: its
 * owner is gone, and that leftover is what the test counts.
 */
static int
expire(event_callback_fn cb)
{
	int i, n = 0;

	for (i = 0; i < MAXEV; i++)
		if (evs[i].ev != NULL && evs[i].cb == cb && !evs[i].fired) {
			evs[i].fired = 1;
			event_active(evs[i].ev, EV_TIMEOUT, 1);
			n++;
		}
	fuzz_drain_events();
	return (n);
}

static const char config[] =
	"create default\n"
	"set default default tcp action block\n"
	"create linux\n"
	"set linux default tcp action reset\n"
	"set linux default udp action block\n"
	"add linux tcp port 80 open\n"
	"bind 10.0.0.2 linux\n";

static void
inject(u_char *pkt, size_t len)
{
	struct pcap_pkthdr h;

	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = len;
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, pkt);
}

/* A SYN with common options so the OS fingerprint code caches it */
static void
syn(uint32_t src, uint16_t sport)
{
	static const u_char opts[20] = {
		2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0,
		1, 3, 3, 7 };
	u_char pkt[14 + 20 + 20 + sizeof(opts)];
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, sport, IP_DF, 64, IP_PROTO_TCP,
	    htonl(src), htonl(0x0a000002));
	tcp_pack_hdr(tcp, sport, 80, 1000, 0, TH_SYN, 5840, 0);
	tcp->th_off = (20 + sizeof(opts)) >> 2;
	memcpy(tcp + 1, opts, sizeof(opts));
	ip_checksum(ip, sizeof(pkt) - 14);
	inject(pkt, sizeof(pkt));
}

/* First fragment of a UDP datagram; the queue waits for the rest */
static void
frag(uint16_t id)
{
	u_char pkt[14 + 20 + 16];
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, id, IP_MF, 64, IP_PROTO_UDP,
	    htonl(0x0b000009), htonl(0x0a000002));
	ip_checksum(ip, sizeof(pkt) - 14);
	inject(pkt, sizeof(pkt));
}

static int fail;

static void
check(const char *name, int before, int made)
{
	printf("%s: %d created, %d events left over\n", name, made,
	    live - before);
	if (made == 0) {
		printf("FAIL %s: setup created nothing\n", name);
		fail = 1;
	} else if (live != before) {
		printf("FAIL %s\n", name);
		fail = 1;
	}
}

int
main(void)
{
	struct template *tmpl;
	struct addr pa, ha;
	struct tuple hdr;
	struct stats *st;
	u_char ipb[20 + 8];
	struct ip_hdr *ip = (struct ip_hdr *)ipb;
	int i, n, base;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}

	/* TCP connections ended by the idle timeout */
	base = live;
	for (i = 0; i < 100; i++)
		syn(0x0b000001, 2000 + i);
	n = 0;
	while (!TAILQ_EMPTY(&tcplru) &&
	    expire((event_callback_fn)honeyd_tcp_timeout) > 0)
		n++;
	expire((event_callback_fn)honeyd_osfp_timeout);
	check("tcp", base, n ? 100 : 0);

	/* OS fingerprint cache entries expiring */
	base = live;
	syn(0x0b000002, 3000);
	n = expire((event_callback_fn)honeyd_osfp_timeout);
	while (!TAILQ_EMPTY(&tcplru) &&
	    expire((event_callback_fn)honeyd_tcp_timeout) > 0)
		;
	check("osfp", base, n);

	/* Delayed packets, delivered by their timer */
	base = live;
	for (i = 0; i < 100; i++) {
		memset(ipb, 0, sizeof(ipb));
		ip_pack_hdr(ip, 0, sizeof(ipb), i, 0, 64, IP_PROTO_UDP,
		    htonl(0x0b000003), htonl(0x0a000002));
		ip_checksum(ip, sizeof(ipb));
		honeyd_delay_packet(tmpl, &fuzz_iface, ip, sizeof(ipb),
		    NULL, NULL, 10, 0, no_spoof);
	}
	n = expire((event_callback_fn)honeyd_delay_callback);
	check("delay", base, n);

	/* Fragment queues ended by their timeout */
	base = live;
	for (i = 0; i < 100; i++)
		frag(100 + i);
	n = expire((event_callback_fn)ip_fragment_timeout);
	check("ipfrag", base, n);

	/* ARP entries */
	base = live;
	for (i = 0; i < 100; i++) {
		addr_aton("10.1.0.1", &pa);
		pa.addr_ip = htonl(0x0a010000 + i + 1);
		addr_aton("02:00:00:00:00:01", &ha);
		ha.addr_eth.data[5] = i + 1;
		arp_free(arp_new(&fuzz_iface, NULL, NULL, &pa, &ha));
	}
	check("arp", base, 100);

	/* Stats objects (the collector side is not configured) */
	stats_init();
	base = live;
	memset(&hdr, 0, sizeof(hdr));
	hdr.type = SOCK_STREAM;
	hdr.ip_src = htonl(0x0b000004);
	hdr.ip_dst = htonl(0x0a000002);
	for (i = 0; i < 100; i++) {
		hdr.sport = 4000 + i;
		hdr.dport = 80;
		st = stats_new(&hdr);
		stats_free(st);
	}
	check("stats", base, 100);

	if (fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: timer_free\n");
	return (0);
}
