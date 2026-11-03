/*
 * PM-SCR-007, hsniff.c: tcp_track_free() only called evtimer_del() on
 * the per connection timeout, so the sniffer leaked one event for every
 * TCP connection it tracked.
 *
 * hsniff.c is compiled in with its main() renamed. Connections are
 * created with tcp_track_new() from hand built headers and freed both
 * directly and through their expired timeout; no capture device is
 * opened.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <dnet.h>
#include "evcount.h"

struct tcp_track;
struct tcp_track *tcp_track_new(struct ip_hdr *, struct tcp_hdr *, int);
void tcp_track_free(struct tcp_track *);
void hsniff_tcp_timeout(int, short, void *);
extern struct event_base *libevent_base;

#define ROUNDS	100

int
main(void)
{
	u_char pkt[40];
	struct ip_hdr *ip = (struct ip_hdr *)pkt;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);
	struct tcp_track *con;
	int i, base;

	setvbuf(stdout, NULL, _IONBF, 0);
	libevent_base = event_base_new();
	base = ev_live;
	for (i = 0; i < ROUNDS; i++) {
		memset(pkt, 0, sizeof(pkt));
		ip_pack_hdr(ip, 0, sizeof(pkt), i, 0, 64, IP_PROTO_TCP,
		    htonl(0x0b000001), htonl(0x0a000002));
		tcp_pack_hdr(tcp, 2000 + i, 80, 1, 0, TH_SYN, 1024, 0);
		if ((con = tcp_track_new(ip, tcp, 0)) == NULL)
			abort();
		if (i & 1)
			tcp_track_free(con);
		else
			hsniff_tcp_timeout(-1, EV_TIMEOUT, con);
	}
	ev_check("hsniff", ROUNDS, ev_live - base, 0);

	if (ev_fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: hsniff_timer\n");
	return (0);
}
