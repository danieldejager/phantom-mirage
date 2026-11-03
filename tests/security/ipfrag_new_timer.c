/*
 * ipfrag.c ip_fragment_new() (Low, CWE-476/CWE-252, reachable from any
 * inbound fragment): the expiry timer from evtimer_new() was not
 * checked, then passed to evtimer_add(), and the fragment record was
 * inserted in the tree and the LRU list and counted in nfragments.
 *
 * Now the timer is checked before any insert; on failure the record is
 * freed, ip_fragment_new() returns NULL and ip_fragment() drops the
 * fragment. Nothing is inserted, listed or counted.
 *
 * event_new is wrapped to fail the ip_fragment_timeout timer once.
 * Fragments go straight into ip_fragment(); nothing leaves the process.
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
#include "personality.h"
#include "ipfrag.h"
#include "fuzz_common.h"

extern int nfragments, nfragmem;
struct fragment *ip_fragment_find(ip_addr_t, ip_addr_t, u_short, u_char);
void ip_fragment_timeout(int, short, void *);

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);

static int fail_event_new;

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	if (fail_event_new && cb == ip_fragment_timeout) {
		fail_event_new = 0;
		return (NULL);
	}
	return (__real_event_new(b, fd, what, cb, arg));
}

#define SRC	htonl(0x0b000009)
#define DST	htonl(0x0a000002)

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static int
frag(uint16_t id)
{
	static u_char pkt[20 + 8];
	struct ip_hdr *ip = (struct ip_hdr *)pkt, *pip;
	u_short plen;

	memset(pkt, 0x41, sizeof(pkt));
	ip_pack_hdr(ip, 0, sizeof(pkt), id, IP_MF | 1, 64, IP_PROTO_UDP,
	    SRC, DST);
	return (ip_fragment(NULL, ip, sizeof(pkt), &pip, &plen));
}

int
main(void)
{
	int n0, m0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();

	n0 = nfragments;
	m0 = nfragmem;
	fail_event_new = 1;
	frag(7);
	printf("after failed timer: nfragments %d (was %d), nfragmem %d "
	    "(was %d)\n", nfragments, n0, nfragmem, m0);
	if (ip_fragment_find(SRC, DST, htons(7), IP_PROTO_UDP) != NULL ||
	    nfragments != n0 || nfragmem != m0) {
		printf("FAIL: fragment queue kept without a timer\n");
		return (1);
	}

	/* The next fragment still gets a queue with a timer */
	frag(8);
	if (ip_fragment_find(SRC, DST, htons(8), IP_PROTO_UDP) == NULL ||
	    nfragments != n0 + 1) {
		printf("FAIL: second fragment not queued\n");
		return (1);
	}
	printf("PASS: ipfrag_new_timer\n");
	return (0);
}
