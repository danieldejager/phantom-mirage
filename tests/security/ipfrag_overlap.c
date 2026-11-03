/*
 * PM-SCR-147: IP fragment insert residuals.
 *
 *  1. A fragment covering several later fragments trimmed only the
 *     first, so the queue could never complete and lingered until the
 *     timeout. It must drop every covered fragment and reassemble.
 *  2. A fragment at the same offset as a shorter queued one left that
 *     one as a zero length entry. It must be dropped.
 *  3. ip_fragment_new reclaimed nfragments/10 queues over the caps,
 *     which is none below ten queues. It must reclaim at least one.
 *
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

extern int nfragmem, nfragments;
struct fragment *ip_fragment_find(ip_addr_t, ip_addr_t, u_short, u_char);
struct fragment *ip_fragment_new(ip_addr_t, ip_addr_t, u_short, u_char,
    enum fragpolicy);

#define SRC	htonl(0x0b000009)
#define DST	htonl(0x0a000002)

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

/* One fragment, offset in 8 byte units: 0 when reassembled */
static int
frag(uint16_t id, uint16_t off8, int mf, u_short datalen)
{
	static u_char pkt[20 + 1500];
	struct ip_hdr *ip = (struct ip_hdr *)pkt, *pip;
	u_short plen;

	memset(pkt, 0x41, sizeof(pkt));
	ip_pack_hdr(ip, 0, 20 + datalen, id, (mf ? IP_MF : 0) | off8, 64,
	    IP_PROTO_UDP, SRC, DST);
	return (ip_fragment(NULL, ip, 20 + datalen, &pip, &plen));
}

static struct fragment *
queue(uint16_t id)
{
	return (ip_fragment_find(SRC, DST, htons(id), IP_PROTO_UDP));
}

int
main(void)
{
	struct fragment *q;
	struct fragent *e;
	int fail = 0, n, zero, rc, before;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();

	/* 1. head, two fragments past a gap, one covering both, the tail */
	frag(1, 0, 1, 8);
	frag(1, 2, 1, 8);
	frag(1, 3, 1, 8);
	frag(1, 1, 1, 24);
	rc = frag(1, 4, 0, 8);
	printf("cover two: %s, queue %s\n", rc == 0 ? "reassembled" :
	    "not reassembled", queue(1) ? "kept" : "freed");
	if (rc != 0 || queue(1) != NULL) {
		printf("FAIL cover two\n");
		fail = 1;
	}

	/* 2. same offset, longer fragment second */
	frag(2, 1, 1, 8);
	frag(2, 1, 1, 16);
	n = zero = 0;
	if ((q = queue(2)) != NULL)
		TAILQ_FOREACH(e, &q->fraglist, next) {
			n++;
			zero += e->len == 0;
		}
	printf("same offset: %d entries, %d of zero length\n", n, zero);
	if (n != 1 || zero) {
		printf("FAIL same offset\n");
		fail = 1;
	}
	frag(2, 0, 1, 8);
	rc = frag(2, 3, 0, 8);
	printf("same offset then head and tail: %s\n",
	    rc == 0 ? "reassembled" : "not reassembled");
	if (rc != 0) {
		printf("FAIL same offset reassembly\n");
		fail = 1;
	}

	/* 3. over the memory cap with fewer than ten queues */
	frag(3, 1, 1, 8);
	frag(4, 1, 1, 8);
	frag(5, 1, 1, 8);
	before = nfragments;
	nfragmem += IPFRAG_MAX_MEM;
	if (ip_fragment_new(SRC, DST, htons(6), IP_PROTO_UDP, FRAG_OLD) ==
	    NULL)
		abort();
	nfragmem -= IPFRAG_MAX_MEM;
	printf("reclaim: %d queues before, %d after a new one\n", before,
	    nfragments);
	if (nfragments > before) {
		printf("FAIL reclaim\n");
		fail = 1;
	}

	printf(fail ? "FAIL\n" : "OK\n");
	return (fail);
}
