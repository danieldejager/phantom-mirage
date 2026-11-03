/*
 * PM-SCR-008: IP fragment reassembly limits.
 *
 *  1. A single queue accepted any number of fragments (up to 8192 of
 *     eight bytes each). It must hold at most IPFRAG_MAX_PERQUEUE.
 *  2. A fragment with offset 65528 had the IP header length added to a
 *     u_short offset, which wrapped to a small value, and the fragment
 *     was queued at the wrong place. It must be rejected.
 *  3. The global memory cap was checked only when a new queue was
 *     created, so fragments added to existing queues grew nfragmem past
 *     IPFRAG_MAX_MEM without bound. It must hold on every fragment.
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

#ifndef IPFRAG_MAX_PERQUEUE
#define IPFRAG_MAX_PERQUEUE	64	/* so the test also builds before the fix */
#endif

extern int nfragmem;
struct fragment *ip_fragment_find(ip_addr_t, ip_addr_t, u_short, u_char);

#define SRC	htonl(0x0b000009)
#define DST	htonl(0x0a000002)

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static int fail;

/* Feed one fragment: offset in 8 byte units, datalen bytes of payload */
static void
frag(uint16_t id, uint16_t off8, int mf, u_short datalen)
{
	static u_char pkt[20 + 1500];
	struct ip_hdr *ip = (struct ip_hdr *)pkt, *pip;
	u_short plen;

	memset(pkt, 0x41, sizeof(pkt));
	ip_pack_hdr(ip, 0, 20 + datalen, id, (mf ? IP_MF : 0) | off8, 64,
	    IP_PROTO_UDP, SRC, DST);
	ip_fragment(NULL, ip, 20 + datalen, &pip, &plen);
}

static int
count(uint16_t id, int *found)
{
	struct fragment *q;
	struct fragent *e;
	int n = 0;

	q = ip_fragment_find(SRC, DST, htons(id), IP_PROTO_UDP);
	*found = q != NULL;
	if (q != NULL)
		TAILQ_FOREACH(e, &q->fraglist, next)
			n++;
	return (n);
}

int
main(void)
{
	int i, k, n, found;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_drain_events();

	/* 1. per queue fragment cap */
	for (i = 1; i <= 200; i++)
		frag(1, i, 1, 8);
	n = count(1, &found);
	printf("perqueue: %d fragments held after 200 sent\n", n);
	if (n > IPFRAG_MAX_PERQUEUE) {
		printf("FAIL perqueue\n");
		fail = 1;
	}

	/* 2. offset 65528 plus the header length must not wrap */
	frag(2, 8191, 0, 8);
	n = count(2, &found);
	printf("wrap: queue %s, %d fragments\n", found ? "created" : "absent",
	    n);
	if (found) {
		printf("FAIL wrap\n");
		fail = 1;
	}

	/* 3. global memory cap with fragments added to existing queues */
	for (i = 0; i < 600; i++)
		frag(1000 + i, 1, 1, 8);
	for (i = 0; i < 600; i++)
		for (k = 0; k < 44; k++)
			frag(1000 + i, 2 + 185 * k, 1, 1480);
	printf("memcap: nfragmem %d, cap %d\n", nfragmem, IPFRAG_MAX_MEM);
	if (nfragmem > IPFRAG_MAX_MEM + 4096) {
		printf("FAIL memcap\n");
		fail = 1;
	}

	return (fail);
}
