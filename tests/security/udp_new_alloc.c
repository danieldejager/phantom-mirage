/*
 * PM-SCR-157 (Info): udp_new() made room under the global UDP flow cap before allocating
 * the new flow, so a failed allocation at the cap still evicted a live
 * flow. The allocation now comes first: on failure no flow is evicted
 * and honeyd_udp_evicted and honeyd_nudp are unchanged. On success the
 * least recently used flow is evicted as before and the new flow is
 * never the one evicted.
 *
 * calloc is wrapped for the daemon objects (-Wl,--wrap=calloc) and made
 * to fail on demand.
 */
#include "udpflow.h"

void *__real_calloc(size_t, size_t);
static int fail_calloc;

void *
__wrap_calloc(size_t n, size_t sz)
{
	if (fail_calloc)
		return (NULL);
	return (__real_calloc(n, sz));
}

#define CAP	10
#define DST	0x0a000002
#define SRC(i)	(0x0b000000 + (i))

static const char config[] =
	"option honeyd max_udp_flows 10\n"
	"create linux\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	struct ip_hdr ip;
	struct udp_hdr udp;
	struct udp_con *c;
	uint32_t evicted;
	int i, nudp;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);

	for (i = 0; i < CAP; i++)
		send_udp(SRC(i), 1024, DST);
	check(live_udp() == CAP && honeyd_nudp == CAP, "at cap");
	evicted = honeyd_udp_evicted;
	nudp = honeyd_nudp;

	memset(&ip, 0, sizeof(ip));
	memset(&udp, 0, sizeof(udp));
	ip.ip_src = htonl(0x0c000001);
	ip.ip_dst = htonl(DST);
	udp.uh_sport = htons(4000);
	udp.uh_dport = htons(53);

	fail_calloc = 1;
	c = udp_new(&ip, &udp, 0);
	fail_calloc = 0;

	printf("failed alloc: live %d counter %d evicted %u (was %u)\n",
	    live_udp(), honeyd_nudp, honeyd_udp_evicted, evicted);
	check(c == NULL, "udp_new returns NULL");
	check(live_udp() == CAP, "no flow evicted");
	check(find_udp(SRC(0), 1024) != NULL, "oldest flow still live");
	check(honeyd_udp_evicted == evicted, "eviction counter unchanged");
	check(honeyd_nudp == nudp, "honeyd_nudp unchanged");

	/* Success path: oldest evicted, counted, new flow at the LRU head */
	c = udp_new(&ip, &udp, 0);
	check(c != NULL, "next udp_new works");
	check(find_udp(SRC(0), 1024) == NULL, "oldest flow evicted");
	check(c != NULL && find_udp(0x0c000001, 4000) == c,
	    "new flow not evicted");
	check(c != NULL && TAILQ_FIRST(&udplru) == &c->conhdr,
	    "new flow at LRU head");
	check(honeyd_udp_evicted == evicted + 1, "eviction counted");
	check(honeyd_nudp == CAP && live_udp() == CAP,
	    "counter equals list length");

	if (fails)
		return (1);
	printf("PASS: udp_new_alloc\n");
	return (0);
}
