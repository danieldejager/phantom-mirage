/*
 * PM-SCR-160 (Info): the inline flow creation in honeyd_udp_recv() made
 * room under the global UDP flow cap before allocating the new flow, so
 * a failed allocation at the cap still evicted a live flow and counted
 * the eviction. The allocation now comes first: on failure no flow is
 * evicted, honeyd_udp_evicted and honeyd_nudp are unchanged and the
 * packet is dropped without an ICMP error. On success the least recently
 * used flow is evicted as before.
 *
 * calloc is wrapped for the daemon objects (-Wl,--wrap=calloc) and made
 * to fail once for an allocation the size of a struct udp_con.
 */
#include "udpflow.h"

void *__real_calloc(size_t, size_t);
static int fail_calloc, failed;

void *
__wrap_calloc(size_t n, size_t sz)
{
	if (fail_calloc && n * sz == sizeof(struct udp_con)) {
		fail_calloc = 0;
		failed++;
		return (NULL);
	}
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
	struct udp_con *c;
	uint32_t evicted;
	int i, nudp;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_ip_send_hook = count_icmp;

	for (i = 0; i < CAP; i++)
		send_udp(SRC(i), 1024, DST);
	check(live_udp() == CAP && honeyd_nudp == CAP, "at cap");
	evicted = honeyd_udp_evicted;
	nudp = honeyd_nudp;
	nicmp = 0;

	fail_calloc = 1;
	send_udp(0x0c000001, 4000, DST);
	fail_calloc = 0;

	printf("failed alloc: live %d counter %d evicted %u (was %u) icmp %d\n",
	    live_udp(), honeyd_nudp, honeyd_udp_evicted, evicted, nicmp);
	check(failed == 1, "the flow allocation failed once");
	check(live_udp() == CAP, "no flow evicted");
	check(find_udp(SRC(0), 1024) != NULL, "oldest flow still live");
	check(honeyd_udp_evicted == evicted, "eviction counter unchanged");
	check(honeyd_nudp == nudp, "honeyd_nudp unchanged");
	check(find_udp(0x0c000001, 4000) == NULL, "failed flow not listed");
	check(nicmp == 0, "packet dropped without ICMP");

	/* Success path: oldest evicted, counted, new flow at the LRU head */
	send_udp(0x0c000001, 4000, DST);
	c = find_udp(0x0c000001, 4000);
	check(c != NULL, "next packet makes a flow");
	check(find_udp(SRC(0), 1024) == NULL, "oldest flow evicted");
	check(c != NULL && TAILQ_FIRST(&udplru) == &c->conhdr,
	    "new flow at LRU head");
	check(honeyd_udp_evicted == evicted + 1, "eviction counted");
	check(honeyd_nudp == CAP && live_udp() == CAP,
	    "counter equals list length");

	if (fails)
		return (1);
	printf("PASS: udp_recv_alloc\n");
	return (0);
}
