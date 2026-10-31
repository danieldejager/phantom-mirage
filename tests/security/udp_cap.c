/*
 * PM-SCR-139: UDP flow state had no global cap. With
 * "option honeyd max_udp_flows 1000" and three templates, 2700 spoofed
 * flows must leave at most 1000 live. Eviction is LRU: a flow refreshed
 * just before the overflow survives and the oldest unrefreshed one goes.
 * Evictions are counted and no ICMP is sent for an evicted flow.
 */
#include "udpflow.h"

#define CAP	1000
#define NFLOWS	2700
#define SRC(i)	(0x0b000000 + (i))
#define DST(i)	(0x0a000002 + (i) % 3)

static const char config[] =
	"option honeyd max_udp_flows 1000\n"
	"create default\n"
	"set default default udp action block\n"
	"create linux\n"
	"set linux default udp action reset\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n"
	"bind 10.0.0.3 linux\n"
	"bind 10.0.0.4 linux\n";

int
main(void)
{
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_ip_send_hook = count_icmp;

	for (i = 0; i < CAP; i++)
		send_udp(SRC(i), 1024, DST(i));
	check(live_udp() == CAP, "1000 flows live at the cap");

	/* Refresh the oldest flow, then overflow by one */
	send_udp(SRC(0), 1024, DST(0));
	send_udp(SRC(CAP), 1024, DST(CAP));
	check(live_udp() == CAP, "still 1000 after one more");
	check(find_udp(SRC(0), 1024) != NULL, "refreshed flow 0 survives");
	check(find_udp(SRC(1), 1024) == NULL, "oldest flow 1 evicted");
	check(find_udp(SRC(CAP), 1024) != NULL, "new flow present");

	for (i = CAP + 1; i < NFLOWS; i++)
		send_udp(SRC(i), 1024, DST(i));

	printf("%d flows sent, %d live, icmp %d\n", NFLOWS, live_udp(), nicmp);
	check(live_udp() <= CAP, "live flows at most the cap");
	check(&honeyd_udp_evicted != NULL &&
	    honeyd_udp_evicted == NFLOWS - CAP, "eviction counter is 1700");
	check(&honeyd_nudp != NULL && honeyd_nudp == live_udp(),
	    "flow counter matches the list");
	check(nicmp == 0, "no ICMP sent for evicted flows");

	if (fails)
		return (1);
	printf("PASS: udp_cap\n");
	return (0);
}
