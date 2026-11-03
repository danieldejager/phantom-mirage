/*
 * PM-SCR-139: with no option set the global UDP cap defaults to
 * HONEYD_MAX_UDP (32000). 40000 spoofed flows over two templates must
 * leave at most that many live.
 */
#include "udpflow.h"

#define NFLOWS	40000

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"create linux\n"
	"set linux default udp action reset\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n"
	"bind 10.0.0.3 linux\n";

int
main(void)
{
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	for (i = 0; i < NFLOWS; i++)
		send_udp(0x0b000000 + i, 1024, 0x0a000002 + i % 2);

	printf("%d flows sent, %d live\n", NFLOWS, live_udp());
	check(live_udp() <= HONEYD_MAX_UDP, "live flows at most 32000");
	check(&honeyd_nudp != NULL && honeyd_nudp == live_udp(),
	    "flow counter matches the list");
	if (fails)
		return (1);
	printf("PASS: udp_cap_default\n");
	return (0);
}
