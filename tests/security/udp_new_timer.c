/*
 * PM-SCR-156 (Low): udp_new() did not check evtimer_new(): a NULL idle timer was stored on
 * a live flow and later reached evtimer_add() and event_free(). Now the
 * flow is freed, nothing is left on udplru or counted in honeyd_nudp,
 * and udp_new() returns NULL.
 *
 * event_new (evtimer_new is a macro for it) is wrapped for the daemon
 * objects (-Wl,--wrap=event_new) and made to fail on demand.
 */
#include "udpflow.h"

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
static int fail_event_new;

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	if (fail_event_new)
		return (NULL);
	return (__real_event_new(b, fd, what, cb, arg));
}

static const char config[] =
	"create linux\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	struct ip_hdr ip;
	struct udp_hdr udp;
	struct udp_con *c;
	int i, nudp, live;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);

	for (i = 0; i < 5; i++)
		send_udp(0x0b000000 + i, 1024, 0x0a000002);
	nudp = honeyd_nudp;
	live = live_udp();
	printf("before: live %d counter %d\n", live, nudp);

	memset(&ip, 0, sizeof(ip));
	memset(&udp, 0, sizeof(udp));
	ip.ip_src = htonl(0x0c000001);
	ip.ip_dst = htonl(0x0a000002);
	udp.uh_sport = htons(4000);
	udp.uh_dport = htons(53);

	fail_event_new = 1;
	c = udp_new(&ip, &udp, 0);
	fail_event_new = 0;

	check(c == NULL, "udp_new returns NULL when the timer fails");
	check(honeyd_nudp == nudp, "honeyd_nudp unchanged");
	check(live_udp() == live, "no flow added to udplru");
	check(find_udp(0x0c000001, 4000) == NULL, "failed flow not listed");
	printf("after: live %d counter %d\n", live_udp(), honeyd_nudp);
	if (fails)
		return (1);	/* base: the flow holds a NULL timer, stop here */

	/* Success path still works */
	c = udp_new(&ip, &udp, 0);
	check(c != NULL && c->conhdr.timeout != NULL, "next udp_new works");
	check(honeyd_nudp == live + 1 && live_udp() == live + 1,
	    "counter equals list length");
	udp_free(c);
	check(honeyd_nudp == live && live_udp() == live, "freed again");

	if (fails)
		return (1);
	printf("PASS: udp_new_timer\n");
	return (0);
}
