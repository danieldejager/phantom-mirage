/*
 * PM-SCR-159 (Low): the inline flow creation in honeyd_udp_recv() did not
 * check evtimer_new(). The flow was already inserted, counted and holding
 * a source reference, and the NULL timer reached generic_timeout() and
 * later event_free() in udp_free(). The timer is now created before the
 * flow is listed or counted; on failure the flow is freed, the packet is
 * dropped without an ICMP error and honeyd_nudp and udplru are unchanged.
 *
 * event_new (evtimer_new is a macro for it) is wrapped for the daemon
 * objects (-Wl,--wrap=event_new) and made to fail once for the UDP idle
 * timer.
 */
#include "udpflow.h"

void honeyd_udp_timeout(int, short, void *);
struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
static int fail_event_new, failed;

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	if (fail_event_new && cb == honeyd_udp_timeout) {
		fail_event_new = 0;
		failed++;
		return (NULL);
	}
	return (__real_event_new(b, fd, what, cb, arg));
}

#define DST	0x0a000002

static const char config[] =
	"create linux\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	struct udp_con *c;
	int i, nudp, live;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	fuzz_ip_send_hook = count_icmp;

	for (i = 0; i < 5; i++)
		send_udp(0x0b000000 + i, 1024, DST);
	nudp = honeyd_nudp;
	live = live_udp();
	nicmp = 0;
	printf("before: live %d counter %d\n", live, nudp);

	fail_event_new = 1;
	send_udp(0x0c000001, 4000, DST);
	fail_event_new = 0;
	printf("after: live %d counter %d icmp %d\n", live_udp(), honeyd_nudp,
	    nicmp);

	check(failed == 1, "the idle timer allocation failed once");
	check(honeyd_nudp == nudp, "honeyd_nudp unchanged");
	check(live_udp() == live, "no flow added to udplru");
	check(find_udp(0x0c000001, 4000) == NULL, "failed flow not listed");
	check(nicmp == 0, "packet dropped without ICMP");
	if (fails)
		return (1);

	/* Success path still works for the same source */
	send_udp(0x0c000001, 4000, DST);
	c = find_udp(0x0c000001, 4000);
	check(c != NULL && c->conhdr.timeout != NULL, "next packet makes a flow");
	check(honeyd_nudp == live + 1 && live_udp() == live + 1,
	    "counter equals list length");
	if (c != NULL)
		udp_free(c);
	check(honeyd_nudp == live && live_udp() == live, "freed again");

	if (fails)
		return (1);
	printf("PASS: udp_recv_timer\n");
	return (0);
}
