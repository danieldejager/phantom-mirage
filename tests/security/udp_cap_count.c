/*
 * PM-SCR-139: the global UDP flow counter must track the live list
 * across every free path: cap eviction, the idle timer, ICMP port
 * unreachable soft errors and the command side closing. It never goes
 * negative and ends equal to the list length.
 */
#include <sys/socket.h>
#include <unistd.h>
#include "udpflow.h"

extern struct callback cb_udp;
void cmd_ready_fd(struct command *, struct callback *, void *);

#define CAP	100
#define NFLOWS	150
#define DST	0x0a000002
#define SRC(i)	(0x0b000000 + (i))

static const char config[] =
	"option honeyd max_udp_flows 100\n"
	"create default\n"
	"set default default udp action block\n"
	"create linux\n"
	"set linux default udp action reset\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n";

static int
counter_ok(int want, const char *what)
{
	int ok = &honeyd_nudp != NULL && honeyd_nudp >= 0 &&
	    honeyd_nudp == live_udp() && live_udp() == want;

	printf("%s: live %d counter %d\n", what, live_udp(),
	    &honeyd_nudp != NULL ? honeyd_nudp : -1);
	check(ok, what);
	return (ok);
}

int
main(void)
{
	struct udp_con *c;
	struct tuple *t;
	int i, sv[2];

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);

	for (i = 0; i < NFLOWS; i++)
		send_udp(SRC(i), 1024, DST);
	counter_ok(CAP, "after cap eviction");

	/* Idle timer on flows 50..59 */
	for (i = 50; i < 60; i++)
		if ((c = find_udp(SRC(i), 1024)) != NULL)
			event_active(c->conhdr.timeout, EV_TIMEOUT, 1);
	fuzz_drain_events();
	counter_ok(CAP - 10, "after idle timer");

	/* Three port unreachables each on flows 60..69 */
	for (i = 60; i < 70; i++) {
		send_unreach(SRC(i), 1024, DST);
		send_unreach(SRC(i), 1024, DST);
		send_unreach(SRC(i), 1024, DST);
	}
	counter_ok(CAP - 20, "after ICMP soft errors");

	/* Command side closes on flows 70..79 */
	for (i = 70; i < 80; i++) {
		if ((c = find_udp(SRC(i), 1024)) == NULL)
			continue;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
			abort();
		close(sv[1]);
		c->cmd.pfd = sv[0];
		c->cmd.perrfd = -1;
		cmd_ready_fd(&c->cmd, &cb_udp, c);
		event_add(c->cmd.pread, NULL);
	}
	fuzz_drain_events();
	counter_ok(CAP - 30, "after command close");

	/* Expire everything left */
	TAILQ_FOREACH(t, &udplru, next)
		event_active(t->timeout, EV_TIMEOUT, 1);
	fuzz_drain_events();
	counter_ok(0, "after expiring all");

	if (fails)
		return (1);
	printf("PASS: udp_cap_count\n");
	return (0);
}
