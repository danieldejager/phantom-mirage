/*
 * PM-SCR-198, subsystem.c subsystem_restart: a restart that failed was
 * never tried again, so a subsystem with restart set stayed down for
 * good after one failed start (CWE-754).  PM-SCR-208: after the
 * bounded fast retries it still stayed down for good; a slow retry
 * now continues.
 *
 * cmd_subsystem is replaced with --wrap: it fails a set number of times
 * and then reports a started subsystem without forking anything.
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
#include <pcap.h>
#include <dnet.h>
#include <event2/event.h>
#include "honeyd.h"
#include "template.h"
#include "subsystem.h"
#include "fuzz_common.h"

#ifndef SUBSYSTEM_RESTART_SLOW
#define SUBSYSTEM_RESTART_SLOW	600	/* lets the test build on the base */
#endif

struct subsystem *template_subsystem_find(const char *);
void subsystem_cleanup(struct subsystem *);
void subsystem_restart(int, short, void *);

/* The pending subsystem_restart timer for the subsystem, if any */
static struct subsystem *want;
static struct event *found;

static int
find_restart(const struct event_base *b, const struct event *ev, void *a)
{
	(void)b; (void)a;
	if (event_get_callback(ev) == subsystem_restart &&
	    event_get_callback_arg(ev) == want &&
	    event_pending(ev, EV_TIMEOUT, NULL))
		found = (struct event *)ev;
	return (0);
}

/* Seconds until the restart timer fires, or -1 when there is none */
static long
restart_in(struct subsystem *sub)
{
	struct timeval tv, now;

	want = sub;
	found = NULL;
	event_base_foreach_event(libevent_base, find_restart, NULL);
	if (found == NULL)
		return (-1);
	event_pending(found, EV_TIMEOUT, &tv);
	gettimeofday(&now, NULL);
	return ((long)(tv.tv_sec - now.tv_sec));
}

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n"
	"add 10.0.0.2 subsystem \"/bin/true\" restart\n";

static int calls, fails;

int
__wrap_cmd_subsystem(struct template *tmpl, struct subsystem *sub,
    char *execcmd, char *argv[])
{
	(void)tmpl; (void)execcmd; (void)argv;
	if (++calls <= fails)
		return (-1);
	sub->cmd.pid = 4242;		/* started, nothing forked */
	return (0);
}

static int
expect(int ok, const char *what)
{
	printf("%s: %s (%d calls)\n", ok ? "ok" : "FAIL", what, calls);
	return (ok ? 0 : 1);
}

int
main(int argc, char **argv)
{
	struct subsystem *sub;
	const char *t = argc > 1 ? argv[1] : "";
	int rc;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(20);
	fuzz_honeyd_init(config);
	if ((sub = template_subsystem_find("/bin/true")) == NULL ||
	    !(sub->flags & SUBSYSTEM_RESTART)) {
		printf("FAIL: setup\n");
		return (1);
	}
	sub->cmd.pid = -1;
	timerclear(&sub->tv_restart);	/* last start long ago */

	if (strcmp(t, "retry") == 0) {
		/* One failed restart, then a retry that succeeds */
		fails = 1;
		subsystem_cleanup(sub);
		if (expect(calls == 1 && sub->cmd.pid == -1,
		    "first restart failed"))
			return (1);
		/* The retry is a timer; other start up events may come first */
		for (int i = 0; i < 100 && calls < 2; i++)
			event_base_loop(libevent_base, EVLOOP_ONCE);
		rc = expect(calls == 2 && sub->cmd.pid == 4242 &&
		    sub->restart_tries == 0, "later retry started it");
		sub->cmd.pid = -1;
		return (rc);
	}
	if (strcmp(t, "slow_retry") == 0) {
		/*
		 * PM-SCR-208: after the bounded fast retries a slow retry
		 * is still scheduled, and it starts the subsystem
		 */
		long in;

		fails = SUBSYSTEM_RESTART_TRIES;
		sub->restart_tries = SUBSYSTEM_RESTART_TRIES - 1;
		subsystem_cleanup(sub);
		in = restart_in(sub);
		if (expect(calls == 1 && sub->cmd.pid == -1 &&
		    in >= SUBSYSTEM_RESTART_SLOW - 5 &&
		    in <= SUBSYSTEM_RESTART_SLOW, "slow retry scheduled"))
			return (1);
		/* Another failure keeps the slow pace */
		event_active(found, EV_TIMEOUT, 1);
		event_base_loop(libevent_base, EVLOOP_ONCE | EVLOOP_NONBLOCK);
		in = restart_in(sub);
		if (expect(calls == 2 && sub->cmd.pid == -1 &&
		    sub->restart_tries == SUBSYSTEM_RESTART_TRIES &&
		    in >= SUBSYSTEM_RESTART_SLOW - 5, "still slow after a "
		    "further failure"))
			return (1);
		calls = 0;
		fails = 0;
		event_active(found, EV_TIMEOUT, 1);
		event_base_loop(libevent_base, EVLOOP_ONCE | EVLOOP_NONBLOCK);
		rc = expect(calls == 1 && sub->cmd.pid == 4242 &&
		    sub->restart_tries == 0 && restart_in(sub) == -1,
		    "slow retry started it");
		sub->cmd.pid = -1;
		return (rc);
	}
	printf("FAIL: unknown case %s\n", t);
	return (1);
}
