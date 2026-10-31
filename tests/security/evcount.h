/*
 * Live libevent event counter for the PM-SCR-007 tests. Link with
 * -Wl,--wrap=event_new,--wrap=event_free: every event_new adds one and
 * every event_free takes one away, so a free path that only calls
 * event_del shows up as a growing count.
 */
#ifndef EVCOUNT_H
#define EVCOUNT_H

#include <stdio.h>
#include <event2/event.h>

static int ev_live;
static int ev_made;	/* every event_new, freed or not */

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
void __real_event_free(struct event *);

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	struct event *ev = __real_event_new(b, fd, what, cb, arg);

	if (ev != NULL) {
		ev_live++;
		ev_made++;
	}
	return (ev);
}

void
__wrap_event_free(struct event *ev)
{
	ev_live--;
	__real_event_free(ev);
}

static int ev_fail;

/* check NAME ROUNDS LEFT MAX: at most MAX events may outlive ROUNDS rounds */
static void
ev_check(const char *name, int rounds, int left, int max)
{
	printf("%s: %d rounds, %d events left over (limit %d)\n", name,
	    rounds, left, max);
	if (left > max) {
		printf("FAIL %s\n", name);
		ev_fail = 1;
	}
}

#endif
