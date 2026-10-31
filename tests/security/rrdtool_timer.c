/*
 * PM-SCR-007, rrdtool.c: rrdtool_free() only called event_del() on the
 * driver's restart timer, so every driver that was freed leaked it.
 *
 * rrdtool_init() forks the rrdtool binary, which the harness does not
 * allow, so the driver is built here the same way rrdtool_init() builds
 * it around a closed descriptor and then handed to rrdtool_free().
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include "rrdtool.h"
#include "evcount.h"

#define ROUNDS	50

static void
nop(int fd, short what, void *arg)
{
}

int
main(void)
{
	struct event_base *b = event_base_new();
	struct rrdtool_drv *drv;
	int i, base;

	setvbuf(stdout, NULL, _IONBF, 0);
	base = ev_live;
	for (i = 0; i < ROUNDS; i++) {
		if ((drv = calloc(1, sizeof(*drv))) == NULL)
			abort();
		drv->fd = -1;
		TAILQ_INIT(&drv->commands);
		drv->evb = bufferevent_socket_new(b, -1, 0);
		drv->ev_timeout = evtimer_new(b, nop, drv);
		rrdtool_free(drv);
	}
	ev_check("rrdtool", ROUNDS, ev_live - base, 0);
	event_base_free(b);

	if (ev_fail) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: rrdtool_timer\n");
	return (0);
}
