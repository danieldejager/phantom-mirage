/*
 * config.c template_insert() (Low, CWE-476/CWE-252, config time only):
 * for each broadcast port of a honeypot instance it made a udp_con with
 * an unchecked calloc() (then wrote con->port through it) and a timer
 * with an unchecked event_new() (then passed it to event_add()). Info,
 * CWE-401: neither was ever freed, and inserting the same template
 * again left the old timer running beside a new one.
 *
 * Now each step is checked; a failure frees what was made, logs
 * LOG_ERR and skips that broadcast port. The timer and its argument are
 * kept on the port: template_deallocate() and a later template_insert()
 * of the same template free them.
 *
 * event_new and event_free are wrapped to count live broadcast timers
 * (callback bcast_trigger) and to fail event_new on demand; calloc is
 * wrapped to fail a request of sizeof(struct udp_con) on demand.
 * Nothing is sent: the timers never fire during the test.
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
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "interface.h"
#include "fuzz_common.h"

struct event *__real_event_new(struct event_base *, evutil_socket_t, short,
    event_callback_fn, void *);
void __real_event_free(struct event *);
void *__real_calloc(size_t, size_t);

#define MAXEV	16
static struct event *bev[MAXEV];
static int nbev, fail_event_new, fail_calloc;

struct event *
__wrap_event_new(struct event_base *b, evutil_socket_t fd, short what,
    event_callback_fn cb, void *arg)
{
	struct event *ev;

	if (fail_event_new && cb == bcast_trigger)
		return (NULL);
	ev = __real_event_new(b, fd, what, cb, arg);
	if (ev != NULL && cb == bcast_trigger && nbev < MAXEV)
		bev[nbev++] = ev;
	return (ev);
}

void
__wrap_event_free(struct event *ev)
{
	int i;

	for (i = 0; i < nbev; i++)
		if (bev[i] == ev)
			bev[i] = NULL;
	__real_event_free(ev);
}

void *
__wrap_calloc(size_t n, size_t sz)
{
	if (fail_calloc && n == 1 && sz == sizeof(struct udp_con))
		return (NULL);
	return (__real_calloc(n, sz));
}

/* Live broadcast timers, and how many of them are pending */
static int
live(int *pending)
{
	int i, n = 0;

	*pending = 0;
	for (i = 0; i < nbev; i++)
		if (bev[i] != NULL) {
			n++;
			if (event_pending(bev[i], EV_TIMEOUT, NULL))
				(*pending)++;
		}
	return (n);
}

static const char config[] =
	"create default\n"
	"set default default udp action block\n"
	"bind 10.0.0.2 default\n";

static int fails;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

int
main(void)
{
	struct template *tmpl;
	struct action action;
	int n, p;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);

	/* A honeypot instance with one broadcast port, not yet inserted */
	if ((tmpl = template_create("bcast")) == NULL) {
		printf("FAIL: template_create\n");
		return (1);
	}
	template_remove(tmpl);
	tmpl->honeypot_instance = 1;
	memset(&action, 0, sizeof(action));
	if (bcast_insert(tmpl, 68, 67, 3600, &action) == -1) {
		printf("FAIL: bcast_insert\n");
		return (1);
	}

	/* 1: event_new fails: port skipped, template still inserted */
	fail_event_new = 1;
	n = template_insert(tmpl);
	fail_event_new = 0;
	check(n == 0 && template_find("bcast") == tmpl,
	    "event_new failure: template inserted");
	check(live(&p) == 0, "event_new failure: no broadcast timer");
	if (fails)
		return (1);
	template_remove(tmpl);

	/* 2: calloc of the udp_con fails: port skipped, no timer */
	fail_calloc = 1;
	n = template_insert(tmpl);
	fail_calloc = 0;
	check(n == 0 && live(&p) == 0, "calloc failure: no broadcast timer");
	if (fails)
		return (1);
	template_remove(tmpl);

	/* 3: success, then insert again: still one running timer */
	template_insert(tmpl);
	check(live(&p) == 1 && p == 1, "insert: one pending broadcast timer");
	template_remove(tmpl);
	template_insert(tmpl);
	n = live(&p);
	printf("insert again: %d live, %d pending\n", n, p);
	check(n == 1 && p == 1, "insert again: old timer freed, one pending");

	/*
	 * 4: deallocating the template frees the timer, its argument and
	 * the broadcast port (CWE-401; leak checks report a leaked port)
	 */
	template_deallocate(tmpl);
	check(live(&p) == 0, "template_deallocate frees the broadcast timer");

	if (fails)
		return (1);
	printf("PASS: bcast_timer\n");
	return (0);
}
