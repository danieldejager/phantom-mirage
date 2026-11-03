/*
 * PM-SCR-184, config.c template_clone: when a dynamic rule could not be
 * copied into the clone, the warning had three %s conversions and two
 * arguments (CWE-685), and the clone went on without the rule.
 *
 * The rule copy is made to fail by taking its name first. The clone must
 * now fail, leave nothing in the template index, and log a complete
 * message.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pcap.h>
#include <dnet.h>
#include <event2/event.h>
#include "honeyd.h"
#include "template.h"
#include "fuzz_common.h"

static const char config[] =
	"create child\n"
	"dynamic dyn\n"
	"add dyn otherwise use child\n";

static char logged[1024];

void __real_syslog(int, const char *, ...);

void
__wrap_syslog(int pri, const char *fmt, ...)
{
	va_list ap;

	(void)pri;
	va_start(ap, fmt);
	vsnprintf(logged, sizeof(logged), fmt, ap);
	va_end(ap);
	printf("syslog: %s\n", logged);
}

int
main(void)
{
	struct template *dyn, *copy;
	int bad = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	dyn = template_find("dyn");
	if (dyn == NULL || TAILQ_EMPTY(&dyn->dynamic)) {
		printf("FAIL: setup\n");
		return (1);
	}
	/* The name the rule copy would get */
	if (template_create("copy_0_dyn_0_child") == NULL) {
		printf("FAIL: setup, name\n");
		return (1);
	}
	logged[0] = '\0';
	copy = template_clone("copy", dyn, NULL, 0);
	if (copy != NULL) {
		printf("FAIL: clone without its dynamic rule succeeded\n");
		bad = 1;
	}
	if (template_find("copy") != NULL) {
		printf("FAIL: failed clone left in the index\n");
		bad = 1;
	}
	if (strcmp(logged, "template_clone: couldn't insert dynamic cond "
	    "dyn_0_child into copy") != 0) {
		printf("FAIL: log line \"%s\"\n", logged);
		bad = 1;
	}
	if (!bad)
		printf("ok: clone failed cleanly\n");
	return (bad);
}
