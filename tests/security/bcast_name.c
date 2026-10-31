/*
 * config.c: template_insert() copies the template name into the fixed
 * 20 byte templateName of every broadcast port. strncpy left it without
 * a terminating NUL when the name was 20 bytes or longer, and the
 * broadcast timer later reads it as a string. The copy must always be
 * NUL terminated (the name is truncated to 19 bytes).
 *
 * Cases:
 *  bcast_fit  a 19 byte name: copied whole
 *  bcast_long a 30 byte name: truncated to 19 bytes and terminated
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
#include "fuzz_common.h"

static int
bcast_case(const char *label, size_t n)
{
	struct template *tmpl;
	struct action action;
	struct port *bport;
	char name[64];
	size_t sz, want;
	int terminated, bad = 0;

	memset(name, 'n', n);
	name[n] = '\0';
	name[0] = label[6];	/* unique per case */
	tmpl = template_create(name);
	template_remove(tmpl);
	tmpl->honeypot_instance = 1;
	memset(&action, 0, sizeof(action));
	bcast_insert(tmpl, 1024, 9, 3600, &action);
	template_insert(tmpl);

	bport = SPLAY_ROOT(&tmpl->bcasts);
	sz = sizeof(bport->templateName);
	want = n < sz ? n : sz - 1;
	terminated = memchr(bport->templateName, '\0', sz) != NULL;
	printf("%s: name %zu bytes, templateName %s", label, n,
	    terminated ? "terminated" : "NOT terminated");
	if (terminated)
		printf(", %zu bytes", strlen(bport->templateName));
	printf("\n");
	if (!terminated || strlen(bport->templateName) != want ||
	    strncmp(bport->templateName, name, want) != 0)
		printf("FAIL %s\n", label), bad = 1;
	return (bad);
}

int
main(void)
{
	int bad = 0;

	fuzz_honeyd_init("create default\n");
	bad |= bcast_case("bcast_fit", 19);
	bad |= bcast_case("bcast_long", 30);
	if (bad)
		printf("FAIL\n");
	return (bad);
}
