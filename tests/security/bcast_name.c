/*
 * config.c: every broadcast port keeps its template name in the fixed
 * 20 byte templateName, and bcast_trigger() finds the template again
 * by that name. A longer name was truncated, so the lookup could find
 * another template or none, and bcast_trigger() then dereferenced
 * NULL. A broadcast on a template name of 20 bytes or more must be
 * refused at config time, and bcast_trigger() must not crash when the
 * template is gone.
 *
 * Cases:
 *  bcast_19      a 19 byte name: accepted, templateName holds it whole
 *  bcast_20      a 20 byte name: refused at config time
 *  bcast_30      a 30 byte name: refused at config time
 *  trigger_gone  bcast_trigger() for a name with no template: no crash
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

int parse_line(struct evbuffer *, char *);

/* Returns 0 when the config was accepted */
static int
bcast_conf(const char *name, struct evbuffer *out)
{
	char line[256];

	snprintf(line, sizeof(line), "create %s\n"
	    "broadcast %s srcport 1024 dstport 9 time 3600 \"x\"\n",
	    name, name);
	return (parse_line(out, line));
}

static int
bcast_case(const char *label, char c, size_t n, int want_ok)
{
	struct evbuffer *out = evbuffer_new();
	struct template *tmpl;
	struct port *bport;
	char name[64];
	int rc, bad = 0;

	memset(name, c, n);
	name[n] = '\0';
	rc = bcast_conf(name, out);
	tmpl = template_find(name);
	bport = tmpl != NULL ? SPLAY_ROOT(&tmpl->bcasts) : NULL;
	printf("%s: name %zu bytes, config %s, broadcast port %s\n", label, n,
	    rc == 0 ? "accepted" : "refused", bport ? "added" : "none");
	if (rc != 0)
		printf("%s: error: %.*s", label,
		    (int)evbuffer_get_length(out),
		    (char *)evbuffer_pullup(out, -1));
	if (want_ok) {
		if (rc != 0 || bport == NULL)
			printf("FAIL %s\n", label), bad = 1;
		else {
			/* As template_insert() fills it for an instance */
			strlcpy(bport->templateName, tmpl->name,
			    sizeof(bport->templateName));
			if (strcmp(bport->templateName, name) != 0)
				printf("FAIL %s templateName\n", label),
				    bad = 1;
		}
	} else if (rc == 0 || bport != NULL ||
	    strstr((char *)evbuffer_pullup(out, -1), "too long") == NULL)
		printf("FAIL %s\n", label), bad = 1;
	evbuffer_free(out);
	return (bad);
}

static int
trigger_gone(void)
{
	struct udp_con con;
	struct port port;

	memset(&con, 0, sizeof(con));
	memset(&port, 0, sizeof(port));
	strlcpy(port.templateName, "no-such-template",
	    sizeof(port.templateName));
	port.number = 9;
	con.port = &port;
	bcast_trigger(-1, EV_TIMEOUT, &con);
	printf("trigger_gone: returned\n");
	return (0);
}

int
main(void)
{
	int bad = 0;

	fuzz_honeyd_init("create default\n");
	bad |= bcast_case("bcast_19", 'a', 19, 1);
	bad |= bcast_case("bcast_20", 'b', 20, 0);
	bad |= bcast_case("bcast_30", 'c', 30, 0);
	bad |= trigger_gone();
	if (bad)
		printf("FAIL\n");
	return (bad);
}
