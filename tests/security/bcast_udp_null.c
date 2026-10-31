/*
 * config.c: bcast_trigger() used the result of udp_new() without a NULL
 * check, so an allocation failure while setting up the broadcast helper
 * flow dereferenced NULL (finding 150). With the next calloc failing,
 * bcast_trigger() must return without a crash and leave the UDP flow
 * count unchanged.
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

int parse_line(struct evbuffer *, char *);
extern int honeyd_nudp;

static int fail_next;
void *__real_calloc(size_t, size_t);
void *
__wrap_calloc(size_t n, size_t sz)
{
	if (fail_next) {
		fail_next = 0;
		return (NULL);
	}
	return (__real_calloc(n, sz));
}

int
main(void)
{
	struct evbuffer *out = evbuffer_new();
	struct interface inter;
	struct template *tmpl;
	struct udp_con con;
	struct port port;
	int before;

	fuzz_honeyd_init("create default\n");
	if (parse_line(out, "bind 10.0.0.5 default\n") != 0 ||
	    (tmpl = template_find("10.0.0.5")) == NULL) {
		printf("FAIL setup\n");
		return (1);
	}
	memset(&inter, 0, sizeof(inter));
	inter.subnetBcastAddress = htonl(0x0a0000ff);
	tmpl->inter = &inter;

	memset(&con, 0, sizeof(con));
	memset(&port, 0, sizeof(port));
	strlcpy(port.templateName, "10.0.0.5", sizeof(port.templateName));
	port.number = 9;
	port.srcport = 1024;
	con.port = &port;

	before = honeyd_nudp;
	fail_next = 1;
	bcast_trigger(-1, EV_TIMEOUT, &con);
	fail_next = 0;
	printf("udp_fail: returned, nudp %d -> %d\n", before, honeyd_nudp);
	tmpl->inter = NULL;
	evbuffer_free(out);
	if (honeyd_nudp != before) {
		printf("FAIL nudp\n");
		return (1);
	}
	return (0);
}
