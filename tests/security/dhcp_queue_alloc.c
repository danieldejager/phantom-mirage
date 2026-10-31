/*
 * PM-SCR-154, dhcpclient.c: the first queue_dhcp_discover() call
 * allocates the DHCP discover queue and wrote to it without checking
 * the allocation, a NULL dereference when it fails. The allocation now
 * fails the request cleanly and the next call allocates again.
 *
 * malloc is wrapped for the daemon objects (-Wl,--wrap=malloc) and made
 * to fail on demand. eth_send is stubbed, nothing leaves the process.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "interface.h"
#include "dhcpclient.h"
#include "fuzz_common.h"

void *__real_malloc(size_t);
static int fail_malloc;

void *
__wrap_malloc(size_t n)
{
	if (fail_malloc)
		return (NULL);
	return (__real_malloc(n));
}

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	struct template *tmpl;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL)
		abort();

	fail_malloc = 1;
	queue_dhcp_discover(tmpl);
	fail_malloc = 0;
	printf("queue allocation failed: no crash\n");

	queue_dhcp_discover(tmpl);
	printf("next call queued the template\n");
	dhcp_req_free(tmpl);		/* takes it off the queue again */
	printf("OK\n");
	return (0);
}
