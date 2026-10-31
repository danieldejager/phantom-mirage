/*
 * config.c template_get_dhcp_address() (Low, CWE-400/CWE-770/CWE-617,
 * adjacent network: a rogue DHCP server or many DHCP cloned templates
 * on the segment use up the temporary 169.254.x.y addresses): when the
 * counter ran out the whole process called exit().
 *
 * Now it logs LOG_ERR and returns -1 for every later call, and its
 * caller dhcp_template_new() already returns with the template
 * untouched on -1: same name, still in the index, nothing queued.
 *
 * The counter is static, so the harness simply asks for every address
 * once (no test hook). Nothing leaves the process.
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
#include <event2/buffer.h>
#include "template.h"
#include "interface.h"
#include "dhcpclient.h"
#include "fuzz_common.h"

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	struct template *tmpl;
	struct addr addr, last;
	int i, n = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);

	/* Use up every temporary address; must not exit */
	for (i = 0; i < 70000; i++) {
		if (template_get_dhcp_address(&addr) == -1)
			break;
		last = addr;
		n++;
	}
	printf("temporary addresses handed out: %d, last %s\n", n,
	    addr_ntoa(&last));
	if (n == 0 || i == 70000) {
		printf("FAIL: counter never ran out\n");
		return (1);
	}
	if (template_get_dhcp_address(&addr) != -1) {
		printf("FAIL: address handed out after exhaustion\n");
		return (1);
	}

	/* The caller fails that lease cleanly */
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}
	dhcp_template_new(tmpl);
	if (tmpl->name == NULL || strcmp(tmpl->name, "10.0.0.2") != 0 ||
	    template_find("10.0.0.2") != tmpl || tmpl->dhcp_req != NULL) {
		printf("FAIL: template changed after failed address\n");
		return (1);
	}
	printf("PASS: dhcp_addr_exhaust\n");
	return (0);
}
