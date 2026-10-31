/*
 * dhcpclient.c dhcp_template_new() (Low, CWE-476/CWE-252, adjacent
 * network: reached when a DHCP renewal times out): the template was
 * taken out of the index and its ARP entry, its name freed, and the
 * new name came from an unchecked strdup(). On failure the template
 * was left with a NULL name and an ARP entry and DHCP discover queued
 * for it.
 *
 * Now the new name is copied first; on failure dhcp_template_new()
 * logs LOG_ERR and returns with the template untouched: same name,
 * still in the index, same ARP entry, nothing queued.
 *
 * strdup is wrapped to fail once. The interface is the fake one from
 * fuzz/fuzz_common.c and eth_send is stubbed; nothing leaves the
 * process.
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
#include "arp.h"
#include "dhcpclient.h"
#include "fuzz_common.h"

void template_post_arp(struct template *, struct addr *);
char *__real_strdup(const char *);

static int fail_strdup;

char *
__wrap_strdup(const char *s)
{
	if (fail_strdup) {
		fail_strdup = 0;
		return (NULL);
	}
	return (__real_strdup(s));
}

static const char config[] =
	"create linux\n"
	"bind 10.0.0.2 linux\n";

int
main(void)
{
	struct template *tmpl;
	struct arp_req *arp;
	struct addr ip;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}
	tmpl->ethernet_addr = calloc(1, sizeof(struct addr));
	addr_aton("02:00:00:00:00:02", tmpl->ethernet_addr);
	tmpl->inter = &fuzz_iface;
	addr_aton("10.0.0.2", &ip);
	template_post_arp(tmpl, &ip);
	arp = arp_find(tmpl->ethernet_addr);

	fail_strdup = 1;
	dhcp_template_new(tmpl);
	fail_strdup = 0;

	printf("after failed strdup: name %s\n",
	    tmpl->name != NULL ? tmpl->name : "(null)");
	if (tmpl->name == NULL || strcmp(tmpl->name, "10.0.0.2") != 0 ||
	    template_find("10.0.0.2") != tmpl) {
		printf("FAIL: template renamed or out of the index\n");
		return (1);
	}
	if (arp == NULL || arp_find(tmpl->ethernet_addr) != arp ||
	    tmpl->dhcp_req != NULL) {
		printf("FAIL: ARP entry changed or DHCP request queued\n");
		return (1);
	}
	printf("PASS: dhcp_name_alloc\n");
	return (0);
}
