/*
 * config.c template_clone() (Low, CWE-401/CWE-476): when bcast_insert()
 * or port_insert() failed, template_clone() returned NULL but left the
 * half built clone in the template index, with the ports already
 * copied, and leaked it. A later clone under the same name then failed
 * in template_create(). The NULL check of the source template also ran
 * after it was dereferenced.
 *
 * Now both failure returns free the clone with template_free(), which
 * takes it out of the index and frees its ports and broadcast ports.
 *
 * bcast_insert() refuses a template name that does not fit
 * templateName, so a long clone name of a template with a broadcast
 * port drives the failure without any fault injection. port_insert()
 * exits on allocation failure and cannot return NULL today, so that
 * return is not driven here.
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
#include "fuzz_common.h"

static const char config[] =
	"create base\n"
	"add base tcp port 22 open\n"
	"broadcast base srcport 1024 dstport 9 time 3600 \"x\"\n";

int
main(void)
{
	const char *longname = "a-clone-name-longer-than-templateName";
	struct template *base, *clone;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((base = template_find("base")) == NULL ||
	    SPLAY_ROOT(&base->bcasts) == NULL) {
		printf("FAIL: base template or broadcast missing\n");
		return (1);
	}

	clone = template_clone(longname, base, NULL, 0);
	printf("clone: %s, in index: %s\n", clone ? "made" : "refused",
	    template_find(longname) ? "yes" : "no");
	if (clone != NULL) {
		printf("FAIL: clone with a too long broadcast name made\n");
		return (1);
	}
	if (template_find(longname) != NULL) {
		printf("FAIL: failed clone left in the index\n");
		return (1);
	}

	/* A short name still clones */
	if ((clone = template_clone("ok", base, NULL, 0)) == NULL) {
		printf("FAIL: clone refused\n");
		return (1);
	}
	template_free(clone);
	template_free_all(TEMPLATE_FREE_REGULAR);
	printf("PASS: tmpl_clone_fail\n");
	return (0);
}
