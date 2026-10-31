/*
 * config.c template_create() and template_clone() (Low, CWE-476/
 * CWE-252, config time): template_create() stored an unchecked
 * strdup() of the name and inserted the template in the index with a
 * NULL name; template_clone() stored an unchecked strdup() of the
 * origin name.
 *
 * Now template_create() frees the template and returns NULL before any
 * insert, and template_clone() frees the new template (out of the
 * index) and returns NULL. Leak checks stay on, so a leaked template
 * is reported.
 *
 * strdup is wrapped to fail the Nth call from now.
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
#include "fuzz_common.h"

char *__real_strdup(const char *);

static int fail_at;

char *
__wrap_strdup(const char *s)
{
	if (fail_at > 0 && --fail_at == 0)
		return (NULL);
	return (__real_strdup(s));
}

static const char config[] =
	"create default\n"
	"set default default udp action block\n";

int
main(void)
{
	struct template *tmpl, *def;

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((def = template_find("default")) == NULL) {
		printf("FAIL: no default template\n");
		return (1);
	}

	/* 1: template_create, strdup of the name fails */
	fail_at = 1;
	tmpl = template_create("tcreate");
	fail_at = 0;
	if (tmpl != NULL || template_find("tcreate") != NULL) {
		printf("FAIL: template_create kept a template without a "
		    "name\n");
		return (1);
	}
	printf("ok: template_create returns NULL\n");

	/* 2: template_clone, strdup of the origin fails (second call) */
	fail_at = 2;
	tmpl = template_clone("tclone", def, NULL, 0);
	fail_at = 0;
	if (tmpl != NULL || template_find("tclone") != NULL) {
		printf("FAIL: template_clone kept a template without an "
		    "origin\n");
		return (1);
	}
	printf("ok: template_clone returns NULL\n");

	/* 3: both still work */
	if ((tmpl = template_clone("tclone", def, NULL, 0)) == NULL ||
	    template_find("tclone") != tmpl) {
		printf("FAIL: template_clone after a failure\n");
		return (1);
	}
	template_free(tmpl);
	printf("PASS: template_name_alloc\n");
	return (0);
}
