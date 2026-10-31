/*
 * The LeakSanitizer suppressions cover the data file loaders only. A
 * leak seeded in another start up step (router_init, through --wrap) is
 * still reported.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_common.h"

void __real_router_init(void);
void *volatile lsan_scope_sink;

void
__wrap_router_init(void)
{
	__real_router_init();
	if (getenv("LSAN_SCOPE_SEED") != NULL) {
		lsan_scope_sink = malloc(4242);
		lsan_scope_sink = NULL;		/* leaked */
	}
}

int
main(void)
{
	fuzz_honeyd_init("create linux\n");
	printf("ok: init done\n");
	return (0);
}
