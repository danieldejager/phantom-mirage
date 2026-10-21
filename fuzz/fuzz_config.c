/*
 * libFuzzer harness: the configuration language through parse_line(),
 * the in-memory path honeydctl commands take (issue #38). Templates and
 * routes are reset after every input.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>

#include "fuzz_common.h"

int parse_line(struct evbuffer *, char *);
void template_free_all(int);
void router_end(void);
void router_init(void);
#define TEMPLATE_FREE_REGULAR	0x00	/* template.h */

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fuzz_honeyd_init(NULL);
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct evbuffer *out;
	char *line;

	if (size > 16384)
		return (0);
	if ((line = malloc(size + 1)) == NULL)
		return (0);
	memcpy(line, data, size);
	line[size] = '\0';

	out = evbuffer_new();
	parse_line(out, line);
	evbuffer_free(out);
	free(line);

	fuzz_drain_events();
	/* Same reset as a config reload (SIGHUP) */
	template_free_all(TEMPLATE_FREE_REGULAR);
	router_end();
	return (0);
}
