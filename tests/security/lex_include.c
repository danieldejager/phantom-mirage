/*
 * PM-SCR-027: the lexer EOF rule decremented includes_index for every
 * buffer end, including the single line buffers from parse_line()
 * (honeydctl and the control socket). After a few commands the index
 * went negative and the next include wrote linenos, filenames and
 * includes at a negative index.
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>

#include "fuzz_common.h"

int parse_line(struct evbuffer *, char *);
extern int includes_index;

int
main(void)
{
	char path[] = "/tmp/pm-lex-incXXXXXX";
	char line[128];
	struct evbuffer *out;
	int fd, i;

	fuzz_honeyd_init(NULL);
	if ((fd = mkstemp(path)) == -1)
		return (1);
	if (write(fd, "create inc\n", 11) != 11)
		return (1);
	close(fd);

	out = evbuffer_new();
	for (i = 0; i < 3; i++) {
		parse_line(out, "list template");
		printf("after command %d: includes_index %d\n",
		    i + 1, includes_index);
	}
	snprintf(line, sizeof(line), "include %s\n", path);
	parse_line(out, line);
	printf("after include: includes_index %d\n", includes_index);
	evbuffer_free(out);
	unlink(path);
	if (includes_index != 0) {
		printf("FAIL\n");
		return (1);
	}
	return (0);
}
