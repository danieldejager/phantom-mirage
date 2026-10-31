/*
 * PM-SCR-101: strrpl() must refuse an expansion whose result plus the
 * terminating NUL does not fit in the buffer. The buffer is heap
 * allocated at its exact size so AddressSanitizer catches a one byte
 * overflow.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *strrpl(char *, size_t, char *, char *);

static int
expand(size_t size, size_t vlen, int want_ok)
{
	char *buf, *val, *r;
	int ok;

	buf = malloc(size);
	val = malloc(vlen + 1);
	if (buf == NULL || val == NULL)
		abort();
	memset(val, 'v', vlen);
	val[vlen] = '\0';
	strcpy(buf, "ab$x");		/* result is "ab" + value */

	r = strrpl(buf, size, "$x", val);
	ok = (r != NULL);
	printf("size %zu result %zu: %s\n", size, 2 + vlen,
	    ok ? "expanded" : "refused");
	if (ok && strlen(buf) != 2 + vlen)
		ok = -1;
	free(buf);
	free(val);
	return (ok == want_ok ? 0 : 1);
}

int
main(void)
{
	size_t size = 64;
	int fail = 0;

	fail |= expand(size, size - 4, 1);	/* result size - 2 */
	fail |= expand(size, size - 3, 1);	/* result size - 1, NUL fits */
	fail |= expand(size, size - 2, 0);	/* result fills buffer exactly */
	fail |= expand(size, size - 1, 0);	/* result one past the buffer */
	if (fail)
		printf("FAIL\n");
	return (fail);
}
