/*
 * PM-SCR-101: boundaries of copy_bounded() and strrpl_bounded() in
 * util.c. Every destination is heap allocated at its exact size so
 * AddressSanitizer catches a one byte overflow.
 *
 * copy_bounded:   exact fit, one byte over, empty source, zero size
 * strrpl_bounded: exact fit, one byte over, empty input, empty
 *                 replacement, no match
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int copy_bounded(char *, size_t, const char *, size_t);
int strrpl_bounded(char *, size_t, const char *, const char *, char **);

static int bad;

static void
check(const char *name, int got, int want, const char *buf, const char *exp)
{
	int ok = got == want && (exp == NULL || strcmp(buf, exp) == 0);

	printf("%s: rc %d (want %d)%s%s%s\n", name, got, want,
	    exp ? " buf \"" : "", exp ? buf : "", exp ? "\"" : "");
	if (!ok)
		printf("FAIL %s\n", name), bad = 1;
}

static void
copy_cases(void)
{
	char *d;

	d = malloc(4);
	check("copy_fit", copy_bounded(d, 4, "abc", 3), 0, d, "abc");
	strcpy(d, "xyz");
	check("copy_over", copy_bounded(d, 4, "abcd", 4), -1, d, "xyz");
	check("copy_empty", copy_bounded(d, 4, "", 0), 0, d, "");
	free(d);
	d = malloc(1);
	check("copy_empty_size1", copy_bounded(d, 1, "", 0), 0, d, "");
	d[0] = 'q';
	check("copy_size0", copy_bounded(d, 0, "", 0), -1, NULL, NULL);
	if (d[0] != 'q')
		printf("FAIL copy_size0 wrote\n"), bad = 1;
	free(d);
}

/* strrpl_bounded on a buffer of exactly size bytes holding init */
static int
rpl(size_t size, const char *init, const char *m, const char *v,
    char *out, size_t outlen, int *where_ok)
{
	char *buf = malloc(size), *where = NULL;
	int rc;

	strcpy(buf, init);
	rc = strrpl_bounded(buf, size, m, v, &where);
	*where_ok = rc == 1 ? (where != NULL && where >= buf &&
	    where < buf + size && strncmp(where, v, strlen(v)) == 0) :
	    (where == NULL);
	snprintf(out, outlen, "%s", buf);
	free(buf);
	return (rc);
}

static void
rpl_cases(void)
{
	char out[64];
	int w;

	/* "ab$x" with "vvvv": result "abvvvv", 6 bytes plus NUL */
	check("rpl_fit", rpl(7, "ab$x", "$x", "vvvv", out, sizeof(out), &w),
	    1, out, "abvvvv");
	if (!w) printf("FAIL rpl_fit where\n"), bad = 1;
	check("rpl_over", rpl(7, "ab$x", "$x", "vvvvv", out, sizeof(out), &w),
	    -1, out, "ab$x");
	if (!w) printf("FAIL rpl_over where\n"), bad = 1;
	check("rpl_empty_input", rpl(1, "", "$x", "v", out, sizeof(out), &w),
	    0, out, "");
	check("rpl_empty_value", rpl(5, "ab$x", "$x", "", out, sizeof(out), &w),
	    1, out, "ab");
	if (!w) printf("FAIL rpl_empty_value where\n"), bad = 1;
	check("rpl_no_match", rpl(8, "ab$y", "$x", "v", out, sizeof(out), &w),
	    0, out, "ab$y");
	if (!w) printf("FAIL rpl_no_match where\n"), bad = 1;
}

int
main(void)
{
	copy_cases();
	rpl_cases();
	if (bad)
		printf("FAIL\n");
	return (bad);
}
