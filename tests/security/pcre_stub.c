/* pcre stand in for the security harnesses: every regex reports no match. */
#include <stdlib.h>
#include <pcre.h>

static char dummy;

pcre *
pcre_compile(const char *p, int o, const char **e, int *eo,
    const unsigned char *t)
{
	return ((pcre *)&dummy);
}

int
pcre_exec(const pcre *r, const pcre_extra *x, const char *s, int l, int st,
    int op, int *ov, int n)
{
	return (-1);
}

static void nofree(void *p) { }
void (*pcre_free)(void *) = nofree;
