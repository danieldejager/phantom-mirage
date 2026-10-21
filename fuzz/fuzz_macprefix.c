/*
 * libFuzzer harness: the nmap-mac-prefixes parser (ethernet.c) plus the
 * vendor lookups that use its index (issue #38). ethernet.c is included
 * directly so the index can be freed after every input.
 */
#include "../ethernet.c"

rand_t *honeyd_rand;

static void
ethernet_reset(void)
{
	struct etherindex *e, *next;
	struct ethernetcode *base = NULL;
	size_t i;

	for (e = SPLAY_MIN(ethertree, &etherroot); e != NULL; e = next) {
		next = SPLAY_NEXT(ethertree, &etherroot, e);
		SPLAY_REMOVE(ethertree, &etherroot, e);
		for (i = 0; i < e->list_size; i++) {
			struct ethernetcode *c = e->list[i];
			if (base == NULL || c < base)
				base = c;	/* start of the codes array */
			free(c->vendor);
			c->vendor = NULL;
		}
		free(e->list);
		free(e->index_word);
		free(e);
	}
	free(base);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char query[32];
	FILE *fp;

	/* ethernetcode_init() exits on an empty file; that's by design */
	if (size == 0 || size > 65536)
		return (0);
	if (honeyd_rand == NULL && (honeyd_rand = rand_open()) == NULL)
		abort();

	if ((fp = fmemopen((void *)data, size, "r")) == NULL)
		return (0);
	ethernetcode_init(fp);		/* closes fp */

	/* Exercise the index with a fixed and an input-derived query */
	ethernetcode_find_prefix("cisco", 0);
	snprintf(query, sizeof(query), "%.*s", (int)(size < 31 ? size : 31),
	    (const char *)data);
	query[strcspn(query, "\n")] = '\0';
	ethernetcode_find_prefix(query, 1);
	free(ethernetcode_make_address(query));

	ethernet_reset();
	return (0);
}
