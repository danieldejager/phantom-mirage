/*
 * PM-SCR-127: record_add_hash() allocated a hash entry for every
 * payload chunk and only linked it into the list when the digest was
 * new. A repeated chunk leaked its entry.
 *
 * The same chunk is added many times; after record_remove_hashes() the
 * heap must be back where it started. ASan's allocator statistics give
 * the live heap size, so no leak report at exit is needed.
 */
#include <sys/types.h>
#include <sys/param.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include <sanitizer/allocator_interface.h>
#include "honeyd.h"
#include "stats.h"

#define NADD	1000

int
main(void)
{
	struct hashq hashes;
	struct hash *h;
	char chunk[64];
	size_t before, after;
	int i, n = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	memset(chunk, 'a', sizeof(chunk));
	TAILQ_INIT(&hashes);

	before = __sanitizer_get_current_allocated_bytes();
	for (i = 0; i < NADD; i++)
		record_add_hash(&hashes, chunk, sizeof(chunk));
	TAILQ_FOREACH(h, &hashes, next)
		n++;
	record_remove_hashes(&hashes);
	after = __sanitizer_get_current_allocated_bytes();

	printf("same chunk added %d times: %d in list, %zu bytes left over\n",
	    NADD, n, after - before);
	if (n != 1 || after != before) {
		printf("FAIL\n");
		return (1);
	}
	printf("PASS: stats_hash_dup\n");
	return (0);
}
