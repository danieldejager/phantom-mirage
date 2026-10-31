/*
 * PM-SCR-028: the stats collector password could only be given on the
 * command line (-c host:port:name:password), where any local user can
 * read it from the process list.
 *
 * This runs the real option handling in honeyd.c main() with the
 * arguments given to the harness. stats_init_collect() is wrapped
 * (-Wl,--wrap) to stop the run right after the stats setup: it reports
 * the user name and whether the password equals $STATS_EXPECT, never
 * the password itself, and exits. Nothing is sent anywhere.
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dnet.h>

int honeyd_main(int, char **);

void
__wrap_stats_init_collect(struct addr *dst, u_short port, char *name,
    char *password)
{
	const char *expect = getenv("STATS_EXPECT");

	printf("collector user %s, password %s\n", name,
	    expect != NULL && password != NULL && strcmp(password, expect) == 0 ?
	    "matches" : "differs");
	fflush(stdout);
	_exit(0);
}

int
main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	return (honeyd_main(argc, argv));
}
