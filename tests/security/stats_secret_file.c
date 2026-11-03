/*
 * PM-SCR-028: the stats collector password could only be given on the
 * command line (-c host:port:name:password), where any local user can
 * read it from the process list.
 *
 * This runs the real option handling in main() of the daemon (honeyd.c)
 * or, built with -DHSNIFF, of the sniffer (hsniff.c) with the arguments
 * given to the harness. stats_init_collect() is wrapped (-Wl,--wrap)
 * to stop the run right after the stats setup: it reports the user
 * name, whether the password equals $STATS_EXPECT, and whether
 * $STATS_EXPECT can still be read from /proc/self/cmdline, never the
 * password itself, and exits. Nothing is sent anywhere.
 *
 * lstat() is wrapped too: for the path in $STATS_FAKE_REG it reports a
 * FIFO as a 0600 regular file, as if a FIFO had been swapped in right
 * after the check. The open must then not block.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dnet.h>

#ifdef HSNIFF
int hsniff_main(int, char **);
#define TARGET_MAIN	hsniff_main
#else
int honeyd_main(int, char **);
#define TARGET_MAIN	honeyd_main
#endif

int __real_lstat(const char *, struct stat *);

int
__wrap_lstat(const char *path, struct stat *st)
{
	const char *fake = getenv("STATS_FAKE_REG");
	int rc = __real_lstat(path, st);

	if (rc == 0 && fake != NULL && strcmp(path, fake) == 0 &&
	    S_ISFIFO(st->st_mode))
		st->st_mode = S_IFREG | 0600;
	return (rc);
}

/* 1 when s is in the NUL separated argv area of /proc/self/cmdline */
static int
cmdline_has(const char *s)
{
	char buf[65536];
	size_t n = 0, i, l = strlen(s);
	ssize_t r;
	int fd;

	if ((fd = open("/proc/self/cmdline", O_RDONLY)) == -1)
		return (-1);
	while (n < sizeof(buf) &&
	    (r = read(fd, buf + n, sizeof(buf) - n)) > 0)
		n += r;
	close(fd);
	for (i = 0; l > 0 && i + l <= n; i++)
		if (memcmp(buf + i, s, l) == 0)
			return (1);
	return (0);
}

void
__wrap_stats_init_collect(struct addr *dst, u_short port, char *name,
    char *password)
{
	const char *expect = getenv("STATS_EXPECT");
	int c = expect != NULL ? cmdline_has(expect) : -1;

	printf("collector user %s, password %s, cmdline %s\n", name,
	    expect != NULL && password != NULL && strcmp(password, expect) == 0 ?
	    "matches" : "differs",
	    c == 0 ? "clean" : c == 1 ? "shows password" : "unreadable");
	fflush(stdout);
	_exit(0);
}

#ifdef HSNIFF
/* No capture device is opened: stop the sniffer from touching one */
void __wrap_interface_initialize(void *cb) { }
void __wrap_interface_prevent_init(void) { }
#endif

int
main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	return (TARGET_MAIN(argc, argv));
}
