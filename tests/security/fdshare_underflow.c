/*
 * PM-SCR-200, util.c fdshare_close: the share count had no guard, so one
 * close too many drove it below zero. The next fdshare_dup of a new
 * descriptor with the same number then counted from -1, and its last
 * fdshare_close never closed it.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int fdshare_dup(int);
int fdshare_close(int);
int fdshare_inspect(int);

static int
is_open(int fd)
{
	return (fcntl(fd, F_GETFD) != -1 || errno != EBADF);
}

int
main(void)
{
	int sv[2], fd, fd2, bad = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (1);
	fd = sv[0];
	fdshare_dup(fd);
	fdshare_close(fd);		/* count 1 to 0: closed */
	fdshare_close(fd);		/* one too many */
	printf("count after the extra close: %d\n", fdshare_inspect(fd));
	if (fdshare_inspect(fd) != 0)
		printf("FAIL: count went below zero\n"), bad = 1;

	/* A new descriptor that reuses the number is shared normally */
	fd2 = dup(sv[1]);
	if (fd2 != fd) {
		printf("FAIL: setup, fd %d not reused (%d)\n", fd, fd2);
		return (1);
	}
	fdshare_dup(fd2);
	fdshare_close(fd2);
	if (is_open(fd2)) {
		printf("FAIL: reused fd %d left open by its last close\n", fd2);
		close(fd2);
		bad = 1;
	} else
		printf("ok: reused fd closed exactly once\n");
	close(sv[1]);
	return (bad);
}
