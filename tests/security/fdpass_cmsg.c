/*
 * PM-SCR-014, fdpass.c: receive_fd() read cmsg_type from CMSG_FIRSTHDR()
 * without checking for NULL, so a peer that sent data without control
 * data crashed the daemon. A message carrying more than one descriptor
 * was also accepted and the extra descriptors leaked.
 *
 * Local socketpairs only.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "fdpass.h"

static int failed;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		failed = 1;
}

static int
open_fds(void)
{
	int fd, n = 0;

	for (fd = 0; fd < 256; fd++)
		if (fcntl(fd, F_GETFD) != -1)
			n++;
	return (n);
}

/* Send one byte with n descriptors attached (n may be 0) */
static void
send_raw(int s, int *fds, int n)
{
	char buf[CMSG_SPACE(4 * sizeof(int))];
	struct msghdr msg;
	struct iovec vec;
	struct cmsghdr *cmsg;
	char ch = 0;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, sizeof(buf));
	vec.iov_base = &ch;
	vec.iov_len = 1;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	if (n > 0) {
		msg.msg_control = buf;
		msg.msg_controllen = CMSG_SPACE(n * sizeof(int));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(n * sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), fds, n * sizeof(int));
	}
	if (sendmsg(s, &msg, 0) != 1)
		abort();
}

int
main(void)
{
	int sv[2], p[2], fds[2], fd, base;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1 || pipe(p) == -1)
		abort();

	/* Data without control data */
	send_raw(sv[1], NULL, 0);
	fd = receive_fd(sv[0], NULL, NULL);
	check(fd == -1 && errno == EBADMSG, "no control data rejected");

	/* Two descriptors in one message: rejected, nothing leaks */
	base = open_fds();
	fds[0] = p[0];
	fds[1] = p[1];
	send_raw(sv[1], fds, 2);
	fd = receive_fd(sv[0], NULL, NULL);
	check(fd == -1, "two descriptors rejected");
	check(open_fds() == base, "no descriptor leaked");

	/* A well formed message still works */
	if (send_fd(sv[1], p[0], NULL, 0) == -1)
		abort();
	fd = receive_fd(sv[0], NULL, NULL);
	check(fd >= 0, "single descriptor received");
	if (fd >= 0)
		close(fd);

	close(sv[0]);
	close(sv[1]);
	close(p[0]);
	close(p[1]);
	return (failed);
}
