/*
 * PM-SCR-102: the SMTP and proxy line readers must drop a connection
 * that sends MAX_LINE bytes without an end of line, instead of buffering
 * without limit. Local socketpair only.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <pcre.h>
#include "util.h"
#include "subsystems/smtp.h"
#include "subsystems/proxy.h"

#ifndef MAX_LINE
#define MAX_LINE	4096
#endif

int debug = 0;

#define LIMIT	(8 << 20)	/* give up after 8 MiB */

static int
peer_closed(int fd)
{
	char buf[4096];
	ssize_t n;

	while ((n = read(fd, buf, sizeof(buf))) > 0)
		;
	return (n == 0);
}

static int
pump(int fd, size_t len, struct bufferevent **pbev)
{
	static char chunk[65536];
	size_t sent = 0;
	int i;

	memset(chunk, 'A', sizeof(chunk));
	while (sent < len) {
		size_t want = len - sent < sizeof(chunk) ?
		    len - sent : sizeof(chunk);
		ssize_t w = write(fd, chunk, want);
		if (w == -1 && errno == EPIPE)
			return (1);
		if (w > 0)
			sent += w;
		for (i = 0; i < 4; i++)
			event_loop(EVLOOP_NONBLOCK);
		if (peer_closed(fd))
			return (1);
	}
	return (0);
}

static int
run(const char *name, int is_proxy)
{
	struct sockaddr_in sin;
	struct bufferevent *bev;
	int sv[2], fail = 0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (1);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);

	if (is_proxy) {
		struct proxy_ta *ta = proxy_ta_new(sv[0],
		    (struct sockaddr *)&sin, sizeof(sin), NULL, 0);
		bev = ta->bev;
	} else {
		struct smtp_ta *ta = smtp_ta_new(sv[0],
		    (struct sockaddr *)&sin, sizeof(sin), NULL, 0, 0);
		bev = ta->bev;
	}

	/* A partial line below the cap must not close the connection */
	if (pump(sv[1], MAX_LINE - 100, &bev)) {
		printf("%s: FAIL closed below MAX_LINE\n", name);
		fail = 1;
	} else if (!pump(sv[1], LIMIT, &bev)) {
		printf("%s: FAIL still open after %d bytes without a newline,"
		    " holding %zu bytes\n", name, LIMIT,
		    evbuffer_get_length(EVBUFFER_INPUT(bev)));
		fail = 1;
	} else {
		printf("%s: connection closed after an overlong line\n", name);
	}
	close(sv[1]);
	return (fail);
}

int
main(void)
{
	int fail = 0;

	signal(SIGPIPE, SIG_IGN);
	event_init();
	fail |= run("smtp", 0);
	fail |= run("proxy", 1);
	return (fail);
}
