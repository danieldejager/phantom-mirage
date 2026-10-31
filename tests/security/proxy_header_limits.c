/*
 * PM-SCR-102 follow-up: one proxy request may carry at most
 * PROXY_MAX_HEADER_LINES header lines and PROXY_MAX_HEADER_BYTES header
 * bytes. Past either limit the client gets the 400 reply and the
 * connection is closed; a request at both limits is still handled.
 *
 * The request line is taken as matched by setting empty_cb, as
 * proxy_handle() does for a GET, because the pcre stub matches nothing.
 * Local socketpair only.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <pcre.h>
#include "util.h"
#include "subsystems/proxy.h"

int debug = 0;

#ifndef PROXY_MAX_HEADER_LINES
#define PROXY_MAX_HEADER_LINES	100
#define PROXY_MAX_HEADER_BYTES	(64 * 1024)
#endif

static int handled;
static int nheaders;

static int
fake_get(struct proxy_ta *ta)
{
	struct keyvalue *kv;

	handled = 1;
	nheaders = 0;
	TAILQ_FOREACH(kv, &ta->dictionary, next)
		if (strcmp(kv->key, "data") == 0)
			nheaders++;
	return (0);
}

/* Write all of buf while running the event loop; stop early on EPIPE */
static void
pump(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	int i;

	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);
		if (w == -1 && (errno == EPIPE || errno == ECONNRESET))
			break;
		if (w > 0)
			off += w;
		for (i = 0; i < 4; i++)
			event_loop(EVLOOP_NONBLOCK);
	}
	for (i = 0; i < 8; i++)
		event_loop(EVLOOP_NONBLOCK);
}

/* Read what the proxy sent; *closed is set when it closed the socket */
static size_t
drain(int fd, char *buf, size_t size, int *closed)
{
	size_t got = 0;
	ssize_t r;

	*closed = 0;
	for (;;) {
		r = read(fd, buf + got, size - 1 - got);
		if (r > 0) {
			got += r;
			if (got == size - 1)
				break;
			continue;
		}
		/* Unread input at close makes AF_UNIX report a reset */
		if (r == 0 || (r == -1 && errno == ECONNRESET))
			*closed = 1;
		break;
	}
	buf[got] = '\0';
	return (got);
}

/*
 * Send nlines header lines totalling nbytes bytes (CRLF included), then
 * an empty line when final is set. Returns 0 when the outcome matches
 * want_reject.
 */
static int
run(const char *name, int nlines, size_t nbytes, int discard, int want_reject)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	char reply[512], *req, *p;
	size_t len, each, extra;
	int sv[2], i, closed;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (1);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	handled = 0;
	if (discard)
		ta->wantclose = 1;	/* reply queued, lines are discarded */
	else
		ta->empty_cb = fake_get;	/* request line was a GET */

	len = nbytes + 2;
	req = p = malloc(len + 1);
	each = nbytes / nlines;
	extra = nbytes - each * nlines;
	for (i = 0; i < nlines; i++) {
		size_t l = each + (i == nlines - 1 ? extra : 0);
		memset(p, 'a', l - 2);
		memcpy(p, "X-H:", 4);
		p[l - 2] = '\r';
		p[l - 1] = '\n';
		p += l;
	}
	memcpy(p, "\r\n", 2);
	pump(sv[1], req, len);
	free(req);

	drain(sv[1], reply, sizeof(reply), &closed);
	if (want_reject) {
		if (!discard && strncmp(reply, "HTTP/1.0 400 ", 13) != 0) {
			printf("%s: FAIL no 400 reply\n", name);
			return (1);
		}
		if (!closed) {
			printf("%s: FAIL connection not closed\n", name);
			return (1);
		}
		if (handled) {
			printf("%s: FAIL request handled\n", name);
			return (1);
		}
		printf("%s: %s and close\n", name,
		    discard ? "discarded" : "400");
	} else {
		if (!handled || nheaders != nlines || closed ||
		    reply[0] != '\0') {
			printf("%s: FAIL handled %d headers %d closed %d\n",
			    name, handled, nheaders, closed);
			return (1);
		}
		printf("%s: handled with %d headers\n", name, nheaders);
		proxy_ta_free(ta);
	}
	close(sv[1]);
	return (0);
}

int
main(void)
{
	int fail = 0;
	int L = PROXY_MAX_HEADER_LINES;
	size_t B = PROXY_MAX_HEADER_BYTES;

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGPIPE, SIG_IGN);
	event_init();
	fail |= run("lines at limit, bytes at limit", L, B, 0, 0);
	fail |= run("lines over limit", L + 1, (L + 1) * 40, 0, 1);
	fail |= run("bytes over limit", 20, B + 1, 0, 1);
	fail |= run("discarded lines over limit", 4 * L, 4 * L * 40, 1, 1);
	fail |= run("discarded bytes over limit", 40, 2 * B, 1, 1);
	return (fail);
}
