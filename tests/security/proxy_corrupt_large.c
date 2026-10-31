/*
 * PM-SCR-105: data relayed for a request that is not on the allow list
 * must be corrupted whatever its size. proxy_corrupt() used to return
 * anything over 4096 bytes untouched. The test calls it directly for
 * 100 bytes, 4096, 4097, 8 KiB and 64 KiB, and relays an 8 KiB and a
 * 64 KiB client chunk, buffered whole, through proxy_readcb() on local
 * socketpairs.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <evdns.h>
#include <pcre.h>
#include "util.h"
#include "subsystems/proxy.h"

char *proxy_corrupt(char *, size_t);
void proxy_readcb(struct bufferevent *, void *);

int debug = 0;
static int bad;

static size_t
differ(const char *a, const char *b, size_t len)
{
	size_t i, n = 0;

	for (i = 0; i < len; i++)
		n += a[i] != b[i];
	return (n);
}

static void
direct(size_t len)
{
	char *data = malloc(len), *orig = malloc(len), *out;
	size_t i, n;

	for (i = 0; i < len; i++)
		data[i] = 'a' + i % 26;
	memcpy(orig, data, len);
	out = proxy_corrupt(data, len);
	n = differ(orig, out, len);
	printf("%s: %zu bytes, %zu corrupted\n", n > 0 ? "ok" : "FAIL",
	    len, n);
	if (n == 0)
		bad++;
	free(data);
	free(orig);
}

static void
relay(size_t len)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	int client[2], up[2], i, sz = 1 << 20;
	struct evbuffer *out;
	char *data = malloc(len), *got = calloc(1, len);
	size_t have = 0, n;
	ssize_t r;

	for (n = 0; n < len; n++)
		data[n] = 'a' + n % 26;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	socketpair(AF_UNIX, SOCK_STREAM, 0, client);
	socketpair(AF_UNIX, SOCK_STREAM, 0, up);
	fcntl(client[1], F_SETFL, O_NONBLOCK);
	setsockopt(up[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	setsockopt(up[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	fcntl(up[1], F_SETFL, O_NONBLOCK);
	ta = proxy_ta_new(client[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	ta->remote_fd = up[0];
	ta->remote_bev = bufferevent_new(up[0], NULL, NULL, NULL, ta);
	ta->justforward = 1;
	ta->corrupt = 1;

	/*
	 * A socket bufferevent freezes the end of its input buffer so
	 * only its own reads append to it. Lift that around the add so the
	 * whole chunk is buffered when the read callback runs, and fail
	 * loudly if the add did not land.
	 */
	evbuffer_unfreeze(EVBUFFER_INPUT(ta->bev), 0);
	r = evbuffer_add(EVBUFFER_INPUT(ta->bev), data, len);
	evbuffer_freeze(EVBUFFER_INPUT(ta->bev), 0);
	if (r != 0 || evbuffer_get_length(EVBUFFER_INPUT(ta->bev)) != len) {
		printf("FAIL: could not buffer %zu bytes\n", len);
		bad++;
		return;
	}
	proxy_readcb(ta->bev, ta);
	/*
	 * Drain what proxy_readcb queued for upstream without running
	 * the event loop, so the result does not depend on how the loop
	 * schedules the write. The receive buffer holds the whole chunk.
	 * The bufferevent freezes the start of its output buffer, so lift
	 * that around the drain as well.
	 */
	out = EVBUFFER_OUTPUT(ta->remote_bev);
	evbuffer_unfreeze(out, 1);
	for (i = 0; i < 1000 && evbuffer_get_length(out) > 0; i++)
		if (evbuffer_write(out, up[0]) <= 0)
			break;
	evbuffer_freeze(out, 1);
	for (i = 0; i < 1000 && have < len; i++) {
		r = read(up[1], got + have, len - have);
		if (r <= 0)
			break;
		have += r;
	}
	n = differ(data, got, have);
	printf("%s: relayed %zu of %zu bytes, %zu corrupted\n",
	    have == len && n > 0 ? "ok" : "FAIL", have, len, n);
	if (have != len || n == 0)
		bad++;
	proxy_ta_free(ta);
	close(client[1]);
	close(up[1]);
	free(data);
	free(got);
}

int
main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(10);
	event_init();
	evdns_init();
	if (argc > 1 && strcmp(argv[1], "relay") == 0) {
		relay(8192);
		relay(64 * 1024);
	} else {
		direct(100);
		direct(4096);
		direct(4097);
		direct(8192);
		direct(64 * 1024);
	}
	return (bad ? 1 : 0);
}
