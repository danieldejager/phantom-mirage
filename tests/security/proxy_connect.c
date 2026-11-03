/*
 * PM-SCR-107: the upstream connect event registered by proxy_connect()
 * must not outlive the proxy transaction, and the upstream socket must
 * be closed on every free path.
 *
 * make_socket is wrapped (-Wl,--wrap=make_socket) to return one end of a
 * local socketpair: no network.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <evdns.h>
#include <pcre.h>
#include "util.h"
#include "subsystems/proxy.h"

void proxy_connect(struct proxy_ta *, char *, int);
void proxy_errorcb(struct bufferevent *, short, void *);

int debug = 0;

static int peer[2] = { -1, -1 };

int
__wrap_make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    int type, char *host, uint16_t port)
{
	socketpair(AF_UNIX, SOCK_STREAM, 0, peer);
	return (peer[0]);
}

/*
 * The upstream end is a socketpair; report the address it stands for,
 * since the proxy checks the connected peer (PM-SCR-104).
 */
int __real_getpeername(int, struct sockaddr *, socklen_t *);

int
__wrap_getpeername(int fd, struct sockaddr *sa, socklen_t *len)
{
	struct sockaddr_in sin;

	if (fd != peer[0])
		return (__real_getpeername(fd, sa, len));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = htonl(0x64c80005);	/* 100.200.0.5 */
	if (*len > sizeof(sin))
		*len = sizeof(sin);
	memcpy(sa, &sin, *len);
	return (0);
}

/*
 * Review fix: a second request on the same client connection while the
 * first upstream connect is in flight must get an error response and a
 * clean close, not silence.
 */
static int
second_request(void)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	char buf[512];
	ssize_t r;
	size_t got = 0;
	int sv[2], i;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$host", "100.200.0.5");
	kv_replace(&ta->dictionary, "$rawuri", "/");
	proxy_connect(ta, "100.200.0.5", 80);	/* first request */
	proxy_connect(ta, "100.200.0.6", 80);	/* second, client still here */
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);

	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	while (got < sizeof(buf) - 1 &&
	    (r = read(sv[1], buf + got, sizeof(buf) - 1 - got)) > 0)
		got += r;
	buf[got] = '\0';
	if (strncmp(buf, "HTTP/1.0 400 ", 13) != 0) {
		printf("FAIL: no error response to second request\n");
		return (1);
	}
	if (read(sv[1], buf, 1) != 0) {
		printf("FAIL: client connection not closed\n");
		return (1);
	}
	if (fcntl(peer[0], F_GETFD) != -1) {
		printf("FAIL: upstream socket %d still open after close\n",
		    peer[0]);
		return (1);
	}
	printf("second request: error response and clean close\n");
	close(sv[1]);
	close(peer[1]);
	return (0);
}

void proxy_handle_get_cb(int, char, int, int, void *, void *);

/*
 * R2 follow-up: proxy_ta_free defers while a lookup is in flight. A
 * pending upstream connect must be canceled at that point, not left to
 * complete and send the request upstream for a client that is gone.
 */
static int
deferred_connect(void)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	char buf[64];
	int sv[2], i;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$host", "100.200.0.5");
	kv_replace(&ta->dictionary, "$port", "80");
	kv_replace(&ta->dictionary, "$rawuri", "/");
	proxy_connect(ta, "100.200.0.5", 80);
	ta->dns_pending = 1;		/* a lookup is still in flight */
	proxy_errorcb(NULL, BEV_EVENT_EOF, ta);	/* client goes away */
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);

	fcntl(peer[1], F_SETFL, O_NONBLOCK);
	if (read(peer[1], buf, sizeof(buf)) > 0) {
		printf("FAIL: request sent upstream after client left\n");
		return (1);
	}
	if (fcntl(peer[0], F_GETFD) != -1) {
		printf("FAIL: upstream socket still open at deferral\n");
		return (1);
	}
	/* The lookup completes: last reference frees the transaction */
	proxy_handle_get_cb(DNS_ERR_TIMEOUT, 0, 0, 0, NULL, ta);
	printf("deferred free: connect canceled, nothing sent upstream\n");
	close(sv[1]);
	close(peer[1]);
	return (0);
}

/* Optional argument "second" or "deferred" runs only that case */
int
main(int argc, char **argv)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	int sv[2], i;

	if (argc > 1 && strcmp(argv[1], "second") == 0) {
		event_init();
		return (second_request());
	}
	if (argc > 1 && strcmp(argv[1], "deferred") == 0) {
		event_init();
		return (deferred_connect());
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	event_init();
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	proxy_connect(ta, "100.200.0.5", 80);
	/* Client goes away before the upstream connect completes */
	proxy_errorcb(NULL, BEV_EVENT_EOF, ta);
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);
	printf("connect event after free: no use after free\n");

	if (peer[0] != -1 && fcntl(peer[0], F_GETFD) != -1) {
		printf("FAIL: upstream socket %d still open after free\n",
		    peer[0]);
		return (1);
	}
	printf("upstream socket closed on free\n");
	close(sv[1]);
	close(peer[1]);

	/* Upstream connect completes, then the client goes away */
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$host", "100.200.0.5");
	kv_replace(&ta->dictionary, "$rawuri", "/");
	proxy_connect(ta, "100.200.0.5", 80);
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);
	if (ta->remote_bev == NULL) {
		printf("FAIL: upstream connection not set up\n");
		return (1);
	}
	proxy_errorcb(NULL, BEV_EVENT_EOF, ta);
	if (fcntl(peer[0], F_GETFD) != -1) {
		printf("FAIL: upstream socket %d still open after free\n",
		    peer[0]);
		return (1);
	}
	printf("completed connect: freed cleanly\n");
	close(sv[1]);
	close(peer[1]);
	return (0);
}
