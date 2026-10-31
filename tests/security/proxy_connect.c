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

int
main(void)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	int sv[2], i;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	event_init();
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	proxy_connect(ta, "192.0.2.5", 80);
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
	kv_replace(&ta->dictionary, "$host", "192.0.2.5");
	kv_replace(&ta->dictionary, "$rawuri", "/");
	proxy_connect(ta, "192.0.2.5", 80);
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
