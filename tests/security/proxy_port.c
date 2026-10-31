/*
 * PM-SCR-108: the GET and CONNECT lookup callbacks passed the $port
 * dictionary value to atoi() without a NULL check, and took any number
 * atoi returned. A missing, empty, zero, non numeric or out of range
 * port must get an error reply and no upstream connection; ports 1 to
 * 65535 still connect.
 *
 * One process per case (argv[1], argv[2]) with a 10 s alarm. The lookup
 * result is passed to the callback directly and make_socket is wrapped
 * onto a local socketpair: no DNS, no network.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

void proxy_handle_get_cb(int, char, int, int, void *, void *);
void proxy_handle_connect_cb(int, char, int, int, void *, void *);

int debug = 0;

static int peer[2] = { -1, -1 };
static int nconnect, lastport;

int
__wrap_make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    int type, char *host, uint16_t port)
{
	nconnect++;
	lastport = port;
	socketpair(AF_UNIX, SOCK_STREAM, 0, peer);
	return (peer[0]);
}

int
main(int argc, char **argv)
{
	struct sockaddr_in sin;
	struct in_addr in;
	struct proxy_ta *ta;
	const char *path, *port;
	char buf[64];
	ssize_t r;
	int sv[2], i, want;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(10);
	if (argc < 3) {
		printf("FAIL: usage: get|connect port|none\n");
		return (1);
	}
	path = argv[1];
	port = strcmp(argv[2], "none") == 0 ? NULL :
	    strcmp(argv[2], "empty") == 0 ? "" : argv[2];
	want = argc > 3;	/* expect a connection on this port */

	event_init();
	evdns_init();
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$host", "192.0.2.5");
	kv_replace(&ta->dictionary, "$rawhost", "192.0.2.5");
	kv_replace(&ta->dictionary, "$rawuri", "/");
	if (port != NULL)
		kv_replace(&ta->dictionary, "$port", port);
	inet_pton(AF_INET, "192.0.2.5", &in);

	ta->dns_pending++;
	if (strcmp(path, "get") == 0)
		proxy_handle_get_cb(DNS_ERR_NONE, DNS_IPv4_A, 1, 60, &in, ta);
	else
		proxy_handle_connect_cb(DNS_ERR_NONE, DNS_IPv4_A, 1, 60,
		    &in, ta);
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);

	r = read(sv[1], buf, sizeof(buf) - 1);
	buf[r > 0 ? r : 0] = '\0';
	if (want) {
		int ok = nconnect == 1 && lastport == atoi(argv[3]);
		printf("%s: %s port %s connects to port %d\n",
		    ok ? "ok" : "FAIL", path, argv[2], lastport);
		return (!ok);
	}
	if (nconnect != 0 || strncmp(buf, "HTTP/1.0 ", 9) != 0 ||
	    strncmp(buf, "HTTP/1.0 200", 12) == 0) {
		printf("FAIL: %s port %s: %d connections, reply \"%.20s\"\n",
		    path, argv[2], nconnect, buf);
		return (1);
	}
	printf("ok: %s port %s refused with \"%.20s\"\n", path, argv[2],
	    buf);
	return (0);
}
