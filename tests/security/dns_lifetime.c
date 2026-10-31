/*
 * PM-SCR-103: an evdns callback must not run on a freed SMTP or proxy
 * transaction. Two lookups are in flight, the first answers, the client
 * goes away, then the second answers.
 *
 * evdns_resolve_reverse and evdns_resolve_ipv4 are replaced by recorders
 * and the callbacks are fired by hand: no resolver, no network.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <evdns.h>
#include <pcre.h>
#include "util.h"
#include "subsystems/smtp.h"
#include "subsystems/proxy.h"

void smtp_errorcb(struct bufferevent *, short, void *);
void proxy_errorcb(struct bufferevent *, short, void *);
int proxy_handle_get(struct proxy_ta *);
int proxy_handle_connect(struct proxy_ta *);

int debug = 0;

static evdns_callback_type cbs[8];
static void *args[8];
static int n;

static int
record(evdns_callback_type cb, void *arg)
{
	cbs[n] = cb;
	args[n] = arg;
	n++;
	return (0);
}

int
evdns_resolve_reverse(const struct in_addr *in, int flags,
    evdns_callback_type cb, void *arg)
{
	return (record(cb, arg));
}

int
evdns_resolve_ipv4(const char *name, int flags,
    evdns_callback_type cb, void *arg)
{
	return (record(cb, arg));
}

static void
answer(int i)
{
	cbs[i](DNS_ERR_TIMEOUT, 0, 0, 0, NULL, args[i]);
}

static void
setup(int sv[2], struct sockaddr_in *sin)
{
	n = 0;
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0x7f000001);
}

static void
smtp_case(void)
{
	struct sockaddr_in sin;
	struct smtp_ta *ta;
	const char *in = "HELO a\r\nHELO b\r\n";
	int sv[2];

	setup(sv, &sin);
	ta = smtp_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0, 0);
	write(sv[1], in, strlen(in));
	event_loop(EVLOOP_ONCE);	/* smtp_readcb issues two lookups */
	if (n != 2)
		printf("smtp: expected 2 lookups, got %d\n", n);
	answer(0);
	smtp_errorcb(ta->bev, BEV_EVENT_EOF, ta);
	answer(1);
	close(sv[1]);
	printf("smtp HELO: second answer after close handled\n");
}

static void
proxy_case(const char *name, int (*handle)(struct proxy_ta *))
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	int sv[2];

	setup(sv, &sin);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$rawhost", "example.invalid");
	handle(ta);
	handle(ta);
	answer(0);
	proxy_errorcb(ta->bev, BEV_EVENT_EOF, ta);
	answer(1);
	close(sv[1]);
	printf("proxy %s: second answer after close handled\n", name);
}

/* Optional argument: smtp, get or connect to run one case */
int
main(int argc, char **argv)
{
	const char *only = argc > 1 ? argv[1] : NULL;

	event_init();
	if (only == NULL || strcmp(only, "smtp") == 0)
		smtp_case();
	if (only == NULL || strcmp(only, "get") == 0)
		proxy_case("GET", proxy_handle_get);
	if (only == NULL || strcmp(only, "connect") == 0)
		proxy_case("CONNECT", proxy_handle_connect);
	return (0);
}
