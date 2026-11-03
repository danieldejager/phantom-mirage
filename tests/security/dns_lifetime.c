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
static int fail_resolve;	/* make evdns_resolve_* fail synchronously */

static int
record(evdns_callback_type cb, void *arg)
{
	if (fail_resolve)
		return (-1);
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

/*
 * Review fix: evdns_resolve_* fails synchronously, so no callback will
 * ever run. Teardown must still free the transaction (LeakSanitizer).
 */
static int
syncfail_case(void)
{
	struct sockaddr_in sin;
	struct smtp_ta *sta;
	struct proxy_ta *ta;
	const char *in = "HELO a\r\n";
	int sv[2], bad = 0;

	fail_resolve = 1;
	setup(sv, &sin);
	sta = smtp_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0, 0);
	write(sv[1], in, strlen(in));
	event_loop(EVLOOP_ONCE);
	if (sta->dns_pending != 0)
		printf("FAIL smtp: dns_pending %d after failed lookup\n",
		    sta->dns_pending), bad = 1;
	smtp_errorcb(sta->bev, BEV_EVENT_EOF, sta);
	close(sv[1]);

	setup(sv, &sin);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$rawhost", "example.invalid");
	proxy_handle_get(ta);
	proxy_handle_connect(ta);
	if (ta->dns_pending != 0)
		printf("FAIL proxy: dns_pending %d after failed lookups\n",
		    ta->dns_pending), bad = 1;
	proxy_errorcb(ta->bev, BEV_EVENT_EOF, ta);
	close(sv[1]);
	fail_resolve = 0;
	printf("sync resolve failure: transactions freed\n");
	return (bad);
}

/*
 * Review fix: the deferred free path must stop I/O on remote_bev too,
 * not only on bev, while lookups are still in flight.
 */
static int
remote_case(void)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	int sv[2], rv[2], bad = 0;

	setup(sv, &sin);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	socketpair(AF_UNIX, SOCK_STREAM, 0, rv);
	ta->remote_fd = rv[0];
	ta->remote_bev = bufferevent_socket_new(NULL, rv[0], 0);
	bufferevent_enable(ta->remote_bev, EV_READ|EV_WRITE);
	kv_replace(&ta->dictionary, "$rawhost", "example.invalid");
	proxy_handle_get(ta);
	proxy_errorcb(ta->bev, BEV_EVENT_EOF, ta);
	if (bufferevent_get_enabled(ta->bev) != 0) {
		printf("FAIL: bev still enabled on deferred free\n");
		bad = 1;
	}
	if (bufferevent_get_enabled(ta->remote_bev) != 0) {
		printf("FAIL: remote_bev still enabled on deferred free\n");
		bad = 1;
	}
	answer(0);
	close(sv[1]);
	close(rv[1]);
	printf("deferred free: remote_bev checked\n");
	return (bad);
}

/*
 * R2 follow-up: evdns_resolve_* fails synchronously on a live
 * transaction. The client must get the same reply as for a failed
 * lookup (HELO reply, proxy bad domain), not silence.
 */
static int
reply_seen(int fd)
{
	char buf[512];
	ssize_t r;

	event_loop(EVLOOP_NONBLOCK);	/* flush the bufferevent */
	r = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
	return (r > 0);
}

static int
syncreply_case(void)
{
	struct sockaddr_in sin;
	struct smtp_ta *sta;
	struct proxy_ta *ta;
	const char *in = "HELO a\r\n";
	int sv[2], bad = 0, i;

	fail_resolve = 1;
	setup(sv, &sin);
	sta = smtp_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0, 0);
	reply_seen(sv[1]);		/* drop the greeting */
	write(sv[1], in, strlen(in));
	event_loop(EVLOOP_ONCE);
	i = reply_seen(sv[1]);
	printf("smtp HELO, resolver failed: %s\n", i ? "replied" : "no reply");
	bad |= !i;
	smtp_errorcb(sta->bev, BEV_EVENT_EOF, sta);
	close(sv[1]);

	for (i = 0; i < 2; i++) {
		int got;

		setup(sv, &sin);
		ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin,
		    sizeof(sin), NULL, 0);
		kv_replace(&ta->dictionary, "$rawhost", "example.invalid");
		if (i == 0)
			proxy_handle_get(ta);
		else
			proxy_handle_connect(ta);
		got = reply_seen(sv[1]);
		printf("proxy %s, resolver failed: %s\n",
		    i == 0 ? "GET" : "CONNECT", got ? "replied" : "no reply");
		bad |= !got;
		/* After the reply, wantclose has already freed ta */
		if (!got)
			proxy_errorcb(ta->bev, BEV_EVENT_EOF, ta);
		close(sv[1]);
	}
	fail_resolve = 0;
	return (bad);
}

/* Optional argument: smtp, get, connect, syncfail, syncreply or remote */
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
	if (only != NULL && strcmp(only, "syncfail") == 0)
		return (syncfail_case());
	if (only != NULL && strcmp(only, "syncreply") == 0)
		return (syncreply_case());
	if (only != NULL && strcmp(only, "remote") == 0)
		return (remote_case());
	return (0);
}
