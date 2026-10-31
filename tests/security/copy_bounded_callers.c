/*
 * PM-SCR-101 follow-up: smtp_response and proxy_response return NULL
 * when an expanded template does not fit their line buffer, and the
 * callers must not then write a partial template or dereference NULL.
 * An over long reply must be replaced by a fixed error and a close.
 *
 * Cases:
 *  ehlo_fit   an EHLO name that expands to exactly 1023 bytes: normal 250
 *  ehlo_long  one byte more: fixed 421 reply, then the connection closes
 *  proxy_long a $host that overflows the 404 template: fixed 500, close
 *  greet_ok   a normal greeting on a direct SMTP connection: 220
 *  greet_long a $hostname too long for the greeting: fixed 421, close
 *  connect_long CONNECT to port 25 where the greeting does not fit:
 *             the new SMTP session is freed, fixed 500, close
 *
 * Socketpairs only; evdns is stubbed so nothing touches the network.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <evdns.h>
#include <pcre.h>
#include "util.h"
#include "subsystems/smtp.h"
#include "subsystems/proxy.h"

void proxy_handle_get_cb(int, char, int, int, void *, void *);
void proxy_handle_connect_cb(int, char, int, int, void *, void *);

/* Linked with --wrap=smtp_ta_new to reach the CONNECT session */
struct smtp_ta *__real_smtp_ta_new(int, struct sockaddr *, socklen_t,
    struct sockaddr *, socklen_t, int);
static char *long_hostname;

int debug = 0;

int
evdns_resolve_reverse(const struct in_addr *in, int flags,
    evdns_callback_type cb, void *arg)
{
	return (-1);
}

int
evdns_resolve_ipv4(const char *name, int flags,
    evdns_callback_type cb, void *arg)
{
	return (-1);
}

static char reply[16384];

struct smtp_ta *
__wrap_smtp_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen, int greeting)
{
	struct smtp_ta *ta;

	ta = __real_smtp_ta_new(fd, sa, salen, lsa, lsalen, greeting);
	if (ta != NULL && long_hostname != NULL)
		kv_replace(&ta->dictionary, "$hostname", long_hostname);
	return (ta);
}

/* Runs the loop until the peer has written and gone quiet */
static size_t
collect(int fd, int *closed)
{
	size_t len = 0;
	ssize_t r;
	int i;

	*closed = 0;
	fcntl(fd, F_SETFL, O_NONBLOCK);
	for (i = 0; i < 20; i++) {
		event_loop(EVLOOP_NONBLOCK);
		while ((r = read(fd, reply + len,
			    sizeof(reply) - 1 - len)) > 0)
			len += r;
		if (r == 0) {
			*closed = 1;
			break;
		}
		usleep(2000);
	}
	reply[len] = '\0';
	return (len);
}

static void
peer(struct sockaddr_in *sin, int sv[2])
{
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0x7f000001);
}

/* Sends EHLO with a name of n bytes, returns the reply length */
static size_t
ehlo(size_t n, int *closed)
{
	struct sockaddr_in sin;
	struct smtp_ta *ta;
	char *line;
	size_t len;
	int sv[2];

	peer(&sin, sv);
	ta = smtp_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0, 0);
	ta->mailer_id = "sendmail";	/* its EHLO reply echoes $srcname */
	line = malloc(n + 8);
	memcpy(line, "EHLO ", 5);
	memset(line + 5, 'h', n);
	memcpy(line + 5 + n, "\r\n", 3);
	write(sv[1], line, strlen(line));
	free(line);
	len = collect(sv[1], closed);
	if (!*closed) {
		/* let the daemon side tear down, keep the reply */
		char keep[sizeof(reply)];
		int dummy;

		memcpy(keep, reply, len + 1);
		shutdown(sv[1], SHUT_WR);
		collect(sv[1], &dummy);
		memcpy(reply, keep, len + 1);
	}
	close(sv[1]);
	return (len);
}

static int
smtp_cases(void)
{
	size_t base, fit, len;
	int closed, bad = 0;

	base = ehlo(1, &closed);	/* reply with a one byte name */
	fit = 1023 - (base - 1);	/* name making the reply 1023 bytes */

	len = ehlo(fit, &closed);
	printf("ehlo_fit: name %zu reply %zu bytes, starts \"%.4s\", "
	    "closed %d\n", fit, len, reply, closed);
	if (len != 1023 || strncmp(reply, "250", 3) != 0 || closed)
		printf("FAIL ehlo_fit\n"), bad = 1;

	len = ehlo(fit + 1, &closed);
	printf("ehlo_long: name %zu reply %zu bytes, starts \"%.40s\", "
	    "closed %d, template text %s\n", fit + 1, len, reply, closed,
	    strchr(reply, '$') ? "LEAKED" : "absent");
	if (strncmp(reply, "421 ", 4) != 0 || strchr(reply, '$') ||
	    !closed)
		printf("FAIL ehlo_long\n"), bad = 1;
	return (bad);
}

static int
proxy_case(void)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	char *host;
	size_t len;
	int sv[2], closed, bad = 0;

	peer(&sin, sv);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	host = malloc(1201);
	memset(host, 'd', 1200);
	host[1200] = '\0';
	kv_replace(&ta->dictionary, "$host", host);
	kv_replace(&ta->dictionary, "$port", "80");
	free(host);
	ta->dns_pending = 1;
	proxy_handle_get_cb(DNS_ERR_TIMEOUT, 0, 0, 0, NULL, ta);
	len = collect(sv[1], &closed);
	printf("proxy_long: reply %zu bytes, starts \"%.32s\", closed %d, "
	    "template text %s\n", len, reply, closed,
	    strchr(reply, '$') ? "LEAKED" : "absent");
	if (strncmp(reply, "HTTP/1.0 500 ", 13) != 0 || strchr(reply, '$') ||
	    !closed)
		printf("FAIL proxy_long\n"), bad = 1;
	close(sv[1]);
	return (bad);
}

/* Greets a direct SMTP connection whose $hostname is n bytes (0: as is) */
static size_t
greet(size_t n, int *closed)
{
	struct sockaddr_in sin;
	struct smtp_ta *ta;
	size_t len;
	int sv[2];

	peer(&sin, sv);
	ta = smtp_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0, 0);
	if (n > 0) {
		char *name = malloc(n + 1);

		memset(name, 'g', n);
		name[n] = '\0';
		kv_replace(&ta->dictionary, "$hostname", name);
		free(name);
	}
	smtp_greeting(ta);
	len = collect(sv[1], closed);
	if (!*closed) {
		char keep[sizeof(reply)];
		int dummy;

		memcpy(keep, reply, len + 1);
		shutdown(sv[1], SHUT_WR);
		collect(sv[1], &dummy);
		memcpy(reply, keep, len + 1);
	}
	close(sv[1]);
	return (len);
}

static int
greet_cases(void)
{
	size_t len;
	int closed, bad = 0;

	len = greet(0, &closed);
	printf("greet_ok: reply %zu bytes, starts \"%.4s\", closed %d\n",
	    len, reply, closed);
	if (strncmp(reply, "220 ", 4) != 0 || closed)
		printf("FAIL greet_ok\n"), bad = 1;

	len = greet(1100, &closed);
	printf("greet_long: hostname 1100 reply %zu bytes, starts \"%.40s\", "
	    "closed %d, template text %s\n", len, reply, closed,
	    strchr(reply, '$') ? "LEAKED" : "absent");
	if (strncmp(reply, "421 ", 4) != 0 || strchr(reply, '$') ||
	    !closed)
		printf("FAIL greet_long\n"), bad = 1;
	return (bad);
}

static int
connect_case(void)
{
	struct sockaddr_in sin;
	struct proxy_ta *ta;
	struct in_addr addr;
	size_t len;
	int sv[2], closed, bad = 0;

	peer(&sin, sv);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    NULL, 0);
	kv_replace(&ta->dictionary, "$host", "192.0.2.25");
	kv_replace(&ta->dictionary, "$port", "25");
	long_hostname = malloc(1101);
	memset(long_hostname, 'g', 1100);
	long_hostname[1100] = '\0';
	addr.s_addr = htonl(0xc0000219);
	ta->dns_pending = 1;
	proxy_handle_connect_cb(DNS_ERR_NONE, DNS_IPv4_A, 1, 0, &addr, ta);
	free(long_hostname);
	long_hostname = NULL;
	len = collect(sv[1], &closed);
	printf("connect_long: reply %zu bytes, starts \"%.32s\", closed %d, "
	    "template text %s\n", len, reply, closed,
	    strchr(reply, '$') ? "LEAKED" : "absent");
	if (strncmp(reply, "HTTP/1.0 500 ", 13) != 0 ||
	    strstr(reply, "220 ") || strchr(reply, '$') || !closed)
		printf("FAIL connect_long\n"), bad = 1;
	if (!closed) {
		/* let any surviving session see EOF and tear down */
		int dummy;

		shutdown(sv[1], SHUT_WR);
		collect(sv[1], &dummy);
	}
	close(sv[1]);
	return (bad);
}

int
main(void)
{
	int bad = 0;

	event_init();
	bad |= smtp_cases();
	bad |= proxy_case();
	bad |= greet_cases();
	bad |= connect_case();
	if (bad)
		printf("FAIL\n");
	return (bad);
}
