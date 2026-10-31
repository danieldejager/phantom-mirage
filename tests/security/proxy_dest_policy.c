/*
 * PM-SCR-104: the proxy destination filter must judge the resolved
 * numeric address against the special purpose ranges, IPv4 and IPv6,
 * with IPv4 mapped and IPv4 compatible IPv6 judged by the embedded
 * IPv4 address. It must also refuse the host's own interface
 * addresses, the subsystem's own decoy address and operator named
 * decoy ranges, allow an operator named range only when one is
 * configured, and check the connected peer again before relaying.
 *
 * One process per group (argv[1]) with a 10 s alarm. make_socket and
 * getpeername are wrapped onto a local socketpair: no network.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
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

int proxy_allowed_network(const char *);
void proxy_connect(struct proxy_ta *, char *, int);
int proxy_allow_range(const char *) __attribute__((weak));
int proxy_decoy_range(const char *) __attribute__((weak));

int debug = 0;

static int peer[2] = { -1, -1 };
static int nconnect;
static const char *fake_peer;	/* address getpeername reports */

int
__wrap_make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    int type, char *host, uint16_t port)
{
	nconnect++;
	socketpair(AF_UNIX, SOCK_STREAM, 0, peer);
	return (peer[0]);
}

int
__wrap_make_bound_connect(int type, char *host, uint16_t port, char *local)
{
	return (__wrap_make_socket(NULL, type, host, port));
}

int __real_getpeername(int, struct sockaddr *, socklen_t *);

int
__wrap_getpeername(int fd, struct sockaddr *sa, socklen_t *len)
{
	struct sockaddr_in sin;

	if (fake_peer == NULL || fd != peer[0])
		return (__real_getpeername(fd, sa, len));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	inet_pton(AF_INET, fake_peer, &sin.sin_addr);
	if (*len > sizeof(sin))
		*len = sizeof(sin);
	memcpy(sa, &sin, *len);
	return (0);
}

static int bad;

static void
expect(const char *addr, int allowed)
{
	int got = proxy_allowed_network(addr);

	printf("%s: %-28s %s\n", got == allowed ? "ok" : "FAIL", addr,
	    allowed ? "allowed" : "denied");
	if (got != allowed)
		bad++;
}

static const char *v4_denied[] = {
	"0.0.0.0", "0.255.255.255",			/* 0/8 */
	"10.0.0.1", "10.255.255.254",			/* 10/8 */
	"100.64.0.1", "100.127.255.254",		/* CGNAT */
	"127.0.0.1", "127.255.255.254",			/* loopback */
	"169.254.169.254", "169.254.0.1",		/* link local */
	"172.16.0.1", "172.31.255.254",			/* 172.16/12 */
	"192.0.0.1", "192.0.0.170",			/* 192.0.0/24 */
	"192.168.0.1", "192.168.255.254",		/* 192.168/16 */
	"198.18.0.1", "198.19.255.254",			/* benchmarking */
	"224.0.0.1", "239.255.255.250",			/* multicast */
	"240.0.0.1", "254.255.255.254",			/* 240/4 */
	"255.255.255.255",				/* broadcast */
	NULL
};

static const char *v4_edges_allowed[] = {
	"1.0.0.1", "9.255.255.255", "11.0.0.0", "100.63.255.255",
	"100.128.0.0", "126.255.255.255", "128.0.0.0", "169.253.255.255",
	"169.255.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.0",
	"192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0",
	"223.255.255.255", NULL
};

static const char *v6_denied[] = {
	"::", "::1",
	"fe80::1", "febf:ffff::1",			/* fe80::/10 */
	"fc00::1", "fd12:3456::1",			/* fc00::/7 */
	"ff02::1", "ff05::1:3",				/* ff00::/8 */
	NULL
};

static const char *mapped_denied[] = {
	"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.1.2.3",
	"::ffff:100.64.0.1", "::ffff:192.168.1.1", "::ffff:0.0.0.0",
	"::ffff:224.0.0.1", "::ffff:255.255.255.255", "::ffff:7f00:1",
	"::127.0.0.1", "::169.254.169.254", "::10.0.0.1", "::100.64.0.1",
	"::a9fe:a9fe",
	NULL
};

static void
table(const char **t, int allowed)
{
	for (; *t != NULL; t++)
		expect(*t, allowed);
}

static int
own_interface(void)
{
	struct ifaddrs *ifa, *i;
	char buf[INET6_ADDRSTRLEN];
	int n = 0;

	if (getifaddrs(&ifa) == -1)
		return (1);
	for (i = ifa; i != NULL; i = i->ifa_next) {
		if (i->ifa_addr == NULL)
			continue;
		if (i->ifa_addr->sa_family == AF_INET)
			inet_ntop(AF_INET, &((struct sockaddr_in *)
			    i->ifa_addr)->sin_addr, buf, sizeof(buf));
		else if (i->ifa_addr->sa_family == AF_INET6)
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)
			    i->ifa_addr)->sin6_addr, buf, sizeof(buf));
		else
			continue;
		expect(buf, 0);
		n++;
	}
	freeifaddrs(ifa);
	printf("%d interface addresses checked\n", n);
	return (n == 0);
}

static struct proxy_ta *
new_ta(const char *local)
{
	struct sockaddr_in sin, lsin;
	struct proxy_ta *ta;
	int sv[2];

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	lsin = sin;
	if (local != NULL)
		inet_pton(AF_INET, local, &lsin.sin_addr);
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	fcntl(sv[1], F_SETFL, O_NONBLOCK);
	ta = proxy_ta_new(sv[0], (struct sockaddr *)&sin, sizeof(sin),
	    local != NULL ? (struct sockaddr *)&lsin : NULL,
	    local != NULL ? sizeof(lsin) : 0);
	kv_replace(&ta->dictionary, "$rawuri", "/");
	kv_replace(&ta->dictionary, "$host", "x");
	kv_replace(&ta->dictionary, "$rawhost", "x");
	return (ta);
}

/* The connected peer is checked again before anything is relayed */
static int
recheck(void)
{
	struct proxy_ta *ta;
	char buf[64];
	int i, upstream_got;

	fake_peer = "169.254.169.254";
	ta = new_ta(NULL);
	proxy_connect(ta, "192.0.2.5", 80);
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);
	fcntl(peer[1], F_SETFL, O_NONBLOCK);
	upstream_got = read(peer[1], buf, sizeof(buf)) > 0;
	printf("%s: connected peer 169.254.169.254 gets no request\n",
	    upstream_got ? "FAIL" : "ok");
	return (upstream_got);
}

/* The subsystem's own decoy address and named decoy ranges */
static int
decoy(void)
{
	struct proxy_ta *ta;
	int i;

	if (proxy_decoy_range == NULL) {
		printf("FAIL: no decoy range option\n");
		return (1);
	}
	if (proxy_decoy_range("198.51.100.0/24") != 0 ||
	    proxy_decoy_range("2001:db8:1::/48") != 0 ||
	    proxy_decoy_range("bogus") != -1 ||
	    proxy_decoy_range("10.0.0.0/33") != -1) {
		printf("FAIL: decoy range parsing\n");
		return (1);
	}
	expect("198.51.100.20", 0);
	expect("::ffff:198.51.100.20", 0);
	expect("2001:db8:1::5", 0);
	expect("198.51.101.20", 1);
	expect("2001:db8:2::5", 1);

	ta = new_ta("192.0.2.7");
	proxy_connect(ta, "192.0.2.7", 80);
	for (i = 0; i < 4; i++)
		event_loop(EVLOOP_NONBLOCK);
	printf("%s: own decoy address 192.0.2.7 not connected\n",
	    nconnect ? "FAIL" : "ok");
	return (nconnect != 0);
}

static int
override(void)
{
	/* Default off: nothing in the deny list is reachable */
	expect("10.1.2.3", 0);
	if (proxy_allow_range == NULL) {
		printf("FAIL: no allow range option\n");
		return (1);
	}
	if (proxy_allow_range("10.1.0.0/16") != 0 ||
	    proxy_allow_range("fd00:1::/32") != 0 ||
	    proxy_allow_range("1.2.3.4/") != -1) {
		printf("FAIL: allow range parsing\n");
		return (1);
	}
	expect("10.1.2.3", 1);
	expect("::ffff:10.1.2.3", 1);
	expect("10.2.0.1", 0);
	expect("fd00:1::9", 1);
	expect("fd00:2::9", 0);
	expect("127.0.0.1", 0);		/* own interface stays denied */
	return (0);
}

int
main(int argc, char **argv)
{
	const char *g = argc > 1 ? argv[1] : "";
	int rc = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(10);
	event_init();
	evdns_init();

	if (strcmp(g, "v4") == 0) {
		table(v4_denied, 0);
		table(v4_edges_allowed, 1);
		expect("93.184.216.34", 1);
	} else if (strcmp(g, "v6") == 0) {
		table(v6_denied, 0);
		expect("2606:4700::1111", 1);
		expect("2001:4860:4860::8888", 1);
	} else if (strcmp(g, "mapped") == 0) {
		table(mapped_denied, 0);
		expect("::ffff:93.184.216.34", 1);
	} else if (strcmp(g, "name") == 0) {
		/* Only a resolved numeric address is judged */
		expect("localhost", 0);
		expect("metadata.example", 0);
		expect("", 0);
	} else if (strcmp(g, "own") == 0) {
		rc = own_interface();
	} else if (strcmp(g, "decoy") == 0) {
		rc = decoy();
	} else if (strcmp(g, "override") == 0) {
		rc = override();
	} else if (strcmp(g, "recheck") == 0) {
		rc = recheck();
	} else {
		printf("FAIL: unknown group %s\n", g);
		return (1);
	}
	return (rc || bad ? 1 : 0);
}
