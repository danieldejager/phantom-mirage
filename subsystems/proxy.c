/*
 * Copyright (c) 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <netinet/in.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <err.h>
#include <syslog.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include <pcre.h>
#include <event.h>
#include <evdns.h>
#include <dnet.h>

#include "util.h"
#include "proxy.h"
#include "proxy_messages.h"
#include "smtp.h"
#include "honeyd_overload.h"

extern int debug;

#define DFPRINTF(x, y)	do { \
	if (debug >= x) fprintf y; \
} while (0)

/* globals */

FILE *flog_proxy = NULL;	/* log the proxy transactions somewhere */
static pcre *re_connect;	/* regular expression to match connect */
static pcre *re_hostport;	/* extracts host and port */
static pcre *re_get;		/* generic get request */

/* Generic PROXY related code */

char *
proxy_logline(struct proxy_ta *ta)
{
	static char line[1024];
	char *srcipaddress = kv_find(&ta->dictionary, "$srcipaddress");
	char *cmd = kv_find(&ta->dictionary, "$command");
	char *host = kv_find(&ta->dictionary, "$host");
	char *port = kv_find(&ta->dictionary, "$port");
	char *uri = kv_find(&ta->dictionary, "$rawuri");

	if (!strcasecmp("connect", cmd)) {
		snprintf(line, sizeof(line),
		    "%d %s: CONNECT %s:%s",
		    time(NULL), srcipaddress,
		    host, port);
	} else {
		snprintf(line, sizeof(line),
		    "%d %s: GET %s:%s%s", 
		    time(NULL), srcipaddress,
		    host, port, uri);
	}

	return (line);
}

void
proxy_clear_state(struct proxy_ta *ta)
{
	/* XXX - something here */
}

/* Callbacks for PROXY handling */

char *
proxy_response(struct proxy_ta *ta, struct keyvalue data[]) {
	static char line[1024];
	struct keyvalue *cur;

	for (cur = &data[0]; cur->key != NULL; cur++) {
		if (strcmp(ta->proxy_id, cur->key) == 0)
			break;
	}

	if (cur->key == NULL)
		return (NULL);

	if (copy_bounded(line, sizeof(line), cur->value,
		strlen(cur->value)) == -1)
		return (NULL);

	/* NULL if an expansion does not fit, never a partial template */
	TAILQ_FOREACH(cur, &ta->dictionary, next) {
		if (strrpl_bounded(line, sizeof(line), cur->key, cur->value,
			NULL) == -1)
			return (NULL);
	}
	
	return (line);
}

static const char proxy_fail[] = "HTTP/1.0 500 Internal error\r\n\r\n";

/*
 * Expands a response template and writes it to the client. If it
 * cannot be expanded, writes a fixed 500 reply instead. Either way the
 * caller closes once it is written.
 */
static void
proxy_write_response(struct proxy_ta *ta, struct keyvalue data[])
{
	char *response = proxy_response(ta, data);

	if (response == NULL)
		bufferevent_write(ta->bev, proxy_fail, sizeof(proxy_fail) - 1);
	else
		bufferevent_write(ta->bev, response, strlen(response));
}

/*
 * Destination policy (PM-SCR-104). Only a numeric, resolved address is
 * judged; a host name is always refused. IPv4 mapped and IPv4
 * compatible IPv6 addresses are judged by their embedded IPv4 address.
 * In order:
 *   1. the host's own interface addresses and the operator named decoy
 *      ranges (-D) are refused;
 *   2. the hard deny ranges below (PROXY_HARD) are refused;
 *   3. an operator named allow range (-A, none by default) is accepted;
 *   4. the remaining special purpose ranges below are refused;
 *   5. anything else is accepted.
 * So -A, however wide, never reopens steps 1 and 2. NAT64, 6to4 and
 * Teredo prefixes are refused whole rather than judged by the IPv4
 * address they carry: a translator or relay can reach any IPv4
 * address, so the outer address is what the proxy actually talks to.
 * -A and -D each take up to PROXY_MAX_RANGES ranges.
 */
struct proxy_range {
	int af;			/* AF_INET or AF_INET6 */
	u_char net[16];
	int bits;
};

#define PROXY_MAX_RANGES	32
#define PROXY_HARD		1	/* -A cannot reopen */

static struct proxy_range proxy_allow[PROXY_MAX_RANGES];
static int proxy_nallow;
static struct proxy_range proxy_decoy[PROXY_MAX_RANGES];
static int proxy_ndecoy;

static const struct {
	const char *net;
	int bits;
	int hard;
} proxy_denied4[] = {
	{ "0.0.0.0", 8, PROXY_HARD },		/* this network */
	{ "10.0.0.0", 8, 0 },			/* RFC 1918 */
	{ "100.64.0.0", 10, 0 },		/* shared address space, CGNAT */
	{ "127.0.0.0", 8, PROXY_HARD },		/* loopback */
	{ "169.254.0.0", 16, 0 },		/* link local, cloud metadata */
	{ "172.16.0.0", 12, 0 },		/* RFC 1918 */
	{ "192.0.0.0", 24, 0 },			/* IETF protocol assignments */
	{ "192.0.2.0", 24, PROXY_HARD },	/* documentation */
	{ "192.88.99.0", 24, PROXY_HARD },	/* 6to4 relay anycast */
	{ "192.168.0.0", 16, 0 },		/* RFC 1918 */
	{ "198.18.0.0", 15, 0 },		/* benchmarking */
	{ "198.51.100.0", 24, PROXY_HARD },	/* documentation */
	{ "203.0.113.0", 24, PROXY_HARD },	/* documentation */
	{ "224.0.0.0", 4, 0 },			/* multicast */
	{ "240.0.0.0", 4, 0 },			/* reserved */
	{ "255.255.255.255", 32, PROXY_HARD },	/* limited broadcast */
	{ NULL, 0, 0 }
}, proxy_denied6[] = {
	{ "::", 128, PROXY_HARD },		/* unspecified */
	{ "::1", 128, PROXY_HARD },		/* loopback */
	{ "64:ff9b::", 96, PROXY_HARD },	/* NAT64 well known prefix */
	{ "64:ff9b:1::", 48, PROXY_HARD },	/* NAT64 local use */
	{ "100::", 64, PROXY_HARD },		/* discard only */
	{ "2001::", 23, PROXY_HARD },		/* IETF protocol assignments */
	{ "2001::", 32, PROXY_HARD },		/* Teredo (inside the /23) */
	{ "2001:db8::", 32, PROXY_HARD },	/* documentation */
	{ "2002::", 16, PROXY_HARD },		/* 6to4 */
	{ "5f00::", 16, PROXY_HARD },		/* SRv6 SIDs */
	{ "fc00::", 7, 0 },			/* unique local */
	{ "fe80::", 10, 0 },			/* link local */
	{ "fec0::", 10, PROXY_HARD },		/* site local, deprecated */
	{ "ff00::", 8, 0 },			/* multicast */
	{ NULL, 0, 0 }
};

static int
proxy_prefix_match(const u_char *a, const u_char *net, int bits)
{
	int full = bits / 8, rest = bits % 8;

	if (memcmp(a, net, full) != 0)
		return (0);
	if (rest == 0)
		return (1);
	return (((a[full] ^ net[full]) & (0xff << (8 - rest)) & 0xff) == 0);
}

/* Reduces IPv4 mapped and IPv4 compatible IPv6 to IPv4 */
static void
proxy_normalize(int *af, u_char *a)
{
	static const u_char mapped[12] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
	static const u_char zero[16];

	if (*af != AF_INET6)
		return;
	if (memcmp(a, mapped, 12) == 0 ||
	    (memcmp(a, zero, 12) == 0 && memcmp(a, zero, 16) != 0 &&
	     !(memcmp(a, zero, 15) == 0 && a[15] == 1))) {
		memmove(a, a + 12, 4);
		*af = AF_INET;
	}
}

static int
proxy_parse_addr(const char *s, int *af, u_char *a)
{
	memset(a, 0, 16);
	if (inet_pton(AF_INET, s, a) == 1)
		*af = AF_INET;
	else if (inet_pton(AF_INET6, s, a) == 1)
		*af = AF_INET6;
	else
		return (-1);
	proxy_normalize(af, a);
	return (0);
}

static int
proxy_parse_range(const char *s, struct proxy_range *r)
{
	char buf[INET6_ADDRSTRLEN + 8], *slash, *end;
	int max;
	long bits;

	if (strlen(s) >= sizeof(buf))
		return (-1);
	snprintf(buf, sizeof(buf), "%s", s);
	if ((slash = strchr(buf, '/')) != NULL)
		*slash++ = '\0';
	memset(r->net, 0, sizeof(r->net));
	if (inet_pton(AF_INET, buf, r->net) == 1)
		r->af = AF_INET;
	else if (inet_pton(AF_INET6, buf, r->net) == 1)
		r->af = AF_INET6;
	else
		return (-1);
	max = r->af == AF_INET ? 32 : 128;
	r->bits = max;
	if (slash != NULL) {
		bits = strtol(slash, &end, 10);
		if (*slash == '\0' || *end != '\0' || bits < 0 || bits > max)
			return (-1);
		r->bits = bits;
	}
	/*
	 * A mapped or compatible range that covers only embedded IPv4
	 * addresses is stored as the IPv4 range, the same way addresses
	 * are normalised before they are compared.
	 */
	if (r->af == AF_INET6 && r->bits >= 96) {
		int af = AF_INET6;
		u_char a[16];

		memcpy(a, r->net, sizeof(a));
		proxy_normalize(&af, a);
		if (af == AF_INET) {
			memset(r->net, 0, sizeof(r->net));
			memcpy(r->net, a, 4);
			r->af = AF_INET;
			r->bits -= 96;
		}
	}
	return (0);
}

static int
proxy_add_range(struct proxy_range *list, int *n, const char *s)
{
	if (*n >= PROXY_MAX_RANGES || proxy_parse_range(s, &list[*n]) == -1)
		return (-1);
	(*n)++;
	return (0);
}

/*
 * -A: allow a range inside the special purpose ranges that are not
 * hard denied. Off by default; up to PROXY_MAX_RANGES ranges.
 */
int
proxy_allow_range(const char *s)
{
	return (proxy_add_range(proxy_allow, &proxy_nallow, s));
}

/* -D: refuse a decoy (honeyd virtual) address range; up to PROXY_MAX_RANGES */
int
proxy_decoy_range(const char *s)
{
	return (proxy_add_range(proxy_decoy, &proxy_ndecoy, s));
}

static int
proxy_in_ranges(const struct proxy_range *list, int n, int af,
    const u_char *a)
{
	int i;

	for (i = 0; i < n; i++) {
		if (list[i].af == af &&
		    proxy_prefix_match(a, list[i].net, list[i].bits))
			return (1);
	}
	return (0);
}

static int
proxy_own_interface(int af, const u_char *a)
{
	struct ifaddrs *ifa, *i;
	u_char b[16];
	int baf, found = 0;

	if (getifaddrs(&ifa) == -1)
		return (1);	/* cannot tell: refuse */
	for (i = ifa; i != NULL && !found; i = i->ifa_next) {
		if (i->ifa_addr == NULL)
			continue;
		memset(b, 0, sizeof(b));
		baf = i->ifa_addr->sa_family;
		if (baf == AF_INET)
			memcpy(b, &((struct sockaddr_in *)
			    i->ifa_addr)->sin_addr, 4);
		else if (baf == AF_INET6)
			memcpy(b, &((struct sockaddr_in6 *)
			    i->ifa_addr)->sin6_addr, 16);
		else
			continue;
		proxy_normalize(&baf, b);
		found = baf == af && memcmp(a, b, af == AF_INET ? 4 : 16) == 0;
	}
	freeifaddrs(ifa);
	return (found);
}

/* In a deny table range; hard only, or any when hard is 0 */
static int
proxy_denied(int af, const u_char *a, int hard)
{
	u_char net[16];
	int i;

	for (i = 0; ; i++) {
		const char *s = af == AF_INET ?
		    proxy_denied4[i].net : proxy_denied6[i].net;
		int bits = af == AF_INET ?
		    proxy_denied4[i].bits : proxy_denied6[i].bits;
		int h = af == AF_INET ?
		    proxy_denied4[i].hard : proxy_denied6[i].hard;

		if (s == NULL)
			return (0);
		if (hard && !h)
			continue;
		memset(net, 0, sizeof(net));
		inet_pton(af, s, net);
		if (proxy_prefix_match(a, net, bits))
			return (1);
	}
}

static int
proxy_allowed_addr(int af, u_char *a)
{

	proxy_normalize(&af, a);
	if (proxy_own_interface(af, a) ||
	    proxy_in_ranges(proxy_decoy, proxy_ndecoy, af, a))
		return (0);
	if (proxy_denied(af, a, PROXY_HARD))
		return (0);
	if (proxy_in_ranges(proxy_allow, proxy_nallow, af, a))
		return (1);
	return (!proxy_denied(af, a, 0));
}

/* Takes a numeric address; a host name is refused */
int
proxy_allowed_network(const char *host)
{
	u_char a[16];
	int af;

	if (host == NULL || proxy_parse_addr(host, &af, a) == -1)
		return (0);
	return (proxy_allowed_addr(af, a));
}

/* Same policy for a connected socket's peer */
static int
proxy_allowed_peer(int fd)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	u_char a[16];

	memset(&ss, 0, sizeof(ss));
	memset(a, 0, sizeof(a));
	if (getpeername(fd, (struct sockaddr *)&ss, &len) == -1)
		return (0);
	if (ss.ss_family == AF_INET) {
		memcpy(a, &((struct sockaddr_in *)&ss)->sin_addr, 4);
		return (proxy_allowed_addr(AF_INET, a));
	}
	if (ss.ss_family == AF_INET6) {
		memcpy(a, &((struct sockaddr_in6 *)&ss)->sin6_addr, 16);
		return (proxy_allowed_addr(AF_INET6, a));
	}
	return (0);
}

/* The subsystem's own decoy address, as honeyd reported it */
static int
proxy_is_local(struct proxy_ta *ta, const char *host)
{
	char *local = kv_find(&ta->dictionary, "$dstipaddress");
	u_char a[16], b[16];
	int af, bf;

	if (local == NULL || proxy_parse_addr(local, &bf, b) == -1)
		return (0);
	if (proxy_parse_addr(host, &af, a) == -1)
		return (1);
	return (af == bf && memcmp(a, b, af == AF_INET ? 4 : 16) == 0);
}

/*
 * Checks if we are allowed to retrieve a URL from here.
 */

int
proxy_allowed_get(struct proxy_ta *ta, struct keyvalue data[])
{
	const char *error;
	int erroroffset;
	char *host, *uri;
	struct keyvalue *cur;
	pcre *re_uri;
	int rc;
	int ovector[30];

	host = kv_find(&ta->dictionary, "$host");
	uri = kv_find(&ta->dictionary, "$rawuri");

	for (cur = &data[0]; cur->key != NULL; cur++) {
		if (strcmp(host, cur->key) == 0)
			break;
	}

	/* Host is not allowed if we do not find it */
	if (cur->key == NULL)
		return (0);

	re_uri = pcre_compile(cur->value, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_uri == NULL) {
		/* Default to no match */
		fprintf(stderr, "%s: %s: %s at %d",
		    __func__, cur->value, error, erroroffset);
		return (0);
	}

	/* Match against the URI */
	rc = pcre_exec(re_uri, NULL, uri, strlen(uri), 0, 0, ovector, 30);

	pcre_free(re_uri);

	return (rc >= 0);
}

int
proxy_bad_connection(struct proxy_ta *ta)
{
	proxy_write_response(ta, badconnection);
	ta->wantclose = 1;
	return (0);
}

void
proxy_remote_readcb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	struct evbuffer *buffer = EVBUFFER_INPUT(bev);
	unsigned char *data = EVBUFFER_DATA(buffer);
	size_t len = evbuffer_get_length(buffer);

	bufferevent_write(ta->bev, data, len);
	evbuffer_drain(buffer, len);
}

void
proxy_remote_writecb(struct bufferevent *bev, void *arg)
{
}

void
proxy_remote_errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct proxy_ta *ta = arg;
	struct evbuffer *buffer = EVBUFFER_OUTPUT(ta->bev);
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	/* If we still have data to write; we just wait for the flush */
	if (evbuffer_get_length(buffer)) {
		/* Shutdown this site at least - XXX: maybe call shutdown */
		bufferevent_disable(bev, EV_READ|EV_WRITE);

		ta->wantclose = 1;
	} else {
		proxy_ta_free(ta);
	}
}

char *
proxy_corrupt(char *data, size_t len)
{
	static char buffer[4096];
	int corruptions = len / CORRUPT_SPACE + 1;
	int i;

	if (len > sizeof(buffer) || len <= 1)
		return (data);

	memcpy(buffer, data, len);
	for (i = 0; i < corruptions; i++) {
		int off = rand() % (len - 1);
		buffer[off] = rand();
	}

	return (buffer);
}

void
proxy_connect_cb(int fd, short what, void *arg)
{
	char line[1024], *data;
	struct proxy_ta *ta = arg;
	int error;
	socklen_t errsz = sizeof(error);
	char *uri;

	ta->connect_pending = 0;

	/* Check if the connection completed */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1 ||
	    error) {
		fprintf(stderr, "%s: connection failed: %s\n",
		    __func__, strerror(error));
		close(fd);
		ta->remote_fd = -1;

		/* Give them a connect error message */
		kv_replace(&ta->dictionary, "$reason", strerror(error));
		proxy_write_response(ta, badconnect);

		ta->wantclose = 1;
		return;
	}

	/* Check the address actually connected to, not only the name */
	if (!proxy_allowed_peer(fd)) {
		close(fd);
		ta->remote_fd = -1;
		kv_replace(&ta->dictionary, "$reason",
		    "destination not allowed");
		proxy_write_response(ta, badconnect);
		ta->wantclose = 1;
		return;
	}

	ta->remote_bev = bufferevent_new(ta->remote_fd,
	    proxy_remote_readcb, proxy_remote_writecb,
	    proxy_remote_errorcb, ta);
	if (ta->remote_bev == NULL) {
		proxy_ta_free(ta);	/* closes remote_fd */
		return;
	}

	/* If this get is not allowed, we are going to corrupt the data */
	if (!proxy_allowed_get(ta, allowedhosts))
		ta->corrupt = 1;

	uri = kv_find(&ta->dictionary, "$rawuri");
	snprintf(line, sizeof(line), "GET %s HTTP/1.0\r\n",
	    ta->corrupt ? proxy_corrupt(uri, strlen(uri)) : uri);
	bufferevent_write(ta->remote_bev, line, strlen(line));

	/* Forward all the headers */
	while ((data = kv_find(&ta->dictionary, "data")) != NULL) {
		/* We do not propagate X-Forwarded-For headers */
		if (strncasecmp(X_FORWARDED, data, strlen(X_FORWARDED))) {
			bufferevent_write(ta->remote_bev,
			    ta->corrupt ? proxy_corrupt(data, strlen(data)) :
			    data, strlen(data)); 
			bufferevent_write(ta->remote_bev, "\r\n", 2); 
		}

		/* Do not invalidate this data until we used it */
		kv_remove(&ta->dictionary, "data");
	}
	bufferevent_write(ta->remote_bev, "\r\n", 2); 

	/* Allow the remote site to send us data */
	bufferevent_enable(ta->remote_bev, EV_READ);

	ta->justforward = 1;
}

void
proxy_connect(struct proxy_ta *ta, char *host, int port)
{
	fprintf(stderr, "Connecting to %s port %d\n", host, port);

	/*
	 * Only one upstream connection per transaction: refuse a second
	 * request with an error and close once it has been written.
	 */
	if (ta->connect_pending || ta->remote_fd != -1) {
		proxy_bad_connection(ta);
		return;
	}

	if (!proxy_allowed_network(host) || proxy_is_local(ta, host)) {
		errno = EACCES;
	} else {
		char *local_ip = kv_find(&ta->dictionary, "$dstipaddress");

		if (local_ip != NULL) {
			ta->remote_fd = make_bound_connect(
				SOCK_STREAM, host, port, local_ip);
		} else {
			ta->remote_fd = make_socket(
				connect, SOCK_STREAM, host, port);
		}
	}
	if (ta->remote_fd == -1) {
		fprintf(stderr, "%s: failed to connect: %s\n",
		    __func__, strerror(errno));
		kv_replace(&ta->dictionary, "$reason", strerror(errno));
		proxy_write_response(ta, badconnect);
		ta->wantclose = 1;
		return;
	}

	/* Owned by ta so that proxy_ta_free can cancel it */
	event_set(&ta->connect_ev, ta->remote_fd, EV_WRITE,
	    proxy_connect_cb, ta);
	if (event_add(&ta->connect_ev, NULL) == -1) {
		close(ta->remote_fd);
		ta->remote_fd = -1;
		return;
	}
	ta->connect_pending = 1;
}

void
proxy_handle_get_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct proxy_ta *ta = arg;
	struct addr addr;
	struct in_addr *in_addrs = addresses;
	int port = atoi(kv_find(&ta->dictionary, "$port"));

	ta->dns_pending--;
	if (ta->dns_canceled) {
		/* Torn down while lookups were in flight: last one frees */
		if (ta->dns_pending == 0)
			proxy_ta_free(ta);
		return;
	}

	if (result != DNS_ERR_NONE || type != DNS_IPv4_A || count == 0) {
		proxy_write_response(ta, baddomain);
		ta->wantclose = 1;
		return;
	}

	/* Need to make a connection here */
	bufferevent_disable(ta->bev, EV_READ);

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &in_addrs[0], IP_ADDR_LEN);
	proxy_connect(ta, addr_ntoa(&addr), port);
}

int
proxy_handle_get(struct proxy_ta *ta)
{
	char *host = kv_find(&ta->dictionary, "$rawhost");
	int rc;
	int ovector[30];

	kv_replace(&ta->dictionary, "$command", "GET");

	rc = pcre_exec(re_hostport, NULL, host, strlen(host), 0, 0,
	    ovector, 30);
	if (rc >= 0) {
		char *strport = proxy_pcre_group(host, 2, ovector);
		char *real_host = proxy_pcre_group(host, 1, ovector);

		kv_add(&ta->dictionary, "$host", real_host);
		kv_add(&ta->dictionary, "$port", strport);

		free(real_host);
		free(strport);
	} else {
		kv_add(&ta->dictionary, "$host", host);
		kv_add(&ta->dictionary, "$port", "80");
	}

	if (flog_proxy != NULL) {
		char *line = proxy_logline(ta);
		fprintf(flog_proxy, "%s\n", line);
		fflush(flog_proxy);
	}

	/* Try to resolve the domain name */
	ta->dns_pending++;
	if (evdns_resolve_ipv4(kv_find(&ta->dictionary, "$host"), 0,
		proxy_handle_get_cb, ta) != 0) {
		/*
		 * Failed synchronously: no callback will ever run.
		 * Run it now as a failed lookup, so a live client
		 * gets the usual reply and a canceled one is freed.
		 */
		proxy_handle_get_cb(DNS_ERR_UNKNOWN, 0, 0, 0, NULL, ta);
	}
	return (0);
}

void
proxy_handle_connect_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	struct proxy_ta *ta = arg;
	char *host = kv_find(&ta->dictionary, "$host");
	int port = atoi(kv_find(&ta->dictionary, "$port"));
	char *response;
	int allowed = 0;
	fprintf(stderr, "Connecting to %s port %d\n", host, port);

	ta->dns_pending--;
	if (ta->dns_canceled) {
		/* Torn down while lookups were in flight: last one frees */
		if (ta->dns_pending == 0)
			proxy_ta_free(ta);
		return;
	}

	if (result != DNS_ERR_NONE) {
		proxy_write_response(ta, baddomain);
		ta->wantclose = 1;
		return;
	}

	/* Judge the resolved address, not the name (PM-SCR-104) */
	if (type == DNS_IPv4_A && count > 0) {
		struct addr addr;

		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, addresses,
		    IP_ADDR_LEN);
		allowed = proxy_allowed_network(addr_ntoa(&addr));
	}

	if (port != 25 || !allowed) {
		proxy_write_response(ta, badport);
		ta->wantclose = 1;
	} else {
		struct smtp_ta *smtp_ta = NULL;
		int fd = dup(ta->fd);

		if (fd != -1)
			smtp_ta = smtp_ta_new(fd,
			    (struct sockaddr *)&ta->sa, ta->salen, 
			    NULL, 0, 0);
		if (smtp_ta != NULL) {
			char *greeting;

			/* Both must fit before anything is written */
			response = proxy_response(ta, goodport);
			greeting = response != NULL ?
			    smtp_greeting_response(smtp_ta) : NULL;
			if (greeting == NULL) {
				smtp_ta_free(smtp_ta);
				bufferevent_write(ta->bev, proxy_fail,
				    sizeof(proxy_fail) - 1);
				ta->wantclose = 1;
				return;
			}
			bufferevent_write(smtp_ta->bev,
			    response, strlen(response));
			bufferevent_write(smtp_ta->bev,
			    greeting, strlen(greeting));

			proxy_ta_free(ta);
		} else {
			kv_add(&ta->dictionary, "$host", host);
			proxy_write_response(ta, badport);
			ta->wantclose = 1;
		}
	}
}

int
proxy_handle_connect(struct proxy_ta *ta)
{
	char *host = kv_find(&ta->dictionary, "$rawhost");
	int rc;
	int ovector[30];

	kv_replace(&ta->dictionary, "$command", "CONNECT");

	rc = pcre_exec(re_hostport, NULL, host, strlen(host), 0, 0,
	    ovector, 30);
	if (rc >= 0) {
		char *strport = proxy_pcre_group(host, 2, ovector);
		char *real_host = proxy_pcre_group(host, 1, ovector);

		kv_add(&ta->dictionary, "$host", real_host);
		kv_add(&ta->dictionary, "$port", strport);

		free(real_host);
		free(strport);
	} else {
		kv_add(&ta->dictionary, "$host", host);
		kv_add(&ta->dictionary, "$port", "80");
	}

	if (flog_proxy != NULL) {
		char *line = proxy_logline(ta);
		fprintf(flog_proxy, "%s\n", line);
		fflush(flog_proxy);
	}

	/* Try to resolve the domain name */
	ta->dns_pending++;
	if (evdns_resolve_ipv4(kv_find(&ta->dictionary, "$host"), 0,
		proxy_handle_connect_cb, ta) != 0) {
		/*
		 * Failed synchronously: no callback will ever run.
		 * Run it now as a failed lookup, so a live client
		 * gets the usual reply and a canceled one is freed.
		 */
		proxy_handle_connect_cb(DNS_ERR_UNKNOWN, 0, 0, 0, NULL, ta);
	}
	return (0);
}

char *
proxy_pcre_group(char *line, int groupnr, int ovector[])
{
	int start = ovector[2*groupnr];
	int end = ovector[2*groupnr + 1];
	char *group = malloc(end - start + 1);
	if (group == NULL)
	{
		syslog(LOG_ERR, "%s: gettimeofday", __func__);
		exit(EXIT_FAILURE);
	}
	memcpy(group, line + start, end - start);
	group[end-start] = '\0';

	return (group);
}

int
proxy_handle(struct proxy_ta *ta, char *line)
{
	int rc;
	int ovector[30];

	/* Execute regular expressions to match the command */

	rc = pcre_exec(re_connect, NULL, line, strlen(line), 0, 0,
	    ovector, 30);
	if (rc >= 0) {
		char *host = proxy_pcre_group(line, 1, ovector);
		kv_replace(&ta->dictionary, "$rawhost", host);
		free(host);

		ta->empty_cb = proxy_handle_connect;
		return (0);
	}

	rc = pcre_exec(re_get, NULL, line, strlen(line), 0, 0, ovector, 30);
	if (rc >= 0) {
		char *host = proxy_pcre_group(line, 1, ovector);
		char *uri = proxy_pcre_group(line, 2, ovector);
		kv_replace(&ta->dictionary, "$rawhost", host);
		kv_replace(&ta->dictionary, "$rawuri", uri);
		free(host);
		free(uri);

		ta->empty_cb = proxy_handle_get;
		return (0);
	}

	return proxy_bad_connection(ta);
}

char *
proxy_readline(struct bufferevent *bev)
{
	struct evbuffer *buffer = EVBUFFER_INPUT(bev);
	char *data = EVBUFFER_DATA(buffer);
	size_t len = evbuffer_get_length(buffer);
	char *line;
	int i;

	for (i = 0; i < len; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
	}
	
	if (i == len)
		return (NULL);

	if ((line = malloc(i + 1)) == NULL) {
		fprintf(stderr, "%s: out of memory\n", __func__);
		evbuffer_drain(buffer, i);
		return (NULL);
	}

	memcpy(line, data, i);
	line[i] = '\0';

	if ( i < len - 1 ) {
		char fch = data[i], sch = data[i+1];

		/* Drain one more character if needed */
		if ( (sch == '\r' || sch == '\n') && sch != fch )
			i += 1;
	}

	evbuffer_drain(buffer, i + 1);

	return (line);
}

/*
 * Too many header lines or bytes: answer 400 unless a reply is already
 * queued, stop reading and close once the reply has been written.
 */
static void
proxy_header_limit(struct proxy_ta *ta)
{
	struct evbuffer *input = EVBUFFER_INPUT(ta->bev);

	bufferevent_disable(ta->bev, EV_READ);
	evbuffer_drain(input, evbuffer_get_length(input));
	if (!ta->wantclose)
		proxy_bad_connection(ta);
	else if (evbuffer_get_length(EVBUFFER_OUTPUT(ta->bev)) == 0)
		proxy_ta_free(ta);	/* nothing left to write */
}

void
proxy_readcb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	size_t before;
	char *line;

	if (ta->justforward) {
		struct evbuffer *input = EVBUFFER_INPUT(bev);
		char *data = EVBUFFER_DATA(input);
		size_t len = evbuffer_get_length(input);
		if (ta->corrupt) {
			bufferevent_write(ta->remote_bev,
			    proxy_corrupt(data, len), len);
		} else {
			bufferevent_write(ta->remote_bev, data, len);
		}
		evbuffer_drain(input, len);
		return;
	}

	before = evbuffer_get_length(EVBUFFER_INPUT(bev));
	while ((line = proxy_readline(bev)) != NULL) {
		int res = 0;
		size_t used = before - evbuffer_get_length(EVBUFFER_INPUT(bev));

		before = evbuffer_get_length(EVBUFFER_INPUT(bev));
		/* Header lines and discarded lines count against the limits */
		if (ta->wantclose || (ta->empty_cb != NULL && strlen(line))) {
			ta->hdr_lines++;
			ta->hdr_bytes += used;
			if (ta->hdr_lines > PROXY_MAX_HEADER_LINES ||
			    ta->hdr_bytes > PROXY_MAX_HEADER_BYTES) {
				free(line);
				proxy_header_limit(ta);
				return;
			}
		}
		/* If we are ready to close on the bugger, just eat it */
		if (ta->wantclose) {
			free(line);
			continue;
		}
		if (ta->empty_cb) {
			/* eat the input until we get a return */
			if (strlen(line)) {
				kv_add(&ta->dictionary, "data", line);
				free(line);
				continue;
			} else {
				res = (*ta->empty_cb)(ta);
				ta->empty_cb = NULL;
			}
		} else {
			res = proxy_handle(ta, line);
		}
		free(line);

		/* Destroy the state machine on error */
		if (res == -1) {
			proxy_ta_free(ta);
			return;
		}
	}

	/* No end of line within MAX_LINE bytes: drop the connection */
	if (!ta->justforward &&
	    evbuffer_get_length(EVBUFFER_INPUT(bev)) >= MAX_LINE)
		proxy_ta_free(ta);
}

void
proxy_writecb(struct bufferevent *bev, void *arg)
{
	struct proxy_ta *ta = arg;
	
	if (ta->wantclose)
		proxy_ta_free(ta);
}

void
proxy_errorcb(struct bufferevent *bev, short what, void *arg)
{
	fprintf(stderr, "%s: called with %p, freeing\n", __func__, arg);

	proxy_ta_free(arg);
}

/* Tear down a connection */
void
proxy_ta_free(struct proxy_ta *ta)
{
	struct keyvalue *entry;

	if (ta->dns_pending > 0) {
		/*
		 * Lookups in flight hold a pointer to us: stop all I/O and
		 * let the last callback free the transaction.
		 */
		ta->dns_canceled = 1;
		bufferevent_disable(ta->bev, EV_READ|EV_WRITE);
		if (ta->remote_bev != NULL)
			bufferevent_disable(ta->remote_bev,
			    EV_READ|EV_WRITE);
		/* Nobody is waiting for the upstream connect any more */
		if (ta->connect_pending) {
			event_del(&ta->connect_ev);
			ta->connect_pending = 0;
			close(ta->remote_fd);
			ta->remote_fd = -1;
		}
		return;
	}

	while ((entry = TAILQ_FIRST(&ta->dictionary)) != NULL) {
		TAILQ_REMOVE(&ta->dictionary, entry, next);
		free(entry->key);
		free(entry->value);
		free(entry);
	}

	bufferevent_free(ta->bev);
	close(ta->fd);

	if (ta->connect_pending)
		event_del(&ta->connect_ev);
	if (ta->remote_bev != NULL)
		bufferevent_free(ta->remote_bev);
	if (ta->remote_fd != -1)
		close(ta->remote_fd);

	free(ta);
	
}

/* Create a new PROXY transaction */

struct proxy_ta *
proxy_ta_new(int fd, struct sockaddr *sa, socklen_t salen,
    struct sockaddr *lsa, socklen_t lsalen)
{
	struct proxy_ta *ta = calloc(1, sizeof(struct proxy_ta));
	char *srcipname, *srcportname;
	char *dstipname, *dstportname;

	if (ta == NULL)
		goto error;

	ta->proxy_id = "junkbuster";

	TAILQ_INIT(&ta->dictionary);

	memcpy(&ta->sa, sa, salen);
	ta->salen = salen;

	ta->fd = fd;
	ta->remote_fd = -1;
	ta->bev = bufferevent_new(fd,
	    proxy_readcb, proxy_writecb, proxy_errorcb, ta);
	if (ta->bev == NULL)
		goto error;
	bufferevent_setwatermark(ta->bev, EV_READ, 0, MAX_LINE);

	/* Create our tiny dictionary */
	if (lsa != NULL) {
		name_from_addr(lsa, lsalen, &dstipname, &dstportname);
		kv_add(&ta->dictionary, "$dstipaddress", dstipname);
	}

	name_from_addr(sa, salen, &srcipname, &srcportname);
	kv_add(&ta->dictionary, "$srcipaddress", srcipname);

	bufferevent_enable(ta->bev, EV_READ);

	fprintf(stderr, "%s: new proxy instance to %s complete.\n",
	    __func__, srcipname);

	return (ta);

 error:
	if (ta != NULL)
		free(ta);
	fprintf(stderr, "%s: out of memory\n", __func__);
	close(fd);

	return (NULL);
}

static void
accept_socket(int fd, short what, void *arg)
{
	struct sockaddr_storage ss, lss;
	socklen_t addrlen = sizeof(ss), laddrlen = sizeof(lss);
	int nfd, res;

	if ((nfd = accept(fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		fprintf(stderr, "%s: bad accept\n", __func__);
		return;
	}

	/* Test our special subsystem magic */
	res = fcntl(fd, F_XXX_GETSOCK, &lss, &laddrlen);

	if (res != -1) {
		/*
		 * We are running under honeyd and could figure out
		 * who we are.  That's great.
		 */
		proxy_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    (struct sockaddr *)&lss, laddrlen);
	} else {
		proxy_ta_new(nfd, (struct sockaddr *)&ss, addrlen,
		    NULL, 0);
	}
}

void
proxy_bind_socket(struct event *ev, u_short port)
{
	int fd;

	if ((fd = make_socket(bind, SOCK_STREAM, "0.0.0.0", port)) == -1)
	{
		syslog(LOG_ERR, "%s: cannot bind socket: %d", __func__, port);
		exit(EXIT_FAILURE);
	}

	if (listen(fd, 10) == -1)
	{
		syslog(LOG_ERR, "%s: listen failed: %d", __func__, port);
		exit(EXIT_FAILURE);
	}

	/* Schedule the socket for accepting */
	event_set(ev, fd, EV_READ | EV_PERSIST, accept_socket, NULL);
	event_add(ev, NULL);

	fprintf(stderr, 
	    "Bound to port %d\n"
	    "Awaiting connections ... \n",
	    port);
}

void
proxy_init(void)
{
	const char *error;
	int erroroffset;
	const char *exp_connect = "^connect\\s+(.*)\\s+http";
	const char *exp_hostport = "^(.*):([0-9]+)$";
	const char *exp_get = "^GET\\s+http://([^/ ]*)(/?[^ ]*)\\s+HTTP";

	/* Compile regular expressions for command parsing */
	re_connect = pcre_compile(exp_connect, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_connect == NULL)
	{
		syslog(LOG_ERR, "%s: %s at %d", __func__, error, erroroffset);
		exit(EXIT_FAILURE);
	}

	re_hostport = pcre_compile(exp_hostport, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_connect == NULL)
	{
		syslog(LOG_ERR, "%s: %s at %d", __func__, error, erroroffset);
		exit(EXIT_FAILURE);
	}

	re_get = pcre_compile(exp_get, PCRE_CASELESS,
	    &error, &erroroffset, NULL);
	if (re_connect == NULL)
	{
		syslog(LOG_ERR, "%s: %s at %d", __func__, error, erroroffset);
		exit(EXIT_FAILURE);
	}
}
