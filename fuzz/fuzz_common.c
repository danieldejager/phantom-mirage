/*
 * Shared libFuzzer support for honeyd (issue #38).
 *
 * honeyd.c is compiled into each fuzzer with main() renamed, so the
 * harnesses can reach its static state (honeyd_ip). Side effects are
 * stubbed with -Wl,--wrap (see fuzz/build.sh): nothing is ever forked or
 * exec'd, no packet leaves the box, and only AF_UNIX connects (syslog)
 * are allowed.
 */
#define main honeyd_main
#include "../honeyd.c"
#undef main

#include <sys/socket.h>
#include <stdarg.h>
#include "fuzz_common.h"

#ifndef FUZZ_DATADIR
#error "FUZZ_DATADIR must point at the repository root"
#endif

/* ---- side-effect stubs (linked with --wrap) ---- */

pid_t __wrap_fork(void) { errno = EPERM; return (-1); }
int __wrap_execv(const char *p, char *const a[]) { abort(); }
int __wrap_execvp(const char *p, char *const a[]) { abort(); }

int __real_connect(int, const struct sockaddr *, socklen_t);
int
__wrap_connect(int fd, const struct sockaddr *sa, socklen_t len)
{
	if (sa != NULL && sa->sa_family == AF_UNIX)
		return (__real_connect(fd, sa, len));
	errno = ECONNREFUSED;
	return (-1);
}

static char fake_handle[64];
ip_t *__wrap_ip_open(void) { return ((ip_t *)fake_handle); }
void (*fuzz_ip_send_hook)(const void *, size_t);
ssize_t
__wrap_ip_send(ip_t *i, const void *buf, size_t len)
{
	if (fuzz_ip_send_hook != NULL)
		fuzz_ip_send_hook(buf, len);
	return (len);
}
void (*fuzz_eth_send_hook)(const void *, size_t);
ssize_t
__wrap_eth_send(eth_t *e, const void *buf, size_t len)
{
	if (fuzz_eth_send_hook != NULL)
		fuzz_eth_send_hook(buf, len);
	return (len);
}

/* ---- init ---- */

static int load_mac(FILE *);

static void
load(const char *name, int (*parse)(FILE *))
{
	char path[1024];
	FILE *fp;

	snprintf(path, sizeof(path), "%s/%s", FUZZ_DATADIR, name);
	if ((fp = fopen(path, "r")) == NULL || parse(fp) == -1) {
		fprintf(stderr, "fuzz init: cannot load %s\n", path);
		abort();
	}
	if (parse != load_mac)
		fclose(fp);
}

static int
load_mac(FILE *fp)
{
	ethernetcode_init(fp);		/* closes fp itself */
	return (0);
}

/* Fake Ethernet interface 10.0.0.1/24 for honeyd_recv_cb */
struct interface fuzz_iface;

void
fuzz_honeyd_init(const char *conf)
{
	char path[1024];
	static int done;
	struct evbuffer *out;
	char *copy;

	if (done)
		return;
	done = 1;

	/* Quiet: honeyd logs every packet to syslog */
	setlogmask(LOG_UPTO(LOG_EMERG));

	if ((honeyd_rand = rand_open()) == NULL)
		abort();
	libevent_base = event_base_new();
	event_base_priority_init(libevent_base, 3);
	pool_pkt = pool_init(HONEYD_MTU);
	pool_delay = pool_init(sizeof(struct delay));
	hooks_init();
	arp_init();
	config_init();
	router_init();
	plugins_config_init();
	personality_init();
	xprobe_personality_init();
	associations_init();
	load("xprobe2.conf", xprobe_personality_parse);
	load("nmap.assoc", parse_associations);
	load("nmap-os-db", personality_parse);
	snprintf(path, sizeof(path), "%s/pf.os", FUZZ_DATADIR);
	if (honeyd_osfp_init(path) == -1)
		abort();
	honeyd_init();
	honeyd_ip = ip_open();
	load("nmap-mac-prefixes", load_mac);
	ip_fragment_init();

	memset(&fuzz_iface, 0, sizeof(fuzz_iface));
	strlcpy(fuzz_iface.if_ent.intf_name, "fuzz0",
	    sizeof(fuzz_iface.if_ent.intf_name));
	addr_aton("10.0.0.1/24", &fuzz_iface.if_ent.intf_addr);
	addr_aton("02:00:00:00:00:01", &fuzz_iface.if_ent.intf_link_addr);
	fuzz_iface.if_addrbits = 24;
	fuzz_iface.if_dloff = ETH_HDR_LEN;

	if (conf != NULL) {
		out = evbuffer_new();
		copy = strdup(conf);
		if (parse_line(out, copy) == -1) {
			fprintf(stderr, "fuzz init: config failed: %.*s\n",
			    (int)evbuffer_get_length(out),
			    (char *)evbuffer_pullup(out, -1));
			abort();
		}
		free(copy);
		evbuffer_free(out);
	}
}

/* Run whatever the last input scheduled (delayed packets, timers) */
void
fuzz_drain_events(void)
{
	event_base_loop(libevent_base, EVLOOP_NONBLOCK);
}
