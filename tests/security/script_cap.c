/*
 * PM-SCR-152: script actions forked without any bound on live script
 * processes, UDP scripts got a SOCK_DGRAM pair that never reads EOF,
 * and cmd_free() only closed the pipe, so a script that ignored stdin
 * (or a UDP script) lived on after its flow.
 *
 * The harness runs real children: fuzz_real_exec makes fork() real and
 * turns execvp() into execv("/bin/sh"), so each action is a local shell
 * script in a private temporary directory. No packets leave the
 * process (ip_send and eth_send are stubbed). Each mode is one case:
 *
 *  global      max_script_procs caps live scripts over many sources;
 *              UDP takes at most half, TCP the rest, and a TCP flow
 *              at the cap gets a RST
 *  source      one source churning UDP flows stops at the per source
 *              cap; ending flows lets it start new scripts
 *  tcpkill     TCP script that ignores stdin dies when its flow ends
 *  grandchild  a background child of the script dies too
 *  reaped      a script reaped before its flow ends gets no signal
 *  nchildren   honeyd_nchildren returns to 0 after flows end
 *  sigchld     a failed SIGCHLD unblock after fork is retried
 *  seqpacket   with signals suppressed, a UDP script still sees EOF
 *  udpdrop     a UDP flow at the cap gets no script and no ICMP
 *  disabled    0 disables both caps
 *  udpshare    PM-SCR-221: spoofed UDP sources fill only the UDP share
 *              (half of max_script_procs); TCP scripts still start
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "config.h"
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <pcap.h>
#include <dnet.h>
#include "honeyd.h"
#include "template.h"
#include "interface.h"
#include "parser.h"
#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);
void honeyd_sigchld(int, short, void *);
extern int honeyd_nchildren;
extern uid_t honeyd_uid;
extern gid_t honeyd_gid;
extern struct conlru tcplru, udplru;

/* Present only with the fix; a NULL here is a FAIL, not a crash */
uint32_t cmd_script_procs(void) __attribute__((weak));
uint32_t cmd_script_udp_procs(void) __attribute__((weak));
extern uint32_t cmd_script_refused __attribute__((weak));

#define DST	0x0a000002

static char dir[] = "/tmp/pm152.XXXXXX";
static int fails;

static void
check(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

/* ---- wrapped libc calls ---- */

int __wrap_setgroups(size_t n, const gid_t *g) { return (0); }

static int kill_off;		/* suppress kill/killpg to other pids */
static int nkill;		/* kill/killpg calls aimed at other pids */
static pid_t kill_last;
int __real_kill(pid_t, int);
int __real_killpg(pid_t, int);

int
__wrap_kill(pid_t pid, int sig)
{
	if (pid == getpid() || pid == 0)
		return (__real_kill(pid, sig));
	nkill++;
	kill_last = pid < 0 ? -pid : pid;
	return (kill_off ? 0 : __real_kill(pid, sig));
}

int
__wrap_killpg(pid_t pg, int sig)
{
	nkill++;
	kill_last = pg;
	return (kill_off ? 0 : __real_killpg(pg, sig));
}

static pid_t fuzz_parent;
static int unblock_fail;	/* fail this many SIG_UNBLOCK calls */
int __real_sigprocmask(int, const sigset_t *, sigset_t *);

int
__wrap_sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
	if (how == SIG_UNBLOCK && unblock_fail > 0 && getpid() == fuzz_parent) {
		unblock_fail--;
		errno = EINVAL;
		return (-1);
	}
	return (__real_sigprocmask(how, set, old));
}

/* ---- packets ---- */

static int sent_rst, sent_icmp, sent_udp;
static uint32_t synack_seq;

static void
ip_hook(const void *p, size_t len)
{
	const struct ip_hdr *ip = p;
	const struct tcp_hdr *tcp;

	if (len < IP_HDR_LEN)
		return;
	if (ip->ip_p == IP_PROTO_ICMP)
		sent_icmp++;
	else if (ip->ip_p == IP_PROTO_UDP)
		sent_udp++;
	else if (ip->ip_p == IP_PROTO_TCP && len >= IP_HDR_LEN + TCP_HDR_LEN) {
		tcp = (const struct tcp_hdr *)(ip + 1);
		if (tcp->th_flags & TH_RST)
			sent_rst++;
		if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
			synack_seq = ntohl(tcp->th_seq);
	}
}

static void
feed(u_char *pkt, size_t len)
{
	struct pcap_pkthdr h;

	memset(&h, 0, sizeof(h));
	gettimeofday(&h.ts, NULL);
	h.caplen = h.len = len;
	honeyd_recv_cb((u_char *)&fuzz_iface, &h, pkt);
}

static void
tcp_pkt(uint32_t src, uint16_t sport, uint16_t dport, uint32_t seq,
    uint32_t ack, uint8_t flags)
{
	u_char pkt[14 + 20 + 20];
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct tcp_hdr *tcp = (struct tcp_hdr *)(ip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, sport, 0, 64, IP_PROTO_TCP,
	    htonl(src), htonl(DST));
	tcp_pack_hdr(tcp, sport, dport, seq, ack, flags, 8192, 0);
	ip_checksum(ip, sizeof(pkt) - 14);
	feed(pkt, sizeof(pkt));
}

/* SYN, then the ACK that completes the handshake and starts the script */
static void
tcp_open(uint32_t src, uint16_t sport, uint16_t dport)
{
	synack_seq = 0;
	tcp_pkt(src, sport, dport, 1000, 0, TH_SYN);
	tcp_pkt(src, sport, dport, 1001, synack_seq + 1, TH_ACK);
}

static void
udp_pkt(uint32_t src, uint16_t sport, uint16_t dport)
{
	u_char pkt[14 + 20 + 8 + 4];
	struct ip_hdr *ip = (struct ip_hdr *)(pkt + 14);
	struct udp_hdr *udp = (struct udp_hdr *)(ip + 1);

	memset(pkt, 0, sizeof(pkt));
	pkt[12] = 0x08;
	ip_pack_hdr(ip, 0, sizeof(pkt) - 14, sport, 0, 64, IP_PROTO_UDP,
	    htonl(src), htonl(DST));
	udp_pack_hdr(udp, sport, dport, 8 + 4);
	memcpy(udp + 1, "ping", 4);
	ip_checksum(ip, sizeof(pkt) - 14);
	feed(pkt, sizeof(pkt));
}

static struct tuple *
find(struct conlru *lru, uint32_t src, uint16_t sport)
{
	struct tuple *t;

	TAILQ_FOREACH(t, lru, next)
		if (t->ip_src == htonl(src) && t->sport == sport)
			return (t);
	return (NULL);
}

static struct command *
cmd_of(struct conlru *lru, struct tuple *t)
{
	if (t == NULL)
		return (NULL);
	return (lru == &tcplru ? &((struct tcp_con *)t)->cmd :
	    &((struct udp_con *)t)->cmd);
}

static void
end_all(void)
{
	struct tuple *t;

	while ((t = TAILQ_FIRST(&tcplru)) != NULL)
		tcp_free((struct tcp_con *)t);
	while ((t = TAILQ_FIRST(&udplru)) != NULL)
		udp_free((struct udp_con *)t);
}

/* Is pid gone or a zombie (dead but not yet reaped by someone else)? */
static int
dead(pid_t pid)
{
	char path[64], buf[256], *p;
	FILE *f;
	int z;

	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	if ((f = fopen(path, "r")) == NULL)
		return (1);
	z = 0;
	if (fgets(buf, sizeof(buf), f) != NULL &&
	    (p = strrchr(buf, ')')) != NULL)
		z = p[2] == 'Z' || p[2] == 'X';
	fclose(f);
	return (z);
}

/* Reap like the SIGCHLD handler until nchildren <= want (max 3 s) */
static void
reap_to(int want)
{
	int i;

	for (i = 0; i < 300; i++) {
		honeyd_sigchld(SIGCHLD, EV_SIGNAL, NULL);
		if (honeyd_nchildren <= want)
			return;
		usleep(10000);
	}
}

static int
wait_dead(pid_t pid)
{
	int i;

	for (i = 0; i < 300; i++) {
		honeyd_sigchld(SIGCHLD, EV_SIGNAL, NULL);
		if (dead(pid))
			return (1);
		usleep(10000);
	}
	return (0);
}

static void
script(const char *name, const char *body)
{
	char path[256];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if ((f = fopen(path, "w")) == NULL)
		abort();
	fprintf(f, "%s\n", body);
	fclose(f);
}

static void
option(const char *line)
{
	struct evbuffer *out = evbuffer_new();

	if (parse_line(out, (char *)line) == -1) {
		printf("FAIL: setup: %s", line);
		exit(1);
	}
	evbuffer_free(out);
}

/* Kill whatever the daemon left behind so the harness exits cleanly */
static void
cleanup(void)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd),
	    "pkill -KILL -f '%s/' 2>/dev/null; rm -rf '%s'", dir, dir);
	kill_off = 0;
	if (system(cmd) == -1)
		;
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

static uint32_t
procs(void)
{
	return (cmd_script_procs != NULL ? cmd_script_procs() : 0xffffffff);
}

/* ---- cases ---- */

static void
t_global(void)
{
	int i;

	option("option honeyd max_script_procs 6\n");
	option("option honeyd max_script_procs_per_source 0\n");
	for (i = 0; i < 10; i++)
		udp_pkt(0x0b000001 + i, 4000, 53);
	for (i = 0; i < 10; i++)
		tcp_open(0x0d000001 + i, 5000, 80);
	reap_to(-1);
	printf("10 UDP and 10 TCP sources, cap 6: %d live scripts\n",
	    honeyd_nchildren);
	check(honeyd_nchildren == 6, "global cap holds live scripts at 6");

	sent_rst = 0;
	tcp_open(0x0c000001, 5000, 80);
	printf("TCP at cap: %d RST, flow %s\n", sent_rst,
	    find(&tcplru, 0x0c000001, 5000) ? "kept" : "gone");
	check(sent_rst == 1 && find(&tcplru, 0x0c000001, 5000) == NULL &&
	    honeyd_nchildren == 6, "TCP connection at cap reset, no script");

	end_all();
	reap_to(0);
	tcp_open(0x0c000001, 5001, 80);
	check(honeyd_nchildren == 1, "TCP script starts once slots free");
}

static void
t_source(void)
{
	int i, round, ok = 1;

	for (round = 0; round < 3; round++) {
		for (i = 0; i < 40; i++)
			udp_pkt(0x0b000001, 4000 + round * 100 + i, 53);
		printf("round %d: 40 flows from one source, %d live\n",
		    round, honeyd_nchildren);
		if (honeyd_nchildren != 32)
			ok = 0;
		end_all();
		reap_to(0);
		if (honeyd_nchildren != 0)
			ok = 0;
	}
	check(ok, "one source capped at 32 live scripts, slots come back");
	udp_pkt(0x0b000002, 4000, 53);
	check(honeyd_nchildren == 1, "other source unaffected");
}

static void
t_tcpkill(void)
{
	struct tuple *t;
	pid_t pid;

	tcp_open(0x0b000001, 5000, 81);
	t = find(&tcplru, 0x0b000001, 5000);
	pid = t ? cmd_of(&tcplru, t)->pid : -1;
	check(pid > 0, "TCP script started");
	if (pid <= 0)
		return;
	usleep(100000);
	check(!dead(pid), "script running while flow open");
	tcp_free((struct tcp_con *)t);
	check(wait_dead(pid), "script ignoring stdin killed when flow ends");
	reap_to(0);
	check(honeyd_nchildren == 0, "script reaped");
}

static void
t_grandchild(void)
{
	struct tuple *t;
	char path[256];
	FILE *f;
	pid_t pid;
	int gc = 0, i;

	udp_pkt(0x0b000001, 4000, 54);
	t = find(&udplru, 0x0b000001, 4000);
	pid = t ? cmd_of(&udplru, t)->pid : -1;
	check(pid > 0, "UDP script started");
	if (pid <= 0)
		return;
	snprintf(path, sizeof(path), "%s/gc.%d", dir, (int)pid);
	for (i = 0; i < 300 && gc <= 0; i++) {
		if ((f = fopen(path, "r")) != NULL) {
			if (fscanf(f, "%d", &gc) != 1)
				gc = 0;
			fclose(f);
		}
		usleep(10000);
	}
	check(gc > 0 && !dead(gc), "background grandchild running");
	if (gc <= 0)
		return;
	udp_free((struct udp_con *)t);
	check(wait_dead(pid), "script gone after flow ends");
	check(wait_dead(gc), "grandchild gone after flow ends");
}

static void
t_reaped(void)
{
	struct tuple *t;
	pid_t pid;

	udp_pkt(0x0b000001, 4000, 55);
	t = find(&udplru, 0x0b000001, 4000);
	pid = t ? cmd_of(&udplru, t)->pid : -1;
	check(pid > 0, "UDP script started");
	if (pid <= 0)
		return;
	reap_to(0);
	check(honeyd_nchildren == 0, "script exited and was reaped");
	check(procs() == 0, "reaped script released from the pid map");
	nkill = 0;
	udp_free((struct udp_con *)t);
	printf("kill calls after reap: %d\n", nkill);
	check(nkill == 0, "no signal sent to a reaped pid");
}

static void
t_nchildren(void)
{
	int i;

	option("option honeyd max_script_procs 8\n");
	for (i = 0; i < 6; i++)
		udp_pkt(0x0b000001 + i, 4000, 53);
	for (i = 0; i < 6; i++)
		tcp_open(0x0c000001 + i, 5000, i & 1 ? 81 : 80);
	printf("12 flows, cap 8: %d live\n", honeyd_nchildren);
	end_all();
	reap_to(0);
	printf("all flows ended: honeyd_nchildren %d, map %u\n",
	    honeyd_nchildren, procs());
	check(honeyd_nchildren == 0, "honeyd_nchildren back to 0");
	check(procs() == 0, "pid map empty");
}

static void
t_sigchld(void)
{
	sigset_t cur;

	unblock_fail = 1;
	udp_pkt(0x0b000001, 4000, 53);
	check(unblock_fail == 0, "SIGCHLD unblock failure injected");
	__real_sigprocmask(SIG_BLOCK, NULL, &cur);
	check(!sigismember(&cur, SIGCHLD), "SIGCHLD unblocked after failure");
	check(honeyd_nchildren == 1, "script counted");
	end_all();
	reap_to(0);
	check(honeyd_nchildren == 0, "script reaped");
}

static void
t_seqpacket(void)
{
	struct tuple *t;
	pid_t pid;
	int i;

	kill_off = 1;
	sent_udp = 0;
	udp_pkt(0x0b000001, 4000, 53);
	t = find(&udplru, 0x0b000001, 4000);
	pid = t ? cmd_of(&udplru, t)->pid : -1;
	check(pid > 0, "UDP script started");
	if (pid <= 0)
		return;
	for (i = 0; i < 300 && sent_udp == 0; i++) {
		event_base_loop(libevent_base, EVLOOP_NONBLOCK);
		usleep(10000);
	}
	check(sent_udp == 1, "datagram echoed by script");
	udp_free((struct udp_con *)t);
	check(wait_dead(pid), "UDP script sees EOF and exits without a kill");
	kill_off = 0;
}

static void
t_udpdrop(void)
{
	uint32_t r0;

	option("option honeyd max_script_procs 1\n");
	udp_pkt(0x0b000001, 4000, 53);
	check(honeyd_nchildren == 1, "first UDP script started");
	r0 = &cmd_script_refused != NULL ? cmd_script_refused : 0;
	sent_icmp = sent_udp = 0;
	udp_pkt(0x0b000002, 4000, 53);
	udp_pkt(0x0b000002, 4000, 53);
	printf("at cap: live %d, icmp %d, udp %d\n", honeyd_nchildren,
	    sent_icmp, sent_udp);
	check(honeyd_nchildren == 1, "no script for UDP flow at cap");
	check(sent_icmp == 0 && sent_udp == 0, "dropped quietly");
	check(&cmd_script_refused != NULL && cmd_script_refused - r0 == 1,
	    "one refusal counted, later datagrams just dropped");
}

static void
t_disabled(void)
{
	int i;

	option("option honeyd max_script_procs 0\n");
	option("option honeyd max_script_procs_per_source 0\n");
	for (i = 0; i < 40; i++)
		udp_pkt(0x0b000001, 4000 + i, 53);
	printf("caps 0, 40 flows from one source: %d live, map %u\n",
	    honeyd_nchildren, procs());
	check(honeyd_nchildren == 40, "no cap with 0");
	check(procs() == 40, "scripts still tracked for cleanup");
	end_all();
	reap_to(0);
	check(honeyd_nchildren == 0 && procs() == 0, "all reaped");
}

static void
t_udpshare(void)
{
	int i, tcp = 0;

	option("option honeyd max_script_procs 8\n");
	option("option honeyd max_script_procs_per_source 0\n");
	/* a spoofer sends one datagram from each of many sources */
	for (i = 0; i < 50; i++)
		udp_pkt(0x0b000001 + i, 4000, 53);
	printf("50 spoofed UDP sources, cap 8: %d live scripts, udp %u\n",
	    honeyd_nchildren,
	    cmd_script_udp_procs != NULL ? cmd_script_udp_procs() : 0);
	check(honeyd_nchildren == 4, "UDP scripts stop at half the cap");

	sent_rst = 0;
	for (i = 0; i < 4; i++) {
		tcp_open(0x0c000001 + i, 5000, 80);
		if (find(&tcplru, 0x0c000001 + i, 5000) != NULL)
			tcp++;
	}
	printf("real TCP flows: %d of 4 started, %d RST\n", tcp, sent_rst);
	check(tcp == 4 && sent_rst == 0 && honeyd_nchildren == 8,
	    "TCP scripts still start while spoofed UDP holds its share");
	tcp_open(0x0c000009, 5000, 80);
	check(sent_rst == 1, "TCP at the full cap is still reset");
}

static const struct {
	const char *name;
	void (*fn)(void);
} cases[] = {
	{ "global", t_global }, { "source", t_source },
	{ "tcpkill", t_tcpkill }, { "grandchild", t_grandchild },
	{ "reaped", t_reaped }, { "nchildren", t_nchildren },
	{ "sigchld", t_sigchld }, { "seqpacket", t_seqpacket },
	{ "udpdrop", t_udpdrop }, { "disabled", t_disabled },
	{ "udpshare", t_udpshare },
};

int
main(int argc, char **argv)
{
	char conf[2048];
	size_t i;

	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc != 2 || mkdtemp(dir) == NULL)
		return (2);
	fuzz_parent = getpid();
	script("cat.sh", "exec cat");
	script("ignore.sh", "exec sleep 1000");
	snprintf(conf, sizeof(conf), "sleep 1000 </dev/null >/dev/null 2>&1 &"
	    " echo $! > %s/gc.$$\nexec cat", dir);
	script("grand.sh", conf);
	script("exit.sh", "exit 0");
	snprintf(conf, sizeof(conf),
	    "create default\n"
	    "set default default tcp action block\n"
	    "set default default udp action block\n"
	    "create linux\n"
	    "set linux personality \"Linux 2.6.32\"\n"
	    "set linux default tcp action reset\n"
	    "add linux tcp port 80 \"sh %s/cat.sh\"\n"
	    "add linux tcp port 81 \"sh %s/ignore.sh\"\n"
	    "add linux udp port 53 \"sh %s/cat.sh\"\n"
	    "add linux udp port 54 \"sh %s/grand.sh\"\n"
	    "add linux udp port 55 \"sh %s/exit.sh\"\n"
	    "bind 10.0.0.2 linux\n", dir, dir, dir, dir, dir);
	fuzz_honeyd_init(conf);
	honeyd_uid = getuid();
	honeyd_gid = getgid();
	fuzz_ip_send_hook = ip_hook;
	fuzz_exec_path = "/bin/sh";
	fuzz_real_exec = 1;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		if (strcmp(argv[1], cases[i].name) == 0)
			break;
	if (i == sizeof(cases) / sizeof(cases[0]))
		return (2);
	printf("case %s\n", argv[1]);
	cases[i].fn();
	cleanup();
	if (fails) {
		printf("FAIL: %d checks\n", fails);
		return (1);
	}
	printf("PASS: %s\n", argv[1]);
	return (0);
}
