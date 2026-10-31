/*
 * PM-SCR-139: the udp_new() path (subsystems, config helpers) is counted
 * against the global UDP cap and never evicts the flow it is creating.
 * Evicting a flow with a command attached, and a subsystem flow whose
 * port points back at it, runs udp_free() like the idle timer: the
 * command events are gone and the subsystem port is released, with no
 * use after free when the event loop runs afterwards.
 */
#include <sys/socket.h>
#include <unistd.h>
#include "udpflow.h"
#include "subsystem.h"

extern struct callback cb_udp;
void cmd_ready_fd(struct command *, struct callback *, void *);
struct port *port_insert(struct template *, int, int, struct action *);
struct port *port_find(struct template *, int, int);

#define CAP	4
#define DST	0x0a000002

static const char config[] =
	"option honeyd max_udp_flows 4\n"
	"create default\n"
	"set default default udp action block\n"
	"create linux\n"
	"set linux default udp action reset\n"
	"add linux udp port 53 open\n"
	"bind 10.0.0.2 linux\n";

static struct udp_con *
subsys_flow(struct template *tmpl, uint32_t src, uint16_t sport,
    uint16_t dport)
{
	struct ip_hdr ip;
	struct udp_hdr udp;

	memset(&ip, 0, sizeof(ip));
	ip.ip_src = htonl(src);
	ip.ip_dst = htonl(DST);
	udp.uh_sport = htons(sport);
	udp.uh_dport = htons(dport);
	return (udp_new(&ip, &udp, INITIATED_BY_SUBSYSTEM));
}

int
main(void)
{
	struct template *tmpl;
	struct udp_con *c, *s, *n;
	struct action act;
	struct port *port;
	int sv[2];

	setvbuf(stdout, NULL, _IONBF, 0);
	fuzz_honeyd_init(config);
	if ((tmpl = template_find("10.0.0.2")) == NULL) {
		printf("FAIL: template not found\n");
		return (1);
	}

	/* Oldest: a network flow with a command attached and data pending */
	send_udp(0x0b000001, 1024, DST);
	if ((c = find_udp(0x0b000001, 1024)) == NULL) {
		printf("FAIL: no flow\n");
		return (1);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		abort();
	c->cmd.pfd = sv[0];
	c->cmd.perrfd = -1;
	cmd_ready_fd(&c->cmd, &cb_udp, c);
	event_add(c->cmd.pread, NULL);
	if (write(sv[1], "x", 1) != 1)
		abort();

	/* Next: a subsystem flow holding a subsystem port */
	memset(&act, 0, sizeof(act));
	act.status = PORT_OPEN;
	port = port_insert(tmpl, IP_PROTO_UDP, 5353, &act);
	port->subtmpl = tmpl;
	s = subsys_flow(tmpl, 0x0b000002, 2000, 5353);
	s->tmpl = template_ref(tmpl);
	s->port = port;
	port->sub_conport = &s->port;

	send_udp(0x0b000003, 1024, DST);
	send_udp(0x0b000004, 1024, DST);
	check(live_udp() == CAP, "4 flows live at the cap");

	/* Overflow from the network: the command flow goes */
	send_udp(0x0b000005, 1024, DST);
	check(find_udp(0x0b000001, 1024) == NULL, "command flow evicted");
	/* Its pending read must not fire on freed state */
	if (find_udp(0x0b000001, 1024) == NULL)
		fuzz_drain_events();

	/* Overflow from udp_new(): the subsystem flow goes, not the new one */
	n = subsys_flow(tmpl, 0x0b000006, 2001, 53);
	check(n != NULL && find_udp(0x0b000006, 2001) == n,
	    "udp_new flow kept");
	check(find_udp(0x0b000002, 2000) == NULL, "subsystem flow evicted");
	check(port_find(tmpl, IP_PROTO_UDP, 5353) == NULL,
	    "subsystem port released");
	check(live_udp() == CAP, "still 4 live");
	check(&honeyd_nudp != NULL && honeyd_nudp == CAP,
	    "udp_new flow counted");
	close(sv[1]);

	if (fails)
		return (1);
	printf("PASS: udp_cap_ref\n");
	return (0);
}
