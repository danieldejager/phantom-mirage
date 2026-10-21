/*
 * libFuzzer harness: one Ethernet frame into honeyd_recv_cb() on a fake
 * interface (10.0.0.1/24), as if captured by pcap. Covers ARP, IPv4,
 * TCP/UDP/ICMP handling, fragments, GRE and routing (issue #38).
 */
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "fuzz_common.h"

void honeyd_recv_cb(u_char *, const struct pcap_pkthdr *, const u_char *);

/* No scripts, subsystems or proxies: nothing outside the process */
static const char config[] =
	"create default\n"
	"set default default tcp action block\n"
	"set default default udp action block\n"
	"set default default icmp action open\n"
	"create linux\n"
	"set linux personality \"Linux 2.6.32\"\n"
	"set linux default tcp action reset\n"
	"set linux default udp action reset\n"
	"add linux tcp port 22 open\n"
	"add linux tcp port 80 open\n"
	"add linux udp port 53 open\n"
	"add linux udp port 161 block\n"
	"create win\n"
	"set win personality \"Microsoft Windows XP Professional SP1\"\n"
	"set win default tcp action reset\n"
	"add win tcp port 445 open\n"
	"set win droprate in 0\n"
	"bind 10.0.0.2 linux\n"
	"bind 10.0.0.3 win\n"
	"bind 10.1.0.2 linux\n"
	"route entry 10.0.0.1 network 10.0.0.0/16\n"
	"route 10.0.0.1 link 10.0.0.0/24\n"
	"route 10.0.0.1 add net 10.1.0.0/24 10.1.0.1 latency 0ms loss 0\n"
	"route 10.1.0.1 link 10.1.0.0/24\n";

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fuzz_honeyd_init(config);
	return (0);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct pcap_pkthdr hdr;
	u_char *pkt;

	if (size > 65535 + 14)
		return (0);

	/* Exact-size copy: honeyd may rewrite the packet in place, and
	 * ASan must see any read past the captured length. */
	if ((pkt = malloc(size ? size : 1)) == NULL)
		return (0);
	memcpy(pkt, data, size);

	memset(&hdr, 0, sizeof(hdr));
	gettimeofday(&hdr.ts, NULL);
	hdr.caplen = hdr.len = size;

	honeyd_recv_cb((u_char *)&fuzz_iface, &hdr, pkt);
	fuzz_drain_events();

	free(pkt);
	return (0);
}
