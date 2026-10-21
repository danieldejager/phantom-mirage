#
# Phantom Mirage regression test harness (Python 3, #36).
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# Needs root (AF_PACKET, veth, routes), python3-dpkt and iproute2.
# Probes from 192.0.2.0/24 to 192.18.0.0/15 are injected on a veth pair
# (see HD_IF/TEST_IF below), phantom-mirage's replies are captured on the same
# pair and written in a stable text format that is compared with the
# *.output.* golden files (see IMPORTANT_NOTES.txt for what is masked).
#
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import dpkt

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
PACKET_OUTGOING = 4
NETS = (("192.0.2.0", 24), ("192.18.0.0", 15))

# The suite runs over a veth pair rather than lo, so every probe and
# reply is seen exactly once (on Linux lo phantom-mirage saw each probe twice).
#   HD_IF     phantom-mirage's end (10.250.0.2/30)
#   TEST_IF   our end (10.250.0.1/30)
# Probes are injected as Ethernet frames on TEST_IF straight to HD_IF's
# MAC. Replies reach TEST_IF either directly from phantom-mirage (router mode,
# config.2) or via the kernel's route for 192.0.2.0/24 out HD_IF (plain
# mode, phantom-mirage sends through a raw IP socket). 192.0.2.0/24 is not
# configured anywhere: an ARP responder below answers who-has for it.
# Anything the kernel would forward from either end hits a blackhole
# (policy rule iif hdt0/hdt1 -> table 74), so probes and replies never
# leave the pair or loop back; this works even with a read-only
# /proc/sys and forwarding enabled (CI containers).
HD_IF = "hdt0"
TEST_IF = "hdt1"


def _in_net(addr, net):
    a = struct.unpack("!I", addr)[0]
    n = struct.unpack("!I", socket.inet_aton(net[0]))[0]
    mask = (0xffffffff << (32 - net[1])) & 0xffffffff
    return (a & mask) == (n & mask)


def _cksum_ok(ip):
    """True if the transport checksum of a captured packet is valid."""
    l4 = ip.data
    raw = bytes(ip)[ip.hl * 4:ip.len]
    if isinstance(l4, dpkt.icmp.ICMP):
        return dpkt.in_cksum(raw) == 0
    if isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        pseudo = struct.pack("!4s4sxBH", ip.src, ip.dst, ip.p, len(raw))
        return dpkt.in_cksum(pseudo + raw) == 0
    return True


def _tcp_opts(opts):
    """TCP options with the timestamp values masked (wall clock)."""
    out = []
    for o, d in dpkt.tcp.parse_opts(bytes(opts)):
        if o == dpkt.tcp.TCP_OPT_TIMESTAMP:
            out.append("TS")
        elif o in (dpkt.tcp.TCP_OPT_NOP, dpkt.tcp.TCP_OPT_EOL):
            out.append({1: "NOP", 0: "EOL"}[o])
        else:
            out.append("%d:%s" % (o, bytes(d).hex()))
    return ",".join(out)


def describe(obj, sum_text=None):
    """Version-independent description of a dpkt layer (the Python 2
    harness used repr(), which changed between dpkt releases)."""
    if isinstance(obj, (bytes, bytearray)):
        return repr(bytes(obj))
    if isinstance(obj, dpkt.icmp.ICMP):
        inner = obj.data
        if isinstance(inner, dpkt.icmp.ICMP.Echo):
            inner = "Echo(id=%d, seq=%d, data=%r)" % (inner.id, inner.seq,
                                                      bytes(inner.data))
        else:
            inner = describe(inner)
        return "ICMP(type=%d, code=%d, sum=%s, data=%s)" % (
            obj.type, obj.code, sum_text or obj.sum, inner)
    if isinstance(obj, dpkt.tcp.TCP):
        return ("TCP(sport=%d, dport=%d, seq=%d, ack=%d, flags=0x%02x, "
                "win=%d, sum=%s, opts=%s, data=%r)" % (
                    obj.sport, obj.dport, obj.seq, obj.ack, obj.flags,
                    obj.win, sum_text or obj.sum, _tcp_opts(obj.opts),
                    bytes(obj.data)))
    if isinstance(obj, dpkt.udp.UDP):
        return "UDP(sport=%d, dport=%d, sum=%s, data=%r)" % (
            obj.sport, obj.dport, sum_text or obj.sum, bytes(obj.data))
    return "%s(%r)" % (type(obj).__name__, bytes(obj))


class Test:
    def __init__(self):
        self.name = "<Unknown>"
        self.expect = None
        self.packets = []
        self.Setup()

    def Expect(self):
        return self.expect

    def Name(self):
        return self.name

    def Send(self, dst_mac, src_mac):
        """Inject the probes as Ethernet frames on TEST_IF, addressed to
        phantom-mirage's interface (no kernel ARP/routing on the send path)."""
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((TEST_IF, 0))
        for pkt in self.packets:
            # dpkt fills in the IP and transport checksums when sum == 0
            s.send(bytes(dpkt.ethernet.Ethernet(
                dst=dst_mac, src=src_mac,
                type=dpkt.ethernet.ETH_TYPE_IP, data=pkt)))
            time.sleep(0.10)
        s.close()


class regress:
    def __init__(self, name, cmd, config, debug=0):
        self.testname = name
        self.debug = debug
        self.config = os.path.join(os.getcwd(), config)
        self.cmd = cmd
        self.oktests = 0
        self.runtests = 0
        self.generate = 0
        self.interface = HD_IF
        self.honeyd = None
        if not os.path.exists(self.cmd):
            sys.stderr.write('Cannot find phantom-mirage program "%s"\n' % self.cmd)
            sys.exit(1)
        top = os.path.abspath(os.path.join(os.path.dirname(self.cmd)))
        # Use the source tree's data files, not installed ones
        self.args = [self.cmd, "--disable-webserver", "-R", "1", "-d",
                     "-i", self.interface,
                     "-p", os.path.join(top, "nmap-os-db"),
                     "-x", os.path.join(top, "xprobe2.conf"),
                     "-a", os.path.join(top, "nmap.assoc"),
                     "-0", os.path.join(top, "pf.os"),
                     "-m", os.path.join(top, "nmap-mac-prefixes")]
        # e.g. "-u 0 -g 0" inside an unprivileged user+net namespace
        self.args += os.environ.get("REGRESS_PHANTOM_MIRAGE_ARGS", "").split()
        if not os.path.exists(self.config):
            sys.stderr.write('Configuration file "%s" does not exist, '
                             'aborting.\n' % self.config)
            sys.exit(1)
        # Without a routing topology or template MACs phantom-mirage sends replies
        # through a raw IP socket. Linux then replaces an IP ID of 0 with a
        # random one unless DF is set, so those IDs are masked below. With
        # routing/ethernet phantom-mirage writes frames itself and IDs are exact.
        with open(self.config) as f:
            self.raw_ip_path = not re.search(r"^\s*route\s|\bethernet\b",
                                             f.read(), re.M)
        if self.VerifyRoute() != 0:
            sys.stderr.write("There was an error setting up %s/%s\n" %
                             (HD_IF, TEST_IF))
            self.RemoveAllRoutes()
            sys.exit(1)
        if self.testconfig() != 0:
            sys.stderr.write('Cannot use file "%s", aborting.\n' % self.config)
            self.RemoveAllRoutes()
            sys.exit(1)
        sys.stderr.write('Testing "%s" behavior:\n' % self.testname)

    # --- veth pair and routes -------------------------------------------
    def _ip(self, *args):
        return subprocess.call(["ip", "route"] + list(args),
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

    def _cmd(self, *args):
        return subprocess.call(list(args), stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

    def VerifyRoute(self):
        self.RemoveAllRoutes()
        steps = [
            ("ip", "link", "add", HD_IF, "type", "veth", "peer", "name",
             TEST_IF),
            # no IPv6 addresses -> no ND/MLD noise on the wire
            ("ip", "link", "set", HD_IF, "addrgenmode", "none"),
            ("ip", "link", "set", TEST_IF, "addrgenmode", "none"),
            ("ip", "addr", "add", "10.250.0.2/30", "dev", HD_IF),
            ("ip", "addr", "add", "10.250.0.1/30", "dev", TEST_IF),
            ("ip", "link", "set", HD_IF, "up"),
            ("ip", "link", "set", TEST_IF, "up"),
            ("ip", "route", "replace", "192.0.2.0/24", "dev", HD_IF),
            ("ip", "route", "replace", "blackhole", "default", "table", "74"),
            ("ip", "rule", "add", "iif", HD_IF, "lookup", "74", "pref", "74"),
            ("ip", "rule", "add", "iif", TEST_IF, "lookup", "74", "pref", "75"),
        ]
        for st in steps:
            if self._cmd(*st):
                sys.stderr.write("failed: %s\n" % " ".join(st))
                return 1
        self.test_mac = self._mac(TEST_IF)
        self.hd_mac = self._mac(HD_IF)
        self._start_arp_responder()
        return 0

    @staticmethod
    def _mac(ifname):
        with open("/sys/class/net/%s/address" % ifname) as f:
            return bytes.fromhex(f.read().strip().replace(":", ""))

    def RemoveAllRoutes(self):
        self._cmd("ip", "rule", "del", "pref", "74")
        self._cmd("ip", "rule", "del", "pref", "75")
        self._cmd("ip", "route", "flush", "table", "74")
        self._cmd("ip", "link", "del", HD_IF)

    def _start_arp_responder(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(ETH_P_ARP))
        s.bind((TEST_IF, ETH_P_ARP))

        def loop():
            while True:
                try:
                    frame = s.recv(2048)
                except OSError:     # interface removed at teardown
                    return
                eth = dpkt.ethernet.Ethernet(frame)
                arp = eth.data
                if (not isinstance(arp, dpkt.arp.ARP) or
                        arp.op != dpkt.arp.ARP_OP_REQUEST or
                        not _in_net(arp.tpa, NETS[0])):
                    continue
                rep = dpkt.arp.ARP(op=dpkt.arp.ARP_OP_REPLY,
                                   sha=self.test_mac, spa=arp.tpa,
                                   tha=arp.sha, tpa=arp.spa)
                s.send(bytes(dpkt.ethernet.Ethernet(
                    dst=eth.src, src=self.test_mac,
                    type=dpkt.ethernet.ETH_TYPE_ARP, data=rep)))

        threading.Thread(target=loop, daemon=True).start()

    # --- phantom-mirage ---------------------------------------------------------
    def testconfig(self):
        cmd = self.args + ["--verify-config", "-f", self.config,
                           "192.18.0.0/15"]
        if self.debug:
            sys.stderr.write("Running %s\n" % " ".join(cmd))
        return subprocess.call(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

    def start_honeyd(self):
        cmd = self.args + ["-f", self.config, "192.18.0.0/15"]
        self.honeyd_log = tempfile.TemporaryFile()
        self.honeyd = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                       stdout=self.honeyd_log,
                                       stderr=subprocess.STDOUT)
        time.sleep(2)

    def stop_honeyd(self):
        if self.honeyd is None:
            return
        self.honeyd.send_signal(signal.SIGINT)
        try:
            self.honeyd.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.honeyd.kill()
            self.honeyd.wait()
        if self.debug:
            self.honeyd_log.seek(0)
            sys.stderr.write(self.honeyd_log.read().decode(errors="replace"))
        self.honeyd_log.close()
        self.honeyd = None

    # --- capture --------------------------------------------------------
    def start_pcap(self):
        (fd, self.dpktfile) = tempfile.mkstemp()
        self.capfile = os.fdopen(fd, "w")
        self.cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(ETH_P_ALL))
        self.cap.bind((TEST_IF, 0))
        self.cap.setblocking(False)

    def drain_pcap(self, until):
        while True:
            left = until - time.time()
            if left <= 0:
                return
            r, _, _ = select.select([self.cap], [], [], left)
            if not r:
                return
            pkt, addr = self.cap.recvfrom(65535)
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            # Same as the old BPF filter: one end in each test network
            if not ((_in_net(ip.src, NETS[0]) and _in_net(ip.dst, NETS[1])) or
                    (_in_net(ip.src, NETS[1]) and _in_net(ip.dst, NETS[0]))):
                continue
            self.capfile.write("SRC=%s\n" % socket.inet_ntoa(ip.src))
            self.capfile.write("DST=%s\n" % socket.inet_ntoa(ip.dst))
            if (self.raw_ip_path and _in_net(ip.src, NETS[1]) and
                    not ip.df):
                self.capfile.write("ID=<kernel>\n")
            else:
                self.capfile.write("ID=%d\n" % ip.id)
            self.capfile.write("TTL=%d\n" % ip.ttl)
            # Replies: print checksum validity, not the value (it covers
            # the masked TCP timestamps)
            sum_text = None
            if _in_net(ip.src, NETS[1]):
                sum_text = "ok" if _cksum_ok(ip) else "BAD"
            self.capfile.write("DATA=%s\n\n" % describe(ip.data, sum_text))

    def stop_pcap(self):
        self.drain_pcap(time.time() + 1)
        self.cap.close()
        self.capfile.close()
        os.chmod(self.dpktfile, 0o644)

    # --- running --------------------------------------------------------
    def run(self, test):
        self.start_pcap()
        self.start_honeyd()
        self.drain_pcap(time.time() + 0.1)
        self.outputfile = test.Expect()
        sys.stderr.write("\tRunning %s: " % test.Name())
        sys.stderr.flush()
        self.runtests += 1

        test.Send(self.hd_mac, self.test_mac)
        self.drain_pcap(time.time() + 1)
        self.stop_honeyd()
        self.stop_pcap()

        if self.generate:
            os.replace(self.dpktfile, self.outputfile)
            sys.stderr.write("Generated output file '%s'\n" % self.outputfile)
            return
        if self.compare():
            sys.stderr.write("OK\n")
            self.oktests += 1
            if not self.debug:
                os.remove(self.dpktfile)
        else:
            sys.stderr.write("FAILED (got %s, expected %s)\n" %
                             (self.dpktfile, self.outputfile))
            subprocess.call(["diff", "-u", self.outputfile, self.dpktfile],
                            stdout=sys.stderr)

    def compare(self):
        if not os.path.exists(self.outputfile):
            sys.stderr.write('Expected results file "%s" not found\n' %
                             self.outputfile)
            return False
        with open(self.outputfile) as a, open(self.dpktfile) as b:
            return a.read() == b.read()

    def finish(self):
        self.RemoveAllRoutes()
        if self.generate:
            return
        if self.runtests == self.oktests:
            sys.stderr.write("  OK (%d)\n" % self.oktests)
            sys.exit(0)
        sys.stderr.write("  FAILED (%u/%u)\n" %
                         (self.runtests - self.oktests, self.runtests))
        # 3 = output mismatch; a crashed harness exits 1 via the uncaught
        # exception.
        sys.exit(3)
