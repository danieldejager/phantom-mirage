#
# Honeyd regression test harness (Python 3, #36).
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# Needs root (raw sockets, routes), python3-dpkt and iproute2.  Packets
# are sent with a raw IP socket to two test networks routed over lo
# (192.0.2.0/24 and 192.18.0.0/15); honeyd answers on lo; the replies
# are captured with an AF_PACKET socket and written in a stable text
# format that is compared with the *.output.* golden files.
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
import time

import dpkt

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
NETS = (("192.0.2.0", 24), ("192.18.0.0", 15))


def _in_net(addr, net):
    a = struct.unpack("!I", addr)[0]
    n = struct.unpack("!I", socket.inet_aton(net[0]))[0]
    mask = (0xffffffff << (32 - net[1])) & 0xffffffff
    return (a & mask) == (n & mask)


def describe(obj):
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
        return "ICMP(type=%d, code=%d, sum=%d, data=%s)" % (
            obj.type, obj.code, obj.sum, inner)
    if isinstance(obj, dpkt.tcp.TCP):
        return ("TCP(sport=%d, dport=%d, seq=%d, ack=%d, flags=0x%02x, "
                "win=%d, sum=%d, opts=%r, data=%r)" % (
                    obj.sport, obj.dport, obj.seq, obj.ack, obj.flags,
                    obj.win, obj.sum, bytes(obj.opts), bytes(obj.data)))
    if isinstance(obj, dpkt.udp.UDP):
        return "UDP(sport=%d, dport=%d, sum=%d, data=%r)" % (
            obj.sport, obj.dport, obj.sum, bytes(obj.data))
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

    def Send(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        for pkt in self.packets:
            # dpkt fills in the IP and transport checksums when sum == 0
            data = bytes(pkt)
            s.sendto(data, (socket.inet_ntoa(pkt.dst), 0))
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
        self.interface = "lo"
        self.honeyd = None
        if not os.path.exists(self.cmd):
            sys.stderr.write('Cannot find honeyd program "%s"\n' % self.cmd)
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
        if not os.path.exists(self.config):
            sys.stderr.write('Configuration file "%s" does not exist, '
                             'aborting.\n' % self.config)
            sys.exit(1)
        if self.testconfig() != 0:
            sys.stderr.write('Cannot use file "%s", aborting.\n' % self.config)
            sys.exit(1)
        if self.VerifyRoute() != 0:
            sys.stderr.write("There was an error adding the route\n")
            sys.exit(1)
        sys.stderr.write('Testing "%s" behavior:\n' % self.testname)

    # --- routes over lo -------------------------------------------------
    def _ip(self, *args):
        return subprocess.call(["ip", "route"] + list(args),
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

    def VerifyRoute(self):
        for net, bits in NETS:
            if self._ip("replace", "%s/%d" % (net, bits), "dev", "lo"):
                return 1
        return 0

    def RemoveAllRoutes(self):
        for net, bits in NETS:
            self._ip("del", "%s/%d" % (net, bits), "dev", "lo")

    # --- honeyd ---------------------------------------------------------
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
        self.cap.bind((self.interface, 0))
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
            # lo delivers every frame twice (outgoing + host): keep one
            if addr[2] == PACKET_OUTGOING:
                continue
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
            self.capfile.write("ID=%d\n" % ip.id)
            self.capfile.write("TTL=%d\n" % ip.ttl)
            self.capfile.write("DATA=%s\n\n" % describe(ip.data))

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

        test.Send()
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
        # 3 = output mismatch (known failing, see IMPORTANT_NOTES.txt);
        # a crashed harness exits 1 via the uncaught exception.
        sys.exit(3)
