#!/usr/bin/env python3
#
# mDNS responder: answers A queries for <allocated name>.local with this
# honeypot's address. Network I/O is bytes on stdin/stdout; malformed or
# truncated queries get no reply.
#
# argv[2] is a config file whose first line is "<key> <names db path>".

import os
import socket
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.append("/usr/share/honeyd/scripts/lib/")
sys.path.append(os.path.join(here, "..", "..", "lib"))
sys.path.insert(0, here)
from names import AddNameAllocation  # noqa: E402
import dns  # noqa: E402


def respond(data, hostname, ip):
    packet = dns.DNSHeader()
    try:
        packet.readPacket(data)
    except dns.Truncated:
        return b""
    if packet.qr != dns.QR_QUERY or packet.qdcount == 0:
        return b""
    for question in packet.questions:
        if question.qname.upper() == hostname:
            reply = dns.DNSHeader()
            reply.transactionID = packet.transactionID
            reply.flags = 0x8400
            rr = dns.DNSResourceRecord()
            rr.name = hostname
            rr.type = 1
            rr.dataclass = 0x8001
            rr.ttl = 120
            rr.rdata = socket.inet_aton(ip)
            reply.answers.append(rr)
            return reply.packedString()
    return b""


def main():
    ip = os.getenv("PHANTOM_MIRAGE_TEMPLATE_NAME", os.getenv("HONEYD_TEMPLATE_NAME", ""))
    honeyd_home = os.getenv("PHANTOM_MIRAGE_HOME", os.getenv("HONEYD_HOME", ""))
    with open(sys.argv[2]) as fd:
        names_file = fd.readline().split(" ", 1)[1].rstrip("\n")
    our_name = AddNameAllocation(honeyd_home + names_file, ip).upper()
    if our_name == "":
        sys.stderr.write("Unable to get mdns name\n")
        return
    try:
        socket.inet_aton(ip)
    except OSError:
        return
    hostname = our_name.encode("ascii", "ignore") + b".LOCAL"
    # UDP: one datagram per write; stdin may stay open, so do not wait
    # for EOF.
    reply = respond(os.read(0, 65535), hostname, ip)
    if reply:
        sys.stdout.buffer.write(reply)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
