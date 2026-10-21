# Minimal DNS message parsing/writing for the mDNS honeypot (bytes).
import struct

# From RFC1035, meant to be & with m_flags
BITMASK_QR = 1 << 15
BITMASK_OPCODE = 0xF << 11
BITMASK_AA = 1 << 10
BITMASK_TC = 1 << 9
BITMASK_RD = 1 << 8

BITMASK_RA = 1 << 7
BITMASK_RCODE = 0xF

QR_QUERY = 0
QR_RESPONSE = 1

OPCODE_QUERY = 0
OPCODE_IQUERY = 1
OPCODE_STATUS = 2

RCODE_NO_ERROR = 0
RCODE_FORMAT_ERROR = 1
RCODE_SERVER_FAILURE = 2
RCODE_NAME_ERROR = 3
RCODE_REFUSED = 4


class Truncated(Exception):
    pass


class DNSHeader(object):
    def __init__(self):
        self.transactionID = 0
        self.flags = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0
        self.questions = []
        self.answers = []

    @property
    def qr(self):
        return int(self.flags & BITMASK_QR != 0)

    @property
    def opcode(self):
        return (self.flags & BITMASK_OPCODE) >> 11

    @property
    def aa(self):
        return int(self.flags & BITMASK_AA != 0)

    @property
    def tc(self):
        return int(self.flags & BITMASK_TC != 0)

    @property
    def rd(self):
        return int(self.flags & BITMASK_RD != 0)

    @property
    def ra(self):
        return int(self.flags & BITMASK_RA != 0)

    @property
    def rcode(self):
        return self.flags & BITMASK_RCODE

    def readPacket(self, data):
        """Parses a DNS query from bytes; raises Truncated if short."""
        if len(data) < 12:
            raise Truncated()
        (self.transactionID, self.flags, self.qdcount, self.ancount,
         self.nscount, self.arcount) = struct.unpack("!HHHHHH", data[:12])
        pos = 12
        for _ in range(self.qdcount):
            question = DNSQuestion()
            labels = []
            while True:
                if pos >= len(data):
                    raise Truncated()
                n = data[pos]
                pos += 1
                if n == 0:
                    break
                if n & 0xc0 or pos + n > len(data):   # no compression here
                    raise Truncated()
                labels.append(data[pos:pos + n])
                pos += n
            if pos + 4 > len(data):
                raise Truncated()
            question.qname = b".".join(labels)
            question.qtype = data[pos:pos + 2]
            question.qclass = data[pos + 2:pos + 4]
            pos += 4
            self.questions.append(question)

    def packedString(self):
        self.qdcount = 0
        self.ancount = len(self.answers)
        return struct.pack("!HHHHHH", self.transactionID, self.flags,
                           self.qdcount, self.ancount, self.nscount,
                           self.arcount) + b"".join(
                               a.packedString() for a in self.answers)


class DNSQuestion:
    def __init__(self):
        self.qname = b""
        self.qtype = b""
        self.qclass = b""


class DNSResourceRecord:
    def __init__(self):
        self.name = b""
        self.type = 0
        self.dataclass = 0
        self.ttl = 0
        self.rdata = b""

    def packedString(self):
        out = b""
        for label in self.name.split(b"."):
            out += struct.pack("!B", len(label)) + label
        out += b"\x00"
        out += struct.pack("!HHIH", self.type, self.dataclass, self.ttl,
                           len(self.rdata))
        return out + self.rdata
