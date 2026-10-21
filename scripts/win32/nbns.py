#!/usr/bin/env python3
#
# NetBIOS name service responder: answers NB queries for this honeypot's
# allocated name and NBSTAT queries with that name. Network I/O is bytes
# on stdin/stdout; anything short or malformed gets no reply.
#
# argv[2] is a config file whose first line is "<key> <names db path>".

import os
import socket
import struct
import sys

sys.path.append("/usr/share/honeyd/scripts/lib/")
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "lib"))
from names import AddNameAllocation  # noqa: E402


def FirstLevelDecode(encoded):
    """Decodes a NetBIOS "first level" encoded name (bytes)."""
    out = bytearray()
    for i in range(0, len(encoded) - 1, 2):
        out.append((((encoded[i] - 0x41) & 0xf) << 4) |
                   ((encoded[i + 1] - 0x41) & 0xf))
    return bytes(out)


def parse(data):
    """Returns (trans_id, name_start, encoded_name, decoded, qtype) or None."""
    if len(data) < 13:
        return None
    trans_id = data[0:2]
    questions, answers = struct.unpack("!HH", data[4:8])
    if questions == 0 or answers > 0:
        return None
    if data[12:13] != b"\x20":
        return None
    end = data.find(b"\x00", 13)
    if end == -1 or len(data) < end + 1 + 4:
        return None
    encoded = data[13:end + 1]          # includes the terminating NUL
    decoded = FirstLevelDecode(encoded[:-1]).strip(b"\x00").strip()
    qtype = data[end + 1:end + 3]
    return trans_id, data[12:13], encoded, decoded, qtype


def respond(data, our_name, our_ip):
    parsed = parse(data)
    if parsed is None:
        return b""
    trans_id, name_start, encoded, name, qtype = parsed
    if qtype == b"\x00\x20":            # forward (NB) query
        if name != our_name:
            return b""
        return (trans_id + b"\x85\x80" + b"\x00\x00" + b"\x00\x01" +
                b"\x00\x00" + b"\x00\x00" + name_start + encoded +
                b"\x00\x20" + b"\x00\x01" +     # NB, IN
                b"\x00\x03\xf4\x80" +           # TTL 3 days
                b"\x00\x06" + b"\x00\x00" + socket.inet_aton(our_ip))
    if qtype == b"\x00\x21":            # NBSTAT
        nb = our_name[:15]
        return (trans_id + b"\x84\x00" + b"\x00\x00" + b"\x00\x01" +
                b"\x00\x00" + b"\x00\x00" + name_start + encoded +
                b"\x00\x21" + b"\x00\x01" + b"\x00\x00\x00\x00" +
                struct.pack("!H", 65) + b"\x01" +
                nb + b"\x20" * (15 - len(nb)) + b"\x00" +
                b"\x04\x00" + b"\x00" * 46)
    return b""


def main():
    honeyd_home = os.getenv("PHANTOM_MIRAGE_HOME", os.getenv("HONEYD_HOME", ""))
    our_ip = os.getenv("PHANTOM_MIRAGE_TEMPLATE_NAME", os.getenv("HONEYD_TEMPLATE_NAME", ""))
    with open(sys.argv[2]) as fd:
        names_file = fd.readline().split(" ", 1)[1].rstrip("\n")
    our_name = AddNameAllocation(honeyd_home + names_file, our_ip).upper()
    if our_name == "":
        return
    try:
        socket.inet_aton(our_ip)
    except OSError:
        return
    # UDP: one datagram per write; stdin may stay open, so do not wait
    # for EOF.
    reply = respond(os.read(0, 65535),
                    our_name.encode("ascii", "ignore"), our_ip)
    if reply:
        sys.stdout.buffer.write(reply)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
