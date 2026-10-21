#!/usr/bin/env python3
"""Regenerate fuzz/corpus/packet seeds (Ethernet frames) for fuzz_packet."""
import os, socket, struct

OUT = os.path.join(os.path.dirname(__file__), "corpus", "packet")
HONEY_MAC = bytes.fromhex("020000000001")
PEER_MAC = bytes.fromhex("02aabbccddee")

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def ip(src, dst, proto, payload, ident=1, frag=0, ttl=64, opts=b""):
    hl = (20 + len(opts)) // 4
    h = struct.pack("!BBHHHBBH4s4s", 0x40 | hl, 0, 20 + len(opts) + len(payload),
                    ident, frag, ttl, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst)) + opts
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + payload

def l4sum(src, dst, proto, seg):
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, len(seg))
    return csum(ph + seg)

def tcp(src, dst, sport, dport, flags, seq=1000, ack=0, data=b"", opts=b""):
    off = (20 + len(opts)) // 4
    seg = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, off << 4, flags,
                      8192, 0, 0) + opts + data
    c = l4sum(src, dst, 6, seg)
    return ip(src, dst, 6, seg[:16] + struct.pack("!H", c) + seg[18:])

def udp(src, dst, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    c = l4sum(src, dst, 17, seg)
    return ip(src, dst, 17, seg[:6] + struct.pack("!H", c) + seg[8:])

def icmp(src, dst, typ, code, rest=b"\0\x01\0\x01", data=b"abcdefgh"):
    m = struct.pack("!BBH", typ, code, 0) + rest + data
    m = m[:2] + struct.pack("!H", csum(m)) + m[4:]
    return ip(src, dst, 1, m)

def eth(payload, etype=0x0800, dst=HONEY_MAC, src=PEER_MAC):
    return dst + src + struct.pack("!H", etype) + payload

def bad_off_seg(src, dst):
    """SYN whose data offset (60 bytes) runs past the 24-byte segment."""
    seg = struct.pack("!HHLLBBHHH", 40006, 22, 1, 0, 15 << 4, 0x02, 8192, 0, 0) + b"\x02\x04\x05\xb4"
    c = l4sum(src, dst, 6, seg)
    return seg[:16] + struct.pack("!H", c) + seg[18:]

A = "10.0.0.50"
seeds = {
    "tcp_syn_22": eth(tcp(A, "10.0.0.2", 40000, 22, 0x02,
                          opts=bytes.fromhex("020405b40402080a0000000100000000010303070000"[:40]))),
    "tcp_syn_closed": eth(tcp(A, "10.0.0.2", 40001, 23, 0x02)),
    "tcp_ack_data": eth(tcp(A, "10.0.0.2", 40000, 22, 0x18, seq=1001, ack=1, data=b"SSH-2.0-x\r\n")),
    "tcp_fin": eth(tcp(A, "10.0.0.2", 40000, 22, 0x11, seq=1012, ack=1)),
    "tcp_rst": eth(tcp(A, "10.0.0.2", 40000, 22, 0x04)),
    "tcp_xmas": eth(tcp(A, "10.0.0.3", 40002, 445, 0x29)),
    "tcp_null": eth(tcp(A, "10.0.0.3", 40003, 445, 0x00)),
    "tcp_routed": eth(tcp(A, "10.1.0.2", 40004, 80, 0x02)),
    "udp_dns": eth(udp(A, "10.0.0.2", 5353, 53, bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001"))),
    "udp_closed": eth(udp(A, "10.0.0.2", 5353, 9999, b"hello")),
    "udp_snmp": eth(udp(A, "10.0.0.2", 5353, 161, b"\x30\x00")),
    "udp_dhcp_reply": eth(udp("10.0.0.254", "10.0.0.2", 67, 68, b"\x02\x01\x06\x00" + b"\0" * 232 + b"\x63\x82\x53\x63\xff")),
    "icmp_echo": eth(icmp(A, "10.0.0.2", 8, 0)),
    "icmp_echo_win": eth(icmp(A, "10.0.0.3", 8, 0)),
    "icmp_timestamp": eth(icmp(A, "10.0.0.2", 13, 0, data=b"\0" * 12)),
    "icmp_mask": eth(icmp(A, "10.0.0.2", 17, 0, data=b"\0" * 4)),
    "icmp_info": eth(icmp(A, "10.0.0.2", 15, 0, data=b"")),
    "icmp_unreach_quote": eth(icmp(A, "10.0.0.2", 3, 3, rest=b"\0\0\0\0",
                                   data=udp("10.0.0.2", A, 53, 5353, b"x")[:28])),
    "ip_opts_rr": eth(ip(A, "10.0.0.2", 1, icmp(A, "10.0.0.2", 8, 0)[20:],
                         opts=b"\x07\x07\x04\0\0\0\0\x01")),
    "ip_frag1": eth(ip(A, "10.0.0.2", 1, icmp(A, "10.0.0.2", 8, 0, data=b"A" * 32)[20:][:24], ident=77, frag=0x2000)),
    "ip_frag2": eth(ip(A, "10.0.0.2", 1, icmp(A, "10.0.0.2", 8, 0, data=b"A" * 32)[20:][24:], ident=77, frag=3)),
    "ip_ttl1_routed": eth(ip(A, "10.1.0.2", 1, icmp(A, "10.1.0.2", 8, 0)[20:], ttl=1)),
    "ip_proto_47_gre": eth(ip(A, "10.0.0.1", 47, struct.pack("!HH", 0, 0x0800) + icmp(A, "10.1.0.2", 8, 0))),
    "ip_proto_unknown": eth(ip(A, "10.0.0.2", 132, b"\0" * 16)),
    "arp_whohas": eth(struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + PEER_MAC + socket.inet_aton(A)
                      + b"\0" * 6 + socket.inet_aton("10.0.0.2"), etype=0x0806, dst=b"\xff" * 6),
    "arp_reply": eth(struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + PEER_MAC + socket.inet_aton(A)
                     + HONEY_MAC + socket.inet_aton("10.0.0.1"), etype=0x0806),
    "short_eth": b"\x02" * 13,
    "short_ip": eth(b"\x45\x00\x00\x14"),
    # Regressions for bugs found by fuzzing (see docs/fuzzing.md)
    "regress_icmp_echo_ipopts": eth(ip(A, "10.0.0.2", 1, icmp(A, "10.0.0.2", 8, 0, data=b"")[20:],
                                       opts=b"\x01" * 40)),
    "regress_tcp_no_header": eth(ip(A, "10.0.0.2", 6, b"")),
    "regress_tcp_th_off_past_end": eth(ip(A, "10.0.0.2", 6, bad_off_seg(A, "10.0.0.2"))),
    "regress_tcp_opt_len_past_end": eth(tcp(A, "10.0.0.2", 40007, 22, 0x02, opts=b"\x01\x01\x01\x02")),
    "regress_osfp_th_off": eth(ip(A, "10.0.0.2", 6,
                                  struct.pack("!HHLLBBHHH", 40005, 22, 1, 0, 15 << 4, 0x02, 8192, 0, 0))),
}
os.makedirs(OUT, exist_ok=True)
for name, data in seeds.items():
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
print(f"wrote {len(seeds)} seeds to {OUT}")
