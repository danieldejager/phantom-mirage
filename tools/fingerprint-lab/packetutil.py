"""Scapy helpers: build probes and parse replies (offline-safe)."""

from __future__ import annotations

from typing import Any

from scapy.all import (  # type: ignore
    IP,
    TCP,
    UDP,
    ICMP,
    Raw,
    conf,
)

from probespec import ProbeDef, options_letters

# Quiet scapy verbosity for library use.
conf.verb = 0

_SCAPY_OPT = {"WS": "WScale", "NOP": "NOP", "MSS": "MSS", "TS": "Timestamp", "SACK": "SAckOK", "EOL": "EOL"}


def _tcp_options(opts) -> list:
    """Ordered probespec options -> scapy option list (order preserved)."""
    out: list = []
    for kind, val in opts or ():
        name = _SCAPY_OPT[kind]
        if kind == "SACK":
            out.append((name, b""))
        elif kind in ("NOP", "EOL"):
            out.append((name, None))
        else:
            out.append((name, val))
    return out


def build_probe(
    pdef: ProbeDef,
    *,
    src_ip: str,
    dst_ip: str,
    open_tcp: int,
    closed_tcp: int,
    closed_udp: int,
    ip_id: int,
    tcp_seq: int,
    tcp_sport: int,
    tcp_ack: int = 0,
    icmp_id: int = 0,
) -> Any:
    """Build a scapy packet for *pdef*. Does not send.

    Shapes follow https://nmap.org/book/osdetect-methods.html ("Probes Sent").
    *tcp_ack* is the run's random non-zero ack (used unless the probe says
    ack 0, as ECN does); *icmp_id* is the ICMP echo identifier.
    """
    dst_port = {
        "open_tcp": open_tcp,
        "closed_tcp": closed_tcp,
        "closed_udp": closed_udp,
        "n/a": 0,
    }[pdef.dst_port_role]

    ip = IP(src=src_ip, dst=dst_ip, id=(pdef.ip_id if pdef.ip_id is not None else ip_id), tos=pdef.tos)
    if pdef.df:
        ip.flags = "DF"

    if pdef.kind in ("syn_seq", "tcp_unusual", "ecn"):
        tcp = TCP(
            sport=tcp_sport,
            dport=dst_port,
            seq=tcp_seq,
            ack=0 if pdef.ack_zero else tcp_ack,
            flags=pdef.flags or "",
            window=pdef.window or 0,
            urgptr=pdef.urgptr,
            options=_tcp_options(pdef.options),
        )
        tcp.reserved = pdef.reserved
        return ip / tcp

    if pdef.kind == "icmp":
        icmp = ICMP(type=pdef.icmp_type or 8, code=pdef.icmp_code or 0,
                    id=icmp_id & 0xFFFF, seq=pdef.icmp_seq or 0)
        payload = Raw(b"\x00" * (pdef.icmp_payload_len or 0))
        return ip / icmp / payload

    if pdef.kind == "udp":
        udp = UDP(sport=tcp_sport, dport=dst_port)
        payload = Raw(b"C" * (pdef.udp_payload_len or 0))
        return ip / udp / payload

    raise ValueError(f"unknown probe kind: {pdef.kind}")


def packet_to_hex(pkt: Any) -> str:
    return bytes(pkt).hex()


def _flag_string(tcp: Any) -> str:
    # Prefer scapy's flag string when present.
    try:
        return str(tcp.flags)
    except Exception:
        return ""


def _flag_bits(tcp: Any) -> int | None:
    try:
        return int(tcp.flags) & 0xFF
    except Exception:
        return None


def _options_string(tcp: Any) -> str:
    return options_letters(getattr(tcp, "options", []) or [])


def _jsonable_opt(opt) -> list:
    name = opt[0] if isinstance(opt, tuple) else opt
    val = opt[1] if isinstance(opt, tuple) and len(opt) > 1 else None
    if isinstance(val, bytes):
        val = val.hex() if val else ""
    elif isinstance(val, tuple):
        val = [int(x) for x in val]
    return [name, val]


def parse_reply(pkt: Any) -> dict[str, Any] | None:
    """Extract fingerprint-relevant fields from a reply packet."""
    if pkt is None:
        return None
    # Walk to IP layer
    ip = pkt.getlayer(IP)
    if ip is None:
        return {"raw_layers": pkt.summary(), "note": "non-IP reply"}

    out: dict[str, Any] = {
        "ip_src": ip.src,
        "ip_dst": ip.dst,
        "ip_id": int(ip.id),
        "ip_ttl": int(ip.ttl),
        "ip_tos": int(ip.tos),
        "ip_df": bool(ip.flags.DF) if hasattr(ip.flags, "DF") else bool(int(ip.flags) & 0x2),
        "ip_len": int(ip.len) if ip.len is not None else None,
    }

    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        out.update(
            {
                "l4": "tcp",
                "sport": int(tcp.sport),
                "dport": int(tcp.dport),
                "seq": int(tcp.seq),
                "ack": int(tcp.ack),
                "window": int(tcp.window),
                "flags": _flag_string(tcp),
                # Raw TCP flag bits (FIN=0x01 ... ECE=0x40, CWR=0x80). Added in
                # tool_version 0.2.0 so ECN CC does not depend on scapy's
                # flag-letter rendering. Older runs lack it; derive.py falls
                # back to the letters (E=ECE, C=CWR).
                "flags_bits": _flag_bits(tcp),
                "options": _options_string(tcp),
                "options_raw": [_jsonable_opt(o) for o in (tcp.options or [])],
                "reserved": int(getattr(tcp, "reserved", 0) or 0),
                # Added in 0.3.0 for the Q (urgent-pointer) quirk.
                "urgptr": int(tcp.urgptr or 0),
            }
        )
        return out

    icmp = pkt.getlayer(ICMP)
    if icmp is not None:
        raw_icmp = bytes(icmp)
        out.update(
            {
                "l4": "icmp",
                "icmp_type": int(icmp.type),
                "icmp_code": int(icmp.code),
                # Added in 0.3.0: echo id/seq, and the 4 "unused" header bytes
                # of an unreachable (UN test).
                "icmp_id": int.from_bytes(raw_icmp[4:6], "big") if len(raw_icmp) >= 6 else None,
                "icmp_seq": int.from_bytes(raw_icmp[6:8], "big") if len(raw_icmp) >= 8 else None,
                "icmp_unused": int.from_bytes(raw_icmp[4:8], "big") if len(raw_icmp) >= 8 else None,
            }
        )
        if int(icmp.type) == 3 and len(raw_icmp) >= 28:
            out.update(_parse_quoted(raw_icmp[8:]))
        return out

    udp = pkt.getlayer(UDP)
    if udp is not None:
        out.update({"l4": "udp", "sport": int(udp.sport), "dport": int(udp.dport)})
        return out

    out["l4"] = "other"
    return out


def _parse_quoted(q: bytes) -> dict[str, Any]:
    """Fields of the probe quoted inside an ICMP unreachable (U1 tests)."""
    out: dict[str, Any] = {}
    ihl = (q[0] & 0x0F) * 4
    if len(q) < 20 or ihl < 20 or len(q) < ihl:
        return out
    hdr = q[:ihl]
    out["embedded_ip_len"] = int.from_bytes(hdr[2:4], "big")
    out["embedded_ip_id"] = int.from_bytes(hdr[4:6], "big")
    out["embedded_ip_ttl"] = hdr[8]
    cks = int.from_bytes(hdr[10:12], "big")
    out["embedded_ip_sum"] = cks
    zeroed = hdr[:10] + b"\x00\x00" + hdr[12:]
    out["embedded_ip_sum_ok"] = cks != 0 and _inet_cksum(zeroed) == cks
    l4 = q[ihl:]
    if hdr[9] == 17 and len(l4) >= 8:
        out["embedded_udp_sum"] = int.from_bytes(l4[6:8], "big")
        out["embedded_udp_data_hex"] = l4[8:].hex()
    return out


def _inet_cksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\x00"
    s = sum(int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def parse_hex(hexstr: str) -> dict[str, Any] | None:
    """Re-parse a recorded packet (run JSON ``hex``) offline."""
    if not hexstr:
        return None
    return parse_reply(IP(bytes.fromhex(hexstr)))


def synthesize_tcp_reply(
    *,
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: str,
    window: int,
    ttl: int,
    ip_id: int,
    df: bool,
    options: list | None = None,
) -> Any:
    """Build a synthetic TCP reply for unit tests (never sent)."""
    ip = IP(src=src, dst=dst, ttl=ttl, id=ip_id)
    if df:
        ip.flags = "DF"
    tcp = TCP(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        window=window,
        options=options or [],
    )
    return ip / tcp


def synthesize_icmp_echo_reply(
    *,
    src: str,
    dst: str,
    ttl: int,
    ip_id: int,
    df: bool,
    code: int = 0,
    tos: int = 0,
) -> Any:
    ip = IP(src=src, dst=dst, ttl=ttl, id=ip_id, tos=tos)
    if df:
        ip.flags = "DF"
    return ip / ICMP(type=0, code=code) / Raw(b"\x00" * 32)


def synthesize_icmp_port_unreach(
    *,
    src: str,
    dst: str,
    ttl: int,
    ip_id: int,
    df: bool,
    embedded: Any,
) -> Any:
    ip = IP(src=src, dst=dst, ttl=ttl, id=ip_id)
    if df:
        ip.flags = "DF"
    return ip / ICMP(type=3, code=3) / embedded
