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

from probespec import ProbeDef, TcpOpts

# Quiet scapy verbosity for library use.
conf.verb = 0


def _tcp_options(opts: TcpOpts | None) -> list:
    if opts is None:
        return []
    out: list = []
    if opts.mss is not None:
        out.append(("MSS", opts.mss))
    if opts.sackok:
        out.append(("SAckOK", b""))
    if opts.timestamp is not None:
        out.append(("Timestamp", opts.timestamp))
    for _ in range(opts.nop_count_before_wscale):
        out.append(("NOP", None))
    if opts.wscale is not None:
        out.append(("WScale", opts.wscale))
    if opts.eol:
        out.append(("EOL", None))
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
) -> Any:
    """Build a scapy packet for *pdef*. Does not send."""
    dst_port = {
        "open_tcp": open_tcp,
        "closed_tcp": closed_tcp,
        "closed_udp": closed_udp,
        "n/a": 0,
    }[pdef.dst_port_role]

    ip = IP(src=src_ip, dst=dst_ip, id=ip_id, tos=pdef.tos)
    if pdef.df:
        ip.flags = "DF"

    if pdef.kind in ("syn_seq", "tcp_unusual", "ecn"):
        flags = pdef.flags or ""
        tcp = TCP(
            sport=tcp_sport,
            dport=dst_port,
            seq=tcp_seq,
            flags=flags,
            window=pdef.window or 0,
            options=_tcp_options(pdef.options),
        )
        if pdef.kind == "ecn":
            # Reserved bit conventionally set on the ECN probe (bit 0x40 in
            # the combined reserved/data-offset high nibble area). Scapy
            # exposes `reserved` on TCP.
            tcp.reserved = 8  # set high reserved bit
        return ip / tcp

    if pdef.kind == "icmp":
        icmp = ICMP(type=pdef.icmp_type or 8, code=pdef.icmp_code or 0)
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
    """Encode TCP options in a compact letter form used by personality OPS/O*."""
    letters: list[str] = []
    for opt in getattr(tcp, "options", []) or []:
        name = opt[0] if isinstance(opt, tuple) else opt
        val = opt[1] if isinstance(opt, tuple) and len(opt) > 1 else None
        if name in ("MSS", "M"):
            letters.append(f"M{int(val):X}")
        elif name in ("SAckOK", "SAck", "S"):
            letters.append("S")
        elif name in ("Timestamp", "TSval", "T"):
            if isinstance(val, tuple) and len(val) >= 2:
                tsval, tsecr = int(val[0]), int(val[1])
                letters.append("T" if tsecr != 0 else "T0")
            else:
                letters.append("T")
        elif name in ("NOP", "N"):
            letters.append("N")
        elif name in ("WScale", "W"):
            letters.append(f"W{int(val)}")
        elif name in ("EOL", "E"):
            letters.append("E")
        else:
            letters.append("?")
    return "".join(letters)


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
            }
        )
        return out

    icmp = pkt.getlayer(ICMP)
    if icmp is not None:
        out.update(
            {
                "l4": "icmp",
                "icmp_type": int(icmp.type),
                "icmp_code": int(icmp.code),
            }
        )
        # Embedded IP (port unreachable) carries original probe IP-ID quirks.
        emb = icmp.payload.getlayer(IP) if icmp.payload is not None else None
        if emb is not None:
            out["embedded_ip_id"] = int(emb.id)
            out["embedded_ip_len"] = int(emb.len) if emb.len is not None else None
            out["embedded_ip_ttl"] = int(emb.ttl)
            out["embedded_ip_sum_ok"] = None  # filled by caller if checked
        return out

    udp = pkt.getlayer(UDP)
    if udp is not None:
        out.update({"l4": "udp", "sport": int(udp.sport), "dport": int(udp.dport)})
        return out

    out["l4"] = "other"
    return out


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
