"""Probe packet definitions for the fingerprint lab.

Field names and response categories match what honeyd's personality.c parses
(SEQ, OPS, WIN, ECN, T1-T7, U1, IE).

Packet shapes are written from the published description of the probe set in
the Nmap book, "TCP/IP Fingerprinting Methods Supported by Nmap":
    https://nmap.org/book/osdetect-methods.html  (section "Probes Sent")
They are NOT taken from nmap source code or from nmap-os-db. Where that page
is silent (IP DF on the SEQ, ECN, IE2 and U1 probes) we follow what was seen
on the wire in our own lab capture and say so in a comment. No OS
fingerprint database entries are embedded here.

TCP options are an explicit ORDERED tuple of (kind, value) entries, because
the order and the NOP padding are part of the probe (and of the reply the
target builds). Kinds: "WS" (window scale), "NOP", "MSS", "TS" ((TSval,
TSecr)), "SACK" (SACK permitted), "EOL".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

METHOD_DOC_URL = "https://nmap.org/book/osdetect-methods.html"

TcpOpt = tuple  # ("MSS", 1460) | ("NOP", None) | ...
TS_PROBE = (0xFFFFFFFF, 0)


@dataclass(frozen=True)
class ProbeDef:
    name: str
    kind: str  # syn_seq | tcp_unusual | ecn | icmp | udp
    dst_port_role: str  # open_tcp | closed_tcp | closed_udp | n/a
    window: int | None = None
    flags: str = ""
    reserved: int = 0  # scapy TCP.reserved (3 bits); 4 = the high reserved bit
    urgptr: int = 0
    ack_zero: bool = False  # True: ack field 0; False: the run's random non-zero ack
    tos: int = 0
    df: bool = False
    ip_id: int | None = None  # fixed IP ID (U1 = 0x1042); None = per-run value
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_seq: int | None = None
    icmp_payload_len: int = 0
    udp_payload_len: int = 0
    options: tuple[TcpOpt, ...] = ()
    notes: str = ""


# --- SEQ: six SYNs to an open port, sent exactly 100 ms apart (doc: "Sequence
# generation (SEQ, OPS, WIN, and T1)"). Options and windows per the doc's
# per-packet list. IP DF: the doc does not say; our capture shows DF clear.
_SEQ = [
    (1, (("WS", 10), ("NOP", None), ("MSS", 1460), ("TS", TS_PROBE), ("SACK", None))),
    (63, (("MSS", 1400), ("WS", 0), ("SACK", None), ("TS", TS_PROBE), ("EOL", None))),
    (4, (("TS", TS_PROBE), ("NOP", None), ("NOP", None), ("WS", 5), ("NOP", None), ("MSS", 640))),
    (4, (("SACK", None), ("TS", TS_PROBE), ("WS", 10), ("EOL", None))),
    (16, (("MSS", 536), ("SACK", None), ("TS", TS_PROBE), ("WS", 10), ("EOL", None))),
    (512, (("MSS", 265), ("SACK", None), ("TS", TS_PROBE))),
]
SEQ_PROBES: list[ProbeDef] = [
    ProbeDef(name=f"SEQ{i}", kind="syn_seq", dst_port_role="open_tcp", window=w, flags="S",
             df=False, options=o)
    for i, (w, o) in enumerate(_SEQ, start=1)
]
SEQ_GAP_SEC = 0.100

# --- IE pair (doc: "ICMP echo (IE)"). Sent immediately after SEQ (needed for SS).
ICMP_PROBES: list[ProbeDef] = [
    ProbeDef(name="IE1", kind="icmp", dst_port_role="n/a", tos=0, df=True, icmp_type=8,
             icmp_code=9, icmp_seq=295, icmp_payload_len=120,
             notes="echo request, DF, TOS 0, code 9, seq 295, random id, 120 x 0x00"),
    # Doc: "similar, except TOS 4, code 0, 150 bytes, id and seq +1". It does
    # not restate DF; our capture shows DF clear on the second echo.
    ProbeDef(name="IE2", kind="icmp", dst_port_role="n/a", tos=4, df=False, icmp_type=8,
             icmp_code=0, icmp_seq=296, icmp_payload_len=150,
             notes="echo request, TOS 4, code 0, id+1, seq 296, 150 x 0x00"),
]

# --- U1 (doc: "UDP (U1)"): 300 x 'C' to a closed port, IP ID 0x1042.
UDP_PROBE = ProbeDef(name="U1", kind="udp", dst_port_role="closed_udp", df=False, ip_id=0x1042,
                     udp_payload_len=300, notes="UDP to closed port, IP ID 0x1042")

# --- ECN (doc: "TCP explicit congestion notification (ECN)").
ECN_PROBE = ProbeDef(
    name="ECN", kind="ecn", dst_port_role="open_tcp", window=3, flags="SEC",
    # The doc says "the reserved bit which immediately precedes the CWR bit";
    # on the wire (our capture) that is the high reserved bit, byte 12 = 0x?8,
    # i.e. scapy reserved=4.
    reserved=4, urgptr=0xF7F5, ack_zero=True, df=False,
    options=(("WS", 10), ("NOP", None), ("MSS", 1460), ("SACK", None), ("NOP", None), ("NOP", None)),
    notes="SYN+ECE+CWR, reserved bit, urg 0xF7F5 without URG, ack 0, window 3",
)

# --- T2-T7 (doc: "TCP (T2-T7)"): options hex 03030A0102040109080AFFFFFFFF000000000402,
# T7 with window scale 15.
_T_OPTS = (("WS", 10), ("NOP", None), ("MSS", 265), ("TS", TS_PROBE), ("SACK", None))
_T7_OPTS = (("WS", 15),) + _T_OPTS[1:]
T_PROBES: list[ProbeDef] = [
    ProbeDef(name="T2", kind="tcp_unusual", dst_port_role="open_tcp", window=128, flags="",
             df=True, options=_T_OPTS, notes="NULL flags, DF, open port"),
    ProbeDef(name="T3", kind="tcp_unusual", dst_port_role="open_tcp", window=256, flags="FSPU",
             df=False, options=_T_OPTS, notes="SYN FIN URG PSH, open port"),
    ProbeDef(name="T4", kind="tcp_unusual", dst_port_role="open_tcp", window=1024, flags="A",
             df=True, options=_T_OPTS, notes="ACK, DF, open port"),
    ProbeDef(name="T5", kind="tcp_unusual", dst_port_role="closed_tcp", window=31337, flags="S",
             df=False, options=_T_OPTS, notes="SYN, closed port"),
    ProbeDef(name="T6", kind="tcp_unusual", dst_port_role="closed_tcp", window=32768, flags="A",
             df=True, options=_T_OPTS, notes="ACK, DF, closed port"),
    ProbeDef(name="T7", kind="tcp_unusual", dst_port_role="closed_tcp", window=65535, flags="FPU",
             df=False, options=_T7_OPTS, notes="FIN PSH URG, closed port, WS 15"),
]


def options_letters(options) -> str:
    """TCP options -> the letter string used by OPS/O* and personality.c.

    Per https://nmap.org/book/osdetect-methods.html ("TCP options (O, O1-O6)"):
    L = EOL, N = NOP, M<hex> = MSS, W<hex> = window scale, S = SACK permitted,
    T<a><b> = timestamp where a/b are 1 if TSval/TSecr are non-zero, else 0.
    personality.c's parse_option accepts exactly these letters (M/W as hex,
    T followed by two 0/1 digits).
    """
    letters: list[str] = []
    for opt in options or []:
        name = opt[0] if isinstance(opt, (tuple, list)) else opt
        val = opt[1] if isinstance(opt, (tuple, list)) and len(opt) > 1 else None
        if name in ("MSS", "M"):
            letters.append(f"M{int(val):X}")
        elif name in ("SAckOK", "SAck", "S", "SACK"):
            letters.append("S")
        elif name in ("Timestamp", "TSval", "T", "TS"):
            if isinstance(val, (tuple, list)) and len(val) >= 2:
                letters.append(f"T{int(int(val[0]) != 0)}{int(int(val[1]) != 0)}")
            else:
                letters.append("T00")
        elif name in ("NOP", "N"):
            letters.append("N")
        elif name in ("WScale", "W", "WS"):
            letters.append(f"W{int(val):X}")
        elif name in ("EOL", "L", "E"):
            letters.append("L")
        else:
            letters.append("?")
    return "".join(letters)


def all_probe_defs() -> list[ProbeDef]:
    """Send order: SEQ, then IE right after (doc, for SS), then U1, ECN, T2-T7."""
    return list(SEQ_PROBES) + list(ICMP_PROBES) + [UDP_PROBE, ECN_PROBE] + list(T_PROBES)


def probe_plan_summary() -> list[dict[str, Any]]:
    """Machine-readable plan for --dry-run output."""
    return [
        {"name": p.name, "kind": p.kind, "dst_port_role": p.dst_port_role, "window": p.window,
         "flags": p.flags, "tos": p.tos, "df": p.df, "notes": p.notes}
        for p in all_probe_defs()
    ]
