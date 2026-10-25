"""Probe packet definitions for the fingerprint lab.

Field names and response categories match what honeyd's personality.c parses
(SEQ, OPS, WIN, ECN, T1-T7, U1, IE). Packet shapes follow the well-known
TCP/IP stack fingerprint probe set (SYN timing series, unusual flag
combinations, ECN SYN, closed-port UDP, ICMP echo pair). No vendor OS
database entries are embedded here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TcpOpts:
    """Ordered TCP options for a probe. Values are None when unused."""

    mss: int | None = None
    sackok: bool = False
    timestamp: tuple[int, int] | None = None  # (TSval, TSecr)
    nop_count_before_wscale: int = 0
    wscale: int | None = None
    eol: bool = False


@dataclass(frozen=True)
class ProbeDef:
    name: str
    kind: str  # syn_seq | tcp_unusual | ecn | icmp | udp
    dst_port_role: str  # open_tcp | closed_tcp | closed_udp | n/a
    window: int | None = None
    flags: str = ""
    reserved: int = 0  # TCP reserved/NS bits where relevant
    tos: int = 0
    df: bool = True
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_payload_len: int = 0
    udp_payload_len: int = 0
    options: TcpOpts | None = None
    notes: str = ""


# Six timed SYN probes (~100 ms apart) used for SEQ/OPS/WIN (and T1 reply).
SEQ_PROBES: list[ProbeDef] = [
    ProbeDef(
        name="SEQ1",
        kind="syn_seq",
        dst_port_role="open_tcp",
        window=1,
        flags="S",
        options=TcpOpts(mss=1460, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="SEQ2",
        kind="syn_seq",
        dst_port_role="open_tcp",
        window=63,
        flags="S",
        options=TcpOpts(mss=1400, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=0),
    ),
    ProbeDef(
        name="SEQ3",
        kind="syn_seq",
        dst_port_role="open_tcp",
        window=4,
        flags="S",
        options=TcpOpts(mss=640, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=5),
    ),
    ProbeDef(
        name="SEQ4",
        kind="syn_seq",
        dst_port_role="open_tcp",
        window=4,
        flags="S",
        options=TcpOpts(mss=536, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="SEQ5",
        kind="syn_seq",
        dst_port_role="open_tcp",
        window=16,
        flags="S",
        options=TcpOpts(mss=1460, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="SEQ6",
        kind="syn_seq",
        dst_port_role="open_tcp",
        window=512,
        flags="S",
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0)),
    ),
]

# Unusual TCP packets T2-T7 (T1 is the first SEQ reply category).
T_PROBES: list[ProbeDef] = [
    ProbeDef(
        name="T2",
        kind="tcp_unusual",
        dst_port_role="open_tcp",
        window=128,
        flags="",  # no flags
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
        notes="NULL flags to open port",
    ),
    ProbeDef(
        name="T3",
        kind="tcp_unusual",
        dst_port_role="open_tcp",
        window=256,
        flags="FSPU",  # FIN SYN PSH URG
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="T4",
        kind="tcp_unusual",
        dst_port_role="open_tcp",
        window=1024,
        flags="A",
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="T5",
        kind="tcp_unusual",
        dst_port_role="closed_tcp",
        window=31337,
        flags="S",
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="T6",
        kind="tcp_unusual",
        dst_port_role="closed_tcp",
        window=32768,
        flags="A",
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
    ProbeDef(
        name="T7",
        kind="tcp_unusual",
        dst_port_role="closed_tcp",
        window=65535,
        flags="FPU",  # FIN PSH URG
        options=TcpOpts(mss=265, sackok=True, timestamp=(0xFFFFFFFF, 0), nop_count_before_wscale=1, wscale=10),
    ),
]

ECN_PROBE = ProbeDef(
    name="ECN",
    kind="ecn",
    dst_port_role="open_tcp",
    window=3,
    flags="SEC",  # SYN + ECE + CWR
    reserved=0b0100_0000 >> 1,  # set reserved bit conventionally used in ECN probe
    options=TcpOpts(mss=1460, sackok=False, timestamp=None, wscale=10, eol=True),
    notes="ECN SYN with ECE+CWR; reserved bit set in builder",
)

ICMP_PROBES: list[ProbeDef] = [
    ProbeDef(
        name="IE1",
        kind="icmp",
        dst_port_role="n/a",
        tos=0,
        df=False,
        icmp_type=8,
        icmp_code=9,
        icmp_payload_len=120,
        notes="echo request, code 9, TOS 0",
    ),
    ProbeDef(
        name="IE2",
        kind="icmp",
        dst_port_role="n/a",
        tos=4,  # IP_TOS low-delay-ish value used in classic IE pair
        df=True,
        icmp_type=8,
        icmp_code=0,
        icmp_payload_len=150,
        notes="echo request, code 0, TOS 4, DF set",
    ),
]

UDP_PROBE = ProbeDef(
    name="U1",
    kind="udp",
    dst_port_role="closed_udp",
    tos=0,
    df=False,
    udp_payload_len=300,
    notes="UDP to closed port; expect ICMP port unreachable",
)


def all_probe_defs() -> list[ProbeDef]:
    return list(SEQ_PROBES) + [ECN_PROBE] + list(T_PROBES) + list(ICMP_PROBES) + [UDP_PROBE]


def probe_plan_summary() -> list[dict[str, Any]]:
    """Machine-readable plan for --dry-run output."""
    out = []
    for p in all_probe_defs():
        out.append(
            {
                "name": p.name,
                "kind": p.kind,
                "dst_port_role": p.dst_port_role,
                "window": p.window,
                "flags": p.flags,
                "tos": p.tos,
                "df": p.df,
                "notes": p.notes,
            }
        )
    return out
