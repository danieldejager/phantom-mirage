#!/usr/bin/env python3
"""OS fingerprint probe capture for Phantom Mirage.

Probe set and timing follow the published method description
https://nmap.org/book/osdetect-methods.html (written from that text only).

Sends the standard fingerprint probe set to a single RFC1918/ULA target that
the operator explicitly owns, and records every reply to JSON. Never probes
the public Internet. Use --dry-run to print packets without sending.

This tool does not embed or redistribute any third-party OS fingerprint
database. Derived personalities come only from our own measurements.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow running as `python3 probe.py` from this directory.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from _version import __version__  # noqa: E402
from packetutil import (  # noqa: E402
    build_probe,
    packet_to_hex,
    parse_reply,
)
from probespec import (  # noqa: E402
    METHOD_DOC_URL,
    SEQ_GAP_SEC,
    all_probe_defs,
    probe_plan_summary,
)
from rfc1918 import assert_allowed_targets  # noqa: E402

INTER_GROUP_GAP_SEC = 0.200
RECV_TIMEOUT_SEC = 2.0


def _local_src_ip(dst: str) -> str:
    """Pick a source IP that would be used to reach *dst* (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _describe_packet(pkt: Any) -> dict[str, Any]:
    return {
        "summary": pkt.summary(),
        "hex": packet_to_hex(pkt),
        "len": len(bytes(pkt)),
    }


def build_send_plan(
    *,
    target: str,
    open_tcp: int,
    closed_tcp: int,
    closed_udp: int,
    src_ip: str | None,
) -> list[dict[str, Any]]:
    """Construct every probe packet (offline). Returns metadata + scapy pkt.

    Probe shapes and order: METHOD_DOC_URL ("Probes Sent"). Per run: one random
    non-zero TCP ack (used by every TCP probe except ECN, whose ack is 0) so
    that the S test (reply seq vs probe ack) is meaningful; one random ICMP
    echo id (IE2 uses id + 1). Every TCP probe gets its OWN random 32-bit
    sequence number (not base + i); derive pairs each reply with the probe
    that elicited it, so nothing relies on a relation between probe seqs.
    """
    src = src_ip or _local_src_ip(target)
    plan: list[dict[str, Any]] = []
    base_sport = random.randint(40000, 50000)
    n_probes = len(all_probe_defs())
    seqs: list[int] = []
    while len(seqs) < n_probes:  # distinct, independent per-probe values
        v = random.getrandbits(32)
        if v not in seqs:
            seqs.append(v)
    tcp_ack = random.randint(1, 0xFFFFFFFE)
    base_ipid = random.randint(1, 0xFFFF)
    icmp_id = random.randint(1, 0xFFFE)

    ie_index = 0
    for i, pdef in enumerate(all_probe_defs()):
        pkt = build_probe(
            pdef,
            src_ip=src,
            dst_ip=target,
            open_tcp=open_tcp,
            closed_tcp=closed_tcp,
            closed_udp=closed_udp,
            ip_id=(base_ipid + i) & 0xFFFF,
            tcp_seq=seqs[i],
            tcp_sport=base_sport + i,
            tcp_ack=tcp_ack,
            icmp_id=(icmp_id + ie_index) & 0xFFFF,
        )
        if pdef.kind == "icmp":
            ie_index += 1
        # Probes in a "batch" are sent back to back on a fixed clock (SEQ:
        # exactly SEQ_GAP_SEC apart, as the method requires for ISR/SP/TS).
        batch = pdef.kind if pdef.kind in ("syn_seq", "icmp") else None
        gap = SEQ_GAP_SEC if pdef.kind == "syn_seq" else INTER_GROUP_GAP_SEC
        plan.append(
            {
                "name": pdef.name,
                "kind": pdef.kind,
                "batch": batch,
                "gap_before_sec": 0.0 if i == 0 else gap,
                "packet": pkt,
                "sent_meta": _describe_packet(pkt),
            }
        )
    return plan


def reply_matches(probe: Any, reply: Any) -> bool:
    """Return True if *reply* answers *probe*.

    TCP replies are matched on addresses and ports (src/dst IP, src/dst port,
    protocol). For an RST reply nothing else is checked: observed on the wire,
    page silent -- a Linux or Windows stack answers a probe WITHOUT the ACK
    flag (T2, T3, T7) with RST+ACK seq=0 even though our probe carries a
    non-zero ack field, and scapy's TCP.answers() rejects that pair because
    it compares the probe's ack field with the reply's seq. The S and A
    tests in derive need exactly that reply, so seq/ack must not gate it.
    Non-RST TCP replies keep scapy's own checks on top of the address/port
    match. Non-TCP replies (ICMP echo, ICMP port unreachable for U1) are
    matched by scapy's answers() as before.
    """
    from scapy.layers.inet import IP, TCP  # type: ignore

    if IP not in probe or IP not in reply:
        return bool(reply.answers(probe))
    if TCP in probe and TCP in reply and reply[IP].proto == probe[IP].proto:
        pi, ri, pt, rt = probe[IP], reply[IP], probe[TCP], reply[TCP]
        if not (ri.src == pi.dst and ri.dst == pi.src and rt.sport == pt.dport and rt.dport == pt.sport):
            return False
        if int(rt.flags) & 0x04:  # RST: addresses and ports are enough
            return True
        return bool(reply.answers(probe))
    if TCP in probe or TCP in reply:
        return False
    return bool(reply.answers(probe))


def match_replies(
    sent: list[tuple[Any, float | None]],
    received: list[Any],
    window: float | None = None,
) -> list[Any | None]:
    """Pair each sent probe with the first unclaimed reply that matches it.

    *sent* is (packet, sent_time); *received* is in arrival order (each with
    a .time). A reply is eligible for a probe only inside that probe's own
    window: at or after its send time and, if *window* is given, no later
    than send time + *window*. A late RST therefore cannot be claimed by a
    later probe (ports differ per probe as well).
    """
    used: set[int] = set()
    out: list[Any | None] = []
    for pkt, t_sent in sent:
        hit = None
        for j, r in enumerate(received):
            if j in used:
                continue
            rt = float(getattr(r, "time", 0) or 0)
            if t_sent is not None:
                if rt < t_sent:
                    continue
                if window is not None and rt > t_sent + window:
                    continue
            if reply_matches(pkt, r):
                hit = r
                used.add(j)
                break
        out.append(hit)
    return out


def _route_iface(dst: str) -> Any:
    from scapy.all import conf  # type: ignore

    return conf.route.route(dst)[0]


def wire_send_times(
    pkts: list[Any], post_send: list[float], captured: list[Any]
) -> list[float]:
    """Send time per probe: the capture timestamp of our own outgoing packet
    (what sr() used to record), else the timestamp taken right after send().

    Outgoing packets are found by their IP bytes (src/dst/id/proto plus the
    L4 header), each captured copy used at most once.
    """
    from scapy.layers.inet import IP  # type: ignore

    def key(ip: Any) -> bytes:
        raw = bytes(ip)
        ihl = (raw[0] & 0x0F) * 4
        # ip id (4:6), proto (9), src/dst (12:20), first 8 L4 bytes; skip
        # TTL/checksum fields a capture might show rewritten.
        return raw[4:6] + raw[9:10] + raw[12:20] + raw[ihl : ihl + 8]

    pool: list[tuple[bytes, float]] = [
        (key(c[IP]), float(c.time)) for c in captured if IP in c
    ]
    taken: set[int] = set()
    out: list[float] = []
    for p, fallback in zip(pkts, post_send):
        k = key(p[IP])
        t = fallback
        for j, (ck, ct) in enumerate(pool):
            if j not in taken and ck == k:
                t = ct
                taken.add(j)
                break
        out.append(t)
    return out


def _exchange(
    pkts: list[Any],
    inter: float,
    timeout: float,
    *,
    sniffer_factory: Any = None,
    socket_factory: Any = None,
    clock: Any = time.time,
    sleep: Any = time.sleep,
) -> list[tuple[float | None, Any | None]]:
    """Send *pkts* (L3) *inter* seconds apart on ONE L3 socket while a
    sniffer captures both directions; match replies with reply_matches()
    instead of scapy's sr()/sr1() matcher (see its docstring).

    Send times come from the capture of our own outgoing packets (fallback:
    clock right after the socket's send), because derive uses them for
    ISR/SP/TS and the SEQ probes must be stamped at the wire.
    """
    from scapy.layers.inet import IP  # type: ignore

    if sniffer_factory is None or socket_factory is None:
        from scapy.all import AsyncSniffer, conf  # type: ignore

        target0 = pkts[0][IP].dst
        sniffer_factory = sniffer_factory or (lambda lf: AsyncSniffer(
            iface=_route_iface(target0), lfilter=lf, store=True))
        socket_factory = socket_factory or conf.L3socket

    target = pkts[0][IP].dst
    sniffer = sniffer_factory(lambda r: IP in r and target in (r[IP].src, r[IP].dst))
    sniffer.start()
    sleep(0.05)  # let the capture socket come up before sending
    post_send: list[float] = []
    sock = socket_factory()
    try:
        for k, p in enumerate(pkts):
            if k and inter:
                sleep(inter)
            sock.send(p)
            post_send.append(clock())
        sleep(timeout)
    finally:
        sock.close()
        captured = list(sniffer.stop() or [])
    ips = [_with_time(c[IP], c.time) for c in captured if IP in c]
    outgoing = [c for c in ips if c.dst == target]
    incoming = [c for c in ips if c.src == target]
    sent_times = wire_send_times(pkts, post_send, outgoing)
    replies = match_replies(list(zip(pkts, sent_times)), incoming, window=timeout)
    return list(zip(sent_times, replies))


def _with_time(layer: Any, t: Any) -> Any:
    layer.time = t
    return layer


def _send_and_recv(pkt: Any, timeout: float) -> Any | None:
    return _exchange([pkt], 0.0, timeout)[0][1]


def _send_batch(pkts: list[Any], inter: float, timeout: float) -> list[tuple[float | None, Any | None]]:
    """Send *pkts* on a fixed *inter* clock; return (sent_time, reply) per packet."""
    return _exchange(pkts, inter, timeout)


def run_once(
    *,
    target: str,
    open_tcp: int,
    closed_tcp: int,
    closed_udp: int,
    dry_run: bool,
    src_ip: str | None,
    cmdline: list[str],
    run_index: int,
) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    plan = build_send_plan(
        target=target,
        open_tcp=open_tcp,
        closed_tcp=closed_tcp,
        closed_udp=closed_udp,
        src_ip=src_ip,
    )
    exchanges: list[dict[str, Any]] = []
    t0 = time.monotonic()
    t0_wall = time.time()

    i = 0
    while i < len(plan):
        item = plan[i]
        group = [item]
        if item["batch"]:
            while i + len(group) < len(plan) and plan[i + len(group)]["batch"] == item["batch"]:
                group.append(plan[i + len(group)])
        gap = item["gap_before_sec"]
        if gap and not dry_run:
            time.sleep(gap)

        if dry_run:
            results = [(None, None)] * len(group)
        elif len(group) > 1:
            inter = SEQ_GAP_SEC if item["batch"] == "syn_seq" else 0.0
            results = _send_batch([g["packet"] for g in group], inter, RECV_TIMEOUT_SEC)
        else:
            results = _send_batch([item["packet"]], 0.0, RECV_TIMEOUT_SEC)

        for k, (g, (sent_wall, reply)) in enumerate(zip(group, results)):
            if sent_wall is not None:
                sent_at = sent_wall - t0_wall
            elif dry_run and item["batch"] == "syn_seq":
                sent_at = (time.monotonic() - t0) + k * SEQ_GAP_SEC
            else:
                sent_at = time.monotonic() - t0
            record: dict[str, Any] = {
                "name": g["name"],
                "kind": g["kind"],
                "gap_before_sec": g["gap_before_sec"] if k == 0 else (SEQ_GAP_SEC if g["kind"] == "syn_seq" else 0.0),
                # Actual send time; derive.py uses these (not nominal gaps)
                # for ISR / SP / TS, as the method describes.
                "sent_at_offset_sec": round(sent_at, 6),
                "sent": g["sent_meta"],
                "sent_parsed": parse_reply(g["packet"]),
                "reply": None,
                "reply_parsed": None,
                "timeout": False,
            }
            if dry_run:
                record["dry_run"] = True
            elif reply is None:
                record["timeout"] = True
            else:
                record["reply"] = _describe_packet(reply)
                record["reply_parsed"] = parse_reply(reply)
            exchanges.append(record)
        i += len(group)

    return {
        "run_id": run_id,
        "run_index": run_index,
        "tool": "fingerprint-lab/probe.py",
        "tool_version": __version__,
        "timestamp": _now_iso(),
        "cmdline": cmdline,
        "target": target,
        "ports": {
            "open_tcp": open_tcp,
            "closed_tcp": closed_tcp,
            "closed_udp": closed_udp,
        },
        "dry_run": dry_run,
        "probe_method_doc": METHOD_DOC_URL,
        "probe_plan": probe_plan_summary(),
        "exchanges": exchanges,
    }


def write_run(doc: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"run-{doc['run_id']}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return path


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="probe.py",
        description=(
            "Capture OS fingerprint replies from a host you own "
            "(RFC1918/ULA only). Never probes the public Internet."
        ),
    )
    p.add_argument("target", help="Target IPv4/IPv6 (RFC1918 or ULA)")
    p.add_argument("--open-tcp", type=int, required=True, help="Known-open TCP port")
    p.add_argument("--closed-tcp", type=int, required=True, help="Known-closed TCP port")
    p.add_argument("--closed-udp", type=int, required=True, help="Closed UDP port")
    p.add_argument(
        "--i-own-these-hosts",
        action="store_true",
        help="Required confirmation that you own every target on the command line",
    )
    p.add_argument("--runs", type=int, default=1, help="Repeat full probe set N times")
    p.add_argument("--output", type=Path, default=Path("fingerprint-runs"), help="Output directory")
    p.add_argument("--src-ip", default=None, help="Override source IP (default: route to target)")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and print packets without sending anything",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_arg_parser().parse_args(argv)

    assert_allowed_targets([args.target], i_own_flag=args.i_own_these_hosts)

    if args.runs < 1:
        print("--runs must be >= 1", file=sys.stderr)
        return 2

    cmdline = ["probe.py", *argv]
    written: list[Path] = []
    for i in range(args.runs):
        doc = run_once(
            target=args.target,
            open_tcp=args.open_tcp,
            closed_tcp=args.closed_tcp,
            closed_udp=args.closed_udp,
            dry_run=args.dry_run,
            src_ip=args.src_ip,
            cmdline=cmdline,
            run_index=i,
        )
        path = write_run(doc, args.output)
        written.append(path)
        if args.dry_run:
            print(f"[dry-run] run {i}: would send {len(doc['exchanges'])} probes -> {path}")
            for ex in doc["exchanges"]:
                print(f"  {ex['name']:5s}  {ex['sent']['summary']}")
        else:
            print(f"run {i}: wrote {path}")

    print(f"done: {len(written)} run file(s) in {args.output}")
    return 0


if __name__ == "__main__":
    # Harden: never inherit a proxy that could redirect traffic.
    for k in list(os.environ):
        if k.lower().endswith("_proxy"):
            os.environ.pop(k, None)
    raise SystemExit(main())
