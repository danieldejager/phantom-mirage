#!/usr/bin/env python3
"""OS fingerprint probe capture for Phantom Mirage.

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
    SEQ_PROBES,
    T_PROBES,
    ECN_PROBE,
    ICMP_PROBES,
    UDP_PROBE,
    all_probe_defs,
    probe_plan_summary,
)
from rfc1918 import assert_allowed_targets  # noqa: E402

SEQ_GAP_SEC = 0.100
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
    """Construct every probe packet (offline). Returns metadata + scapy pkt."""
    src = src_ip or _local_src_ip(target)
    plan: list[dict[str, Any]] = []
    base_sport = random.randint(40000, 50000)
    base_seq = random.randint(0, 0x7FFFFFFF)
    base_ipid = random.randint(1, 0xFFFF)

    ordered = list(SEQ_PROBES) + [ECN_PROBE] + list(T_PROBES) + list(ICMP_PROBES) + [UDP_PROBE]
    for i, pdef in enumerate(ordered):
        pkt = build_probe(
            pdef,
            src_ip=src,
            dst_ip=target,
            open_tcp=open_tcp,
            closed_tcp=closed_tcp,
            closed_udp=closed_udp,
            ip_id=(base_ipid + i) & 0xFFFF,
            tcp_seq=(base_seq + i * 1000) & 0xFFFFFFFF,
            tcp_sport=base_sport + i,
        )
        gap = SEQ_GAP_SEC if pdef.kind == "syn_seq" else INTER_GROUP_GAP_SEC
        plan.append(
            {
                "name": pdef.name,
                "kind": pdef.kind,
                "gap_before_sec": 0.0 if i == 0 else gap,
                "packet": pkt,
                "sent_meta": _describe_packet(pkt),
            }
        )
    return plan


def _send_and_recv(pkt: Any, timeout: float) -> Any | None:
    # Imported lazily so unit tests that never send need only scapy offline.
    from scapy.all import sr1  # type: ignore

    return sr1(pkt, timeout=timeout, verbose=0)


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

    for item in plan:
        gap = item["gap_before_sec"]
        if gap and not dry_run:
            time.sleep(gap)
        elif gap and dry_run:
            pass

        sent_at = time.monotonic() - t0
        sent_parsed = parse_reply(item["packet"])
        record: dict[str, Any] = {
            "name": item["name"],
            "kind": item["kind"],
            "gap_before_sec": gap,
            "sent_at_offset_sec": round(sent_at, 4),
            "sent": item["sent_meta"],
            "sent_parsed": sent_parsed,
            "reply": None,
            "reply_parsed": None,
            "timeout": False,
        }

        if dry_run:
            record["dry_run"] = True
        else:
            reply = _send_and_recv(item["packet"], RECV_TIMEOUT_SEC)
            if reply is None:
                record["timeout"] = True
            else:
                record["reply"] = _describe_packet(reply)
                record["reply_parsed"] = parse_reply(reply)

        exchanges.append(record)

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
