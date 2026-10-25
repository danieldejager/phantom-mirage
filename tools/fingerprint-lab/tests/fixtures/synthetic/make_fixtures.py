#!/usr/bin/env python3
"""Regenerate the SYNTHETIC capture fixtures used by test_build_db.py.

Everything written here is invented example data. It is NOT a capture of any
real system, and no packet was sent to produce it. The nmap.xml / nmap.txt /
p0f.log / personality.txt / derive-report.json files exist only so tests can
prove build_db.py never reads them; they hold marker strings, not real tool
output.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER = "SYNTHETIC-MARKER-{}-MUST-NOT-APPEAR"


def _tcp(seq, ack, window, flags, options, ip_id, ttl, df=True):
    return {"l4": "tcp", "seq": seq, "ack": ack, "window": window, "flags": flags,
            "options": options, "options_raw": [["MSS", 1460], ["Timestamp", [7, 0]]] if options else [],
            "ip_id": ip_id, "ip_ttl": ttl, "ip_df": df}


def run_doc(run_id, *, ip, open_tcp, ttl, window, options, isn_mults):
    """isn_mults: five multipliers of 1000 for the SEQ1..SEQ6 ISN deltas."""
    ex = []
    base = 0x20000000
    isns = [base]
    for m in isn_mults:
        isns.append(isns[-1] + m * 1000)
    for i in range(1, 7):
        ex.append({"name": f"SEQ{i}", "kind": "syn_seq", "gap_before_sec": 0.0 if i == 1 else 0.1,
                   "timeout": False, "sent_parsed": {"seq": 1000 + i, "ack": 0},
                   "reply_parsed": _tcp(isns[i - 1], 1001 + i, window, "SA", options, 100 + i, ttl)})
    ex.append({"name": "ECN", "kind": "ecn", "gap_before_sec": 0.2, "timeout": False,
               "sent_parsed": {"seq": 2000, "ack": 0},
               "reply_parsed": _tcp(base, 2001, window, "SA", options, 120, ttl)})
    for name, flags in [("T2", None), ("T3", None), ("T4", "R"), ("T5", "RA"), ("T6", "R"), ("T7", "RA")]:
        sent = {"seq": 3000, "ack": 4000}
        rp = None if flags is None else _tcp(4000 if flags == "R" else 0, 0 if flags == "R" else 3001,
                                              0, flags, "", 0, ttl, df=False)
        ex.append({"name": name, "kind": "tcp_unusual", "gap_before_sec": 0.2, "timeout": rp is None,
                   "sent_parsed": sent, "reply_parsed": rp})
    for i, name in enumerate(("IE1", "IE2"), start=1):
        ex.append({"name": name, "kind": "icmp", "gap_before_sec": 0.2, "timeout": False,
                   "reply_parsed": {"l4": "icmp", "icmp_type": 0, "icmp_code": 0,
                                    "ip_id": 200 + i, "ip_ttl": ttl, "ip_df": False}})
    ex.append({"name": "U1", "kind": "udp", "gap_before_sec": 0.2, "timeout": False,
               "reply_parsed": {"l4": "icmp", "icmp_type": 3, "icmp_code": 3, "ip_id": 300,
                                "ip_ttl": ttl, "ip_df": False, "ip_len": 356,
                                "embedded_ip_id": 42, "embedded_ip_len": 328}})
    return {"run_id": run_id, "run_index": 0, "tool": "fingerprint-lab/probe.py",
            "tool_version": "0.1.0", "timestamp": "2000-01-01T00:00:00Z (SYNTHETIC)",
            "cmdline": ["SYNTHETIC", "example", "no packets sent"], "target": ip,
            "ports": {"open_tcp": open_tcp, "closed_tcp": 1, "closed_udp": 40000},
            "dry_run": False, "probe_plan": "SYNTHETIC", "exchanges": ex}


def tool_versions(target, ip, port, fw):
    return "\n".join([
        "captured_utc=2000-01-01T00:00:00Z",
        f"target={target} vm=SYNTHETIC-{target} ip={ip} open_tcp={port} closed_tcp=1 closed_udp=40000 runs=3 firewall={fw}",
        "probe_host=SYNTHETIC-EXAMPLE",
        "kernel=0.0.0-synthetic",
        "os_release=SYNTHETIC example data",
        "nmap_version=Nmap version 0.0 (synthetic)",
        "nmap_os_db=" + MARKER.format("NMAPOSDB"),
        "python_version=Python 3.0.0 (synthetic)",
        "scapy_version=0.0.0-synthetic",
        "tool_source_commit=0000000000000000000000000000000000000000",
        "pcap_bytes=0",
    ]) + "\n"


def write_case(target, run_name, ip, port, fw, ttl, window, options, steps):
    d = HERE / target / run_name
    d.mkdir(parents=True, exist_ok=True)
    for n, step in enumerate(steps, start=1):
        rid = f"synthetic-{target}-{n:04d}"
        doc = run_doc(rid, ip=ip, open_tcp=port, ttl=ttl, window=window, options=options, isn_mults=step)
        (d / f"run-{rid}.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    (d / "tool-versions.txt").write_text(tool_versions(target, ip, port, fw), encoding="utf-8")
    for fname, tag in [("nmap.xml", "NMAPXML"), ("nmap.txt", "NMAPTXT"), ("p0f.log", "P0F"),
                       ("personality.txt", "PERSTXT"), ("derive-report.json", "DERIVEREPORT")]:
        (d / fname).write_text(
            f"SYNTHETIC decoy file, never an input. {MARKER.format(tag)}\n"
            f"Fingerprint {MARKER.format(tag + '-FP')}\n", encoding="utf-8")


if __name__ == "__main__":
    # ISN deltas differ per run (same GCD of 1000) so SP/ISR differ and the
    # range rule is exercised; the ubuntu2404 case has identical runs.
    write_case("ws2022", "run-900001-1-fwon", "10.0.0.22", 3389, "on", 128, 0xFFFF,
               "M5B4NW8NNS", [[40, 41, 39, 40, 42], [50, 47, 52, 49, 51], [40, 43, 38, 41, 40]])
    write_case("ubuntu2404", "run-900002-1-fwon", "10.0.0.21", 22, "on", 64, 0xFAF0,
               "M5B4ST11NW7", [[30, 31, 29, 30, 30]] * 3)
