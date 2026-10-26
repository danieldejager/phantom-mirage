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
import random
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
MARKER = "SYNTHETIC-MARKER-{}-MUST-NOT-APPEAR"


OPT_RAW = {  # letter form -> options_raw (as probe.py records it)
    "M5B4ST11NW7": [["MSS", 1460], ["SAckOK", ""], ["Timestamp", None], ["NOP", None], ["WScale", 7]],
    "M5B4NW8NNS": [["MSS", 1460], ["NOP", None], ["WScale", 8], ["NOP", None], ["NOP", None], ["SAckOK", ""]],
}


def _tcp(seq, ack, window, flags, options, ip_id, ttl, df=True, tsval=None):
    raw = [list(o) for o in OPT_RAW.get(options, [])]
    for o in raw:
        if o[0] == "Timestamp":
            o[1] = [tsval or 1, 0xFFFFFFFF]
    return {"l4": "tcp", "seq": seq, "ack": ack, "window": window, "flags": flags,
            "options": options, "options_raw": raw, "reserved": 0, "urgptr": 0,
            "ip_id": ip_id, "ip_ttl": ttl, "ip_df": df}


def run_doc(run_id, *, ip, open_tcp, ttl, window, options, isn_mults):
    """isn_mults: five multipliers of 1000 for the SEQ1..SEQ6 ISN deltas.

    Exchanges follow probe.py 0.3.0: SEQ probes 100 ms apart with a non-zero
    ack, then IE1/IE2, U1, ECN (ack 0), T2-T7. TSvals tick at 1000 Hz."""
    ack = 0x5000
    # Per-probe random sequence numbers, as probe.py 0.3.1 sends them; seeded
    # from the run id so the fixtures (and goldens) are reproducible.
    rng = random.Random(zlib.crc32(run_id.encode()))
    pseq = {n: rng.getrandbits(32) for n in
            [f"SEQ{i}" for i in range(1, 7)] + ["ECN", "T2", "T3", "T4", "T5", "T6", "T7"]}
    ex = []
    base = 0x20000000
    isns = [base]
    for m in isn_mults:
        isns.append(isns[-1] + m * 1000)
    for i in range(1, 7):
        t = round(0.1 * (i - 1), 6)
        ex.append({"name": f"SEQ{i}", "kind": "syn_seq", "gap_before_sec": 0.0 if i == 1 else 0.1,
                   "sent_at_offset_sec": t, "timeout": False,
                   "sent_parsed": {"l4": "tcp", "seq": pseq[f"SEQ{i}"], "ack": ack, "ip_df": False, "ip_ttl": 64},
                   "reply_parsed": _tcp(isns[i - 1], (pseq[f"SEQ{i}"] + 1) & 0xFFFFFFFF, window, "SA", options, 100 + i, ttl,
                                        tsval=5000 + int(t * 1000))})
    for i, (name, code, df) in enumerate((("IE1", 9, True), ("IE2", 0, False)), start=1):
        ex.append({"name": name, "kind": "icmp", "gap_before_sec": 0.2, "sent_at_offset_sec": 0.7 + i / 100,
                   "timeout": False,
                   "sent_parsed": {"l4": "icmp", "icmp_type": 8, "icmp_code": code, "ip_df": df, "ip_ttl": 64},
                   "reply_parsed": {"l4": "icmp", "icmp_type": 0, "icmp_code": 0,
                                    "ip_id": 200 + i, "ip_ttl": ttl, "ip_df": False}})
    ex.append({"name": "U1", "kind": "udp", "gap_before_sec": 0.2, "sent_at_offset_sec": 0.9, "timeout": False,
               "sent_parsed": {"l4": "udp", "ip_id": 0x1042, "ip_df": False, "ip_ttl": 64},
               "reply_parsed": {"l4": "icmp", "icmp_type": 3, "icmp_code": 3, "icmp_unused": 0,
                                "ip_id": 300, "ip_ttl": ttl, "ip_df": False, "ip_len": 356,
                                "embedded_ip_id": 0x1042, "embedded_ip_len": 328, "embedded_ip_ttl": 64}})
    ex.append({"name": "ECN", "kind": "ecn", "gap_before_sec": 0.2, "sent_at_offset_sec": 1.1, "timeout": False,
               "sent_parsed": {"l4": "tcp", "seq": pseq["ECN"], "ack": 0, "ip_df": False, "ip_ttl": 64},
               "reply_parsed": _tcp(base, (pseq["ECN"] + 1) & 0xFFFFFFFF, window, "SA", options, 120, ttl)})
    for k, (name, flags) in enumerate([("T2", None), ("T3", None), ("T4", "R"), ("T5", "RA"),
                                       ("T6", "R"), ("T7", "RA")]):
        sent = {"l4": "tcp", "seq": pseq[name], "ack": ack, "ip_df": name in ("T2", "T4", "T6"), "ip_ttl": 64}
        rp = None if flags is None else _tcp(ack if flags == "R" else 0, 0 if flags == "R" else (pseq[name] + 1) & 0xFFFFFFFF,
                                              0, flags, "", 0, ttl, df=False)
        ex.append({"name": name, "kind": "tcp_unusual", "gap_before_sec": 0.2,
                   "sent_at_offset_sec": round(1.3 + 0.2 * k, 6), "timeout": rp is None,
                   "sent_parsed": sent, "reply_parsed": rp})
    return {"run_id": run_id, "run_index": 0, "tool": "fingerprint-lab/probe.py",
            "tool_version": "0.3.2", "timestamp": "2000-01-01T00:00:00Z (SYNTHETIC)",
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
