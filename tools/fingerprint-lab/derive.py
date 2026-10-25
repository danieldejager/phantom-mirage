#!/usr/bin/env python3
"""Derive a draft honeyd personality entry from fingerprint-lab run JSONs.

Reads one or more run files for a single OS (operator-supplied name/build),
computes the fields honeyd's personality.c parses (SEQ, OPS, WIN, ECN,
T1-T7, U1, IE), reports observed ranges across runs, and flags fields that
vary. Output is honeyd syntax with a comment block citing run ids.

No third-party OS fingerprint database content is consulted or emitted.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from _version import __version__  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_runs(paths: list[Path]) -> list[dict[str, Any]]:
    runs = []
    for p in paths:
        doc = json.loads(p.read_text(encoding="utf-8"))
        if "exchanges" not in doc or "run_id" not in doc:
            raise SystemExit(f"not a fingerprint-lab run JSON: {p}")
        runs.append(doc)
    return runs


def _ex_by_name(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {ex["name"]: ex for ex in run.get("exchanges", [])}


def _parsed(ex: dict[str, Any] | None) -> dict[str, Any] | None:
    if not ex:
        return None
    if ex.get("timeout") or not ex.get("reply_parsed"):
        return None
    return ex["reply_parsed"]


def _gcd_list(nums: list[int]) -> int:
    g = 0
    for n in nums:
        g = math.gcd(g, abs(n))
    return g or 1


def _classify_ipid(ids: list[int]) -> str:
    """Classify IP-ID behaviour from a short series of reply IDs."""
    if not ids:
        return "RD"
    if all(i == 0 for i in ids):
        return "Z"
    if len(ids) == 1:
        return "RD"
    diffs = [(ids[i + 1] - ids[i]) & 0xFFFF for i in range(len(ids) - 1)]
    if all(d == 0 for d in diffs):
        return f"{ids[0]:X}"  # constant
    if all(d == 1 for d in diffs):
        return "I"
    if all(d == 256 for d in diffs):
        return "BI"
    # Random positive increments in a modest range → RI heuristic
    if all(1 <= d <= 1279 for d in diffs):
        return "RI"
    return "RD"


def _ts_class(options_raw_list: list[list]) -> str:
    """Rough TCP timestamp class from option presence across SEQ replies."""
    ts_vals = []
    for opts in options_raw_list:
        for name, val in opts or []:
            if name in ("Timestamp", "TSval", "T") and isinstance(val, (tuple, list)):
                ts_vals.append(int(val[0]))
    if not ts_vals:
        return "U"  # unsupported / absent
    if all(v == 0 for v in ts_vals):
        return "0"
    # Presence of non-zero timestamps; finer Hz needs timed captures.
    return "1"


def _ttl_guess(observed: list[int]) -> tuple[str, str]:
    """Return (T=observed_hex, TG=likely_initial_hex) from reply TTLs."""
    if not observed:
        return ("", "")
    # Use median observed; guess common initial TTL bucket.
    obs = sorted(observed)[len(observed) // 2]
    for initial in (32, 64, 128, 255):
        if obs <= initial:
            return (f"{obs:X}", f"{initial:X}")
    return (f"{obs:X}", f"{obs:X}")


def _seq_metrics(seqs: list[int], gaps_sec: list[float]) -> dict[str, Any]:
    """Compute GCD / rough SP / ISR from ISN samples (SEQ1..SEQ6)."""
    if len(seqs) < 2:
        return {"GCD": 1, "SP": 0, "ISR": 0, "note": "insufficient ISN samples"}
    diffs = [(seqs[i + 1] - seqs[i]) & 0xFFFFFFFF for i in range(len(seqs) - 1)]
    # Treat as signed for GCD of step sizes commonly used in literature.
    signed = [d if d < 0x80000000 else d - 0x100000000 for d in diffs]
    gcd = _gcd_list([abs(s) for s in signed if s != 0] or [1])
    # SP/ISR are log-scaled predictability / rate; without precise timing we
    # emit placeholders derived from diff magnitude so the draft is filled.
    mean_abs = sum(abs(s) for s in signed) / max(len(signed), 1)
    # ISR ~ 8*log2(rate); approximate rate from mean diff / mean gap.
    mean_gap = (sum(gaps_sec) / len(gaps_sec)) if gaps_sec else 0.1
    rate = mean_abs / max(mean_gap, 1e-3)
    isr = int(round(8 * math.log2(rate))) if rate > 1 else 0
    isr = max(0, min(0xFF, isr))
    # SP: lower when diffs are regular; higher when noisy. Coarse stand-in.
    if len(signed) >= 2:
        var = sum((abs(s) - mean_abs) ** 2 for s in signed) / len(signed)
        sp = int(round(8 * math.log2(math.sqrt(var) + 1))) if var > 0 else 0
    else:
        sp = 0
    sp = max(0, min(0xFF, sp))
    return {"GCD": gcd, "SP": sp, "ISR": isr, "diffs": signed}


@dataclass
class FieldObs:
    values: list[Any] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # run_ids

    def add(self, value: Any, run_id: str) -> None:
        self.values.append(value)
        self.sources.append(run_id)

    def unanimous(self) -> bool:
        if not self.values:
            return True
        return len({json.dumps(v, sort_keys=True, default=str) for v in self.values}) == 1

    def draft_value(self) -> Any:
        if not self.values:
            return None
        # Prefer first; caller flags variance.
        return self.values[0]

    def range_note(self) -> str:
        uniq = []
        for v in self.values:
            key = json.dumps(v, sort_keys=True, default=str)
            if key not in {json.dumps(u, sort_keys=True, default=str) for u in uniq}:
                uniq.append(v)
        if len(uniq) <= 1:
            return "stable"
        return f"VARIES across runs: {uniq}"


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------

def derive(runs: list[dict[str, Any]], *, os_name: str, os_build: str) -> dict[str, Any]:
    obs: dict[str, FieldObs] = defaultdict(FieldObs)
    run_ids = [r["run_id"] for r in runs]

    for run in runs:
        rid = run["run_id"]
        by = _ex_by_name(run)

        # SEQ series replies
        seq_parsed = [_parsed(by.get(f"SEQ{i}")) for i in range(1, 7)]
        seqs = [p["seq"] for p in seq_parsed if p and "seq" in p]
        gaps = []
        for i in range(1, 7):
            ex = by.get(f"SEQ{i}")
            if ex:
                gaps.append(float(ex.get("gap_before_sec") or 0.1))
        metrics = _seq_metrics(seqs, gaps[1:] if gaps else [])
        obs["SEQ.GCD"].add(metrics["GCD"], rid)
        obs["SEQ.SP"].add(metrics["SP"], rid)
        obs["SEQ.ISR"].add(metrics["ISR"], rid)

        ip_ids = [p["ip_id"] for p in seq_parsed if p]
        obs["SEQ.TI"].add(_classify_ipid(ip_ids), rid)

        opts_raw = [p.get("options_raw") or [] for p in seq_parsed if p]
        obs["SEQ.TS"].add(_ts_class(opts_raw), rid)

        # OPS / WIN from SEQ replies (O1..O6, W1..W6)
        for i, p in enumerate(seq_parsed, start=1):
            if not p:
                obs[f"OPS.O{i}"].add("", rid)
                obs[f"WIN.W{i}"].add(None, rid)
                continue
            obs[f"OPS.O{i}"].add(p.get("options") or "", rid)
            obs[f"WIN.W{i}"].add(p.get("window"), rid)

        # Closed-port TCP replies contribute CI
        closed_ids = []
        for name in ("T5", "T6", "T7"):
            p = _parsed(by.get(name))
            if p:
                closed_ids.append(p["ip_id"])
        obs["SEQ.CI"].add(_classify_ipid(closed_ids), rid)

        # ICMP IE pair → II and IE line
        ie_ids = []
        ie_ttls = []
        ie_dfs = []
        ie_replies = 0
        for name in ("IE1", "IE2"):
            p = _parsed(by.get(name))
            if p and p.get("l4") == "icmp":
                ie_replies += 1
                ie_ids.append(p["ip_id"])
                ie_ttls.append(p["ip_ttl"])
                ie_dfs.append(p["ip_df"])
        obs["SEQ.II"].add(_classify_ipid(ie_ids), rid)
        # SS: shared sequence if TCP and ICMP IP-ID sequences look coupled — heuristic off by default
        obs["SEQ.SS"].add("O", rid)  # O = not shared (safe default without more samples)

        # ECN
        _record_tcp_test(obs, "ECN", _parsed(by.get("ECN")), rid, by.get("ECN", {}).get("sent_parsed"))

        # T1 uses SEQ1 reply category in classic sets
        _record_tcp_test(
            obs, "T1", seq_parsed[0] if seq_parsed else None, rid,
            by.get("SEQ1", {}).get("sent_parsed"),
        )
        for name in ("T2", "T3", "T4", "T5", "T6", "T7"):
            _record_tcp_test(obs, name, _parsed(by.get(name)), rid, by.get(name, {}).get("sent_parsed"))

        # U1
        u1 = _parsed(by.get("U1"))
        if not u1:
            obs["U1.R"].add("N", rid)
        else:
            obs["U1.R"].add("Y", rid)
            obs["U1.DF"].add("Y" if u1.get("ip_df") else "N", rid)
            t, tg = _ttl_guess([u1["ip_ttl"]])
            obs["U1.T"].add(t, rid)
            obs["U1.TG"].add(tg, rid)
            # IP length of unreachable reply (unaligned length quirks left as observed)
            if u1.get("ip_len") is not None:
                obs["U1.IPL"].add(f"{int(u1['ip_len']):X}", rid)
            if u1.get("embedded_ip_len") is not None:
                # unused length of returned probe — informational
                obs["U1.UN"].add(f"{int(u1['embedded_ip_len']):X}", rid)

        # IE aggregate
        if ie_replies == 0:
            obs["IE.R"].add("N", rid)
        else:
            obs["IE.R"].add("Y", rid)
            # DFI: DF behaviour across the pair
            if not ie_dfs:
                dfi = "N"
            elif all(ie_dfs) and ie_dfs[0]:
                dfi = "Y"
            elif not any(ie_dfs):
                dfi = "N"
            else:
                dfi = "S"  # echo DF of request (simplified)
            obs["IE.DFI"].add(dfi, rid)
            t, tg = _ttl_guess(ie_ttls)
            obs["IE.T"].add(t, rid)
            obs["IE.TG"].add(tg, rid)
            obs["IE.CD"].add("Z", rid)  # code zero common default; refine from replies if needed

    return {
        "os_name": os_name,
        "os_build": os_build,
        "run_ids": run_ids,
        "fields": {k: {"values": v.values, "sources": v.sources, "stable": v.unanimous(), "note": v.range_note()} for k, v in sorted(obs.items())},
        "obs": obs,
    }


def _record_tcp_test(
    obs: dict[str, FieldObs],
    prefix: str,
    p: dict[str, Any] | None,
    rid: str,
    sent: dict[str, Any] | None = None,
) -> None:
    if not p or p.get("l4") != "tcp":
        obs[f"{prefix}.R"].add("N", rid)
        return
    obs[f"{prefix}.R"].add("Y", rid)
    obs[f"{prefix}.DF"].add("Y" if p.get("ip_df") else "N", rid)
    t, tg = _ttl_guess([p["ip_ttl"]])
    obs[f"{prefix}.T"].add(t, rid)
    obs[f"{prefix}.TG"].add(tg, rid)
    if p.get("window") is not None:
        obs[f"{prefix}.W"].add(f"{int(p['window']):X}", rid)
    obs[f"{prefix}.S"].add(_seq_ack_relation(p, sent), rid)
    obs[f"{prefix}.A"].add(_ack_relation(p, sent), rid)
    obs[f"{prefix}.F"].add(_flags_letters(p.get("flags") or ""), rid)
    obs[f"{prefix}.O"].add(p.get("options") or "", rid)
    if prefix == "ECN":
        obs["ECN.CC"].add(ecn_cc(p), rid)
    # RD (RST data checksum quirk) left unset unless payload present
    obs[f"{prefix}.Q"].add("", rid)


TH_ECE = 0x40
TH_CWR = 0x80


def ecn_cc(p: dict[str, Any]) -> str:
    """nmap ECN CC for the reply to the ECN probe (scoring gate F13).

    Y = ECE only, N = neither, S = ECE and CWR, O = any other combination
    (that is, CWR without ECE; personality.c maps O to CWR only).
    Uses the raw ``flags_bits`` (tool_version >= 0.2.0) when present, else
    scapy's flag letters (E = ECE, C = CWR) from older runs.
    """
    bits = p.get("flags_bits")
    if isinstance(bits, int) and not isinstance(bits, bool):
        ece, cwr = bool(bits & TH_ECE), bool(bits & TH_CWR)
    else:
        letters = str(p.get("flags") or "")
        ece, cwr = "E" in letters, "C" in letters
    if ece and cwr:
        return "S"
    if ece:
        return "Y"
    if cwr:
        return "O"
    return "N"


def _flags_letters(flags: str) -> str:
    # Normalize scapy flag strings like 'SA' / 'R' into personality F= form.
    order = ["E", "U", "A", "P", "R", "S", "F"]
    present = set(flags.upper())
    return "".join(c for c in order if c in present) or ""


def _seq_ack_relation(p: dict[str, Any], sent: dict[str, Any] | None) -> str:
    """Map reply SEQ to probe SEQ/ACK: Z / A / A+ / O (honeyd letters)."""
    seq = int(p.get("seq") or 0)
    if seq == 0:
        return "Z"
    if not sent:
        return "O"
    probe_seq = int(sent.get("seq") or 0)
    probe_ack = int(sent.get("ack") or 0)
    if seq == probe_ack:
        return "A"
    if seq == (probe_ack + 1) & 0xFFFFFFFF:
        return "A+"
    if seq == probe_seq:
        return "S"
    return "O"


def _ack_relation(p: dict[str, Any], sent: dict[str, Any] | None) -> str:
    """Map reply ACK to probe SEQ: Z / S / S+ / O."""
    ack = int(p.get("ack") or 0)
    if ack == 0:
        return "Z"
    if not sent:
        return "O"
    probe_seq = int(sent.get("seq") or 0)
    if ack == probe_seq:
        return "S"
    if ack == (probe_seq + 1) & 0xFFFFFFFF:
        return "S+"
    return "O"


def render_personality(result: dict[str, Any]) -> str:
    obs: dict[str, FieldObs] = result["obs"]
    os_name = result["os_name"]
    os_build = result["os_build"]
    run_ids = result["run_ids"]

    varying = [k for k, fo in obs.items() if not fo.unanimous()]

    lines: list[str] = []
    lines.append("# Draft honeyd personality — derived ONLY from our measurements.")
    lines.append(f"# OS name/build (operator): {os_name} / {os_build}")
    lines.append(f"# Source run_ids: {', '.join(run_ids)}")
    lines.append(f"# derive.py version: {__version__}")
    if varying:
        lines.append(f"# WARNING: fields that VARIED across runs: {', '.join(varying)}")
    else:
        lines.append("# All derived fields were stable across the supplied runs.")
    lines.append("# Review every value before loading into Phantom Mirage.")
    lines.append("#")
    # Provenance block
    lines.append("# Field provenance:")
    for key, fo in sorted(obs.items()):
        val = fo.draft_value()
        lines.append(f"#   {key} = {val!r}  ({fo.range_note()}; runs={','.join(fo.sources)})")
    lines.append("")
    lines.append(f"Fingerprint {os_name}")

    def g(key: str, default: str = "") -> str:
        fo = obs.get(key)
        if not fo or fo.draft_value() is None:
            return default
        v = fo.draft_value()
        return default if v is None or v == "" else str(v)

    def hx(key: str) -> str:
        fo = obs.get(key)
        if not fo or fo.draft_value() is None:
            return "0"
        v = fo.draft_value()
        if isinstance(v, int):
            return f"{v:X}"
        return str(v)

    seq = (
        f"SEQ(SP={hx('SEQ.SP')}%GCD={hx('SEQ.GCD')}%ISR={hx('SEQ.ISR')}%"
        f"TI={g('SEQ.TI','RD')}%CI={g('SEQ.CI','RD')}%II={g('SEQ.II','RD')}%"
        f"SS={g('SEQ.SS','O')}%TS={g('SEQ.TS','U')})"
    )
    lines.append(seq)

    ops = "OPS(" + "%".join(f"O{i}={g(f'OPS.O{i}')}" for i in range(1, 7)) + ")"
    lines.append(ops)

    win_parts = []
    for i in range(1, 7):
        fo = obs.get(f"WIN.W{i}")
        if fo and isinstance(fo.draft_value(), int):
            win_parts.append(f"W{i}={fo.draft_value():X}")
        else:
            win_parts.append(f"W{i}=")
    lines.append("WIN(" + "%".join(win_parts) + ")")

    def tcp_line(prefix: str) -> str:
        if g(f"{prefix}.R", "N") == "N":
            return f"{prefix}(R=N)"
        parts = [
            "R=Y",
            f"DF={g(f'{prefix}.DF','N')}",
            f"T={g(f'{prefix}.T')}",
            f"TG={g(f'{prefix}.TG')}",
        ]
        if g(f"{prefix}.W"):
            parts.append(f"W={g(f'{prefix}.W')}")
        parts += [
            f"S={g(f'{prefix}.S','O')}",
            f"A={g(f'{prefix}.A','O')}",
            f"F={g(f'{prefix}.F')}",
            f"O={g(f'{prefix}.O')}",
            f"RD=0",
            f"Q={g(f'{prefix}.Q')}",
        ]
        return f"{prefix}(" + "%".join(parts) + ")"

    # ECN uses its own field set: personality.c's parse_ecn accepts only
    # R, DF, T, TG, W, O, CC, Q (not the T-line S/A/F/RD).
    if g("ECN.R", "N") == "N":
        lines.append("ECN(R=N)")
    else:
        ecn = ["R=Y", f"DF={g('ECN.DF','N')}", f"T={g('ECN.T')}", f"TG={g('ECN.TG')}"]
        if g("ECN.W"):
            ecn.append(f"W={g('ECN.W')}")
        ecn += [f"O={g('ECN.O')}", f"CC={g('ECN.CC','N')}", f"Q={g('ECN.Q')}"]
        lines.append("ECN(" + "%".join(ecn) + ")")
    for t in ("T1", "T2", "T3", "T4", "T5", "T6", "T7"):
        lines.append(tcp_line(t))

    if g("U1.R", "N") == "N":
        lines.append("U1(R=N)")
    else:
        u1_parts = [
            "R=Y",
            f"DF={g('U1.DF','N')}",
            f"T={g('U1.T')}",
            f"TG={g('U1.TG')}",
            f"IPL={g('U1.IPL','0')}",
            "UN=0",
            "RIPL=G",
            "RID=G",
            "RIPCK=G",
            "RUCK=G",
            "RUD=G",
        ]
        lines.append("U1(" + "%".join(u1_parts) + ")")

    if g("IE.R", "N") == "N":
        lines.append("IE(R=N)")
    else:
        ie_parts = [
            "R=Y",
            f"DFI={g('IE.DFI','N')}",
            f"T={g('IE.T')}",
            f"TG={g('IE.TG')}",
            f"CD={g('IE.CD','Z')}",
        ]
        lines.append("IE(" + "%".join(ie_parts) + ")")

    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="derive.py", description=__doc__)
    p.add_argument("runs", nargs="+", type=Path, help="One or more run-*.json files")
    p.add_argument("--os-name", required=True, help="OS name for the Fingerprint line")
    p.add_argument("--os-build", required=True, help="Build/version string for provenance comments")
    p.add_argument("-o", "--output", type=Path, help="Write personality text here (default: stdout)")
    p.add_argument("--json-report", type=Path, help="Optional JSON report of field observations")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    runs = _load_runs(args.runs)
    result = derive(runs, os_name=args.os_name, os_build=args.os_build)
    text = render_personality(result)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if args.json_report:
        report = {
            "os_name": result["os_name"],
            "os_build": result["os_build"],
            "run_ids": result["run_ids"],
            "fields": result["fields"],
        }
        args.json_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json_report}", file=sys.stderr)
    varying = [k for k, v in result["fields"].items() if not v["stable"]]
    if varying:
        print(f"note: {len(varying)} field(s) varied across runs — see comments", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
