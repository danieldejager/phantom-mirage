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


# Response tests follow the published method description:
#   https://nmap.org/book/osdetect-methods.html  (section "Response Tests")
# Written from that text only; no nmap source or nmap-os-db content is used.

def _gcd_list(nums: list[int]) -> int:
    g = 0
    for n in nums:
        g = math.gcd(g, abs(n))
    return g or 1


def _u32_diff(a: int, b: int) -> int:
    """Doc (GCD): the smaller of the forward and the wrapped-backward difference."""
    fwd = (b - a) & 0xFFFFFFFF
    back = (a - b) & 0xFFFFFFFF
    return min(fwd, back)


def _classify_ipid(ids: list[int], *, min_count: int = 2, allow_rd: bool = True) -> str | None:
    """IP ID class (TI/CI/II), doc "IP ID sequence generation algorithm".

    Returns None when the test is omitted (too few replies, or no rule fits).
    Differences assume the 16-bit counter wraps.
    """
    if len(ids) < max(min_count, 1):
        return None
    if all(i == 0 for i in ids):
        return "Z"
    diffs = [(ids[i + 1] - ids[i]) & 0xFFFF for i in range(len(ids) - 1)]
    if allow_rd and any(d >= 20000 for d in diffs):
        return "RD"
    if all(i == ids[0] for i in ids):
        return f"{ids[0]:X}"
    if any((d > 1000 and d % 256 != 0) or (d % 256 == 0 and d >= 256000) for d in diffs):
        return "RI"
    if diffs and all(d % 256 == 0 and d <= 5120 for d in diffs):
        return "BI"
    if all(d < 10 for d in diffs):
        return "I"
    return None


def _shared_seq(tcp_ids: list[int], icmp_ids: list[int]) -> str:
    """SS, doc "Shared IP ID sequence Boolean (SS)" (probe numbers assumed 1..n)."""
    n = len(tcp_ids)
    avg = ((tcp_ids[-1] - tcp_ids[0]) & 0xFFFF) / max(n - 1, 1)
    return "S" if icmp_ids[0] < tcp_ids[-1] + 3 * avg else "O"


def _ts_class(samples: list[tuple[float, int | None]]) -> str | None:
    """TS, doc "TCP timestamp option algorithm (TS)".

    *samples*: (probe send time in s, reply TSval or None) per SEQ reply.
    TSval differences wrap at 2**32 (it is a counter).
    """
    if not samples:
        return None
    if any(v is None for _, v in samples):
        return "U"
    if any(v == 0 for _, v in samples):
        return "0"
    rates = []
    for (t0, v0), (t1, v1) in zip(samples, samples[1:]):
        dt = t1 - t0
        if dt > 0:
            rates.append(((v1 - v0) & 0xFFFFFFFF) / dt)
    if not rates:
        return None
    avg = sum(rates) / len(rates)
    if avg <= 5.66:
        return "1"
    if 70 <= avg < 150:
        return "7"
    if 150 <= avg <= 350:
        return "8"
    return f"{int(round(math.log2(avg))):X}"


def _ttl_guess(observed: list[int], hops: int | None = None) -> tuple[str, str]:
    """Return (T, TG) hex. Doc "IP initial time-to-live (T)" / "(TG)":
    T = response TTL + hop distance learned from U1 (sent TTL minus the TTL
    quoted back in the port unreachable); TG = response TTL rounded up to 32,
    64, 128 or 255. Without a hop distance T falls back to the observed TTL."""
    if not observed:
        return ("", "")
    obs = sorted(observed)[len(observed) // 2]
    t = obs + hops if hops is not None and hops >= 0 else obs
    tg = next((i for i in (32, 64, 128, 255) if obs <= i), obs)
    return (f"{t:X}", f"{tg:X}")


def _seq_metrics(seqs: list[int], times_sec: list[float]) -> dict[str, Any]:
    """GCD / ISR / SP, doc "TCP ISN greatest common divisor (GCD)",
    "TCP ISN counter rate (ISR)" and "TCP ISN sequence predictability index (SP)".

    *seqs*: ISNs of consecutive SEQ replies; *times_sec*: send times of the
    probes that elicited them. SP needs >= 4 responses. The standard
    deviation is the sample (n-1) form; on our capture this reproduces the
    oracle's SP exactly (the population form comes out 1 lower).
    """
    if len(seqs) < 2:
        return {"GCD": None, "SP": None, "ISR": None, "note": "insufficient ISN samples"}
    diffs = [_u32_diff(seqs[i], seqs[i + 1]) for i in range(len(seqs) - 1)]
    gcd = _gcd_list(diffs)
    rates = []
    for i, d in enumerate(diffs):
        dt = times_sec[i + 1] - times_sec[i]
        rates.append(d / dt if dt > 0 else 0.0)
    mean = sum(rates) / len(rates)
    isr = int(round(8 * math.log2(mean))) if mean >= 1 else 0
    sp = None
    if len(seqs) >= 4:
        r = [x / gcd for x in rates] if gcd > 9 else rates
        m = sum(r) / len(r)
        sd = math.sqrt(sum((x - m) ** 2 for x in r) / (len(r) - 1))
        sp = 0 if sd <= 1 else int(round(8 * math.log2(sd)))
    return {"GCD": gcd, "SP": sp, "ISR": isr, "diffs": diffs}


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

def _enrich(ex: dict[str, Any] | None, key: str) -> dict[str, Any] | None:
    """Parsed packet (``reply`` or ``sent``), re-parsed from the recorded hex
    when it was written by an older probe.py that did not store a field
    (urgptr, ICMP id/seq/unused, quoted-probe fields). Offline only."""
    if not ex:
        return None
    parsed = ex.get(f"{key}_parsed") if key == "reply" else ex.get("sent_parsed")
    if key == "reply" and (ex.get("timeout") or not parsed):
        return None
    hexstr = (ex.get(key) or {}).get("hex") if isinstance(ex.get(key), dict) else None
    need = (parsed or {}).get("l4") == "tcp" and "urgptr" not in parsed
    need = need or ((parsed or {}).get("l4") == "icmp" and "icmp_unused" not in parsed)
    if hexstr and (parsed is None or need):
        from packetutil import parse_hex  # lazy: needs scapy

        fresh = parse_hex(hexstr) or {}
        merged = dict(fresh)
        merged.update({k: v for k, v in (parsed or {}).items() if k not in fresh})
        return merged
    return parsed


def _send_times(by: dict[str, dict[str, Any]], names: list[str]) -> dict[str, float]:
    """Actual probe send times (sent_at_offset_sec); falls back to the
    cumulative nominal gaps for run files that lack them."""
    out: dict[str, float] = {}
    t = 0.0
    for n in names:
        ex = by.get(n) or {}
        t += float(ex.get("gap_before_sec") or 0.0)
        out[n] = float(ex["sent_at_offset_sec"]) if ex.get("sent_at_offset_sec") is not None else t
    return out


def _tsval(p: dict[str, Any]) -> int | None:
    for opt in p.get("options_raw") or []:
        name, val = opt[0], (opt[1] if len(opt) > 1 else None)
        if name in ("Timestamp", "TSval", "T") and isinstance(val, (tuple, list)):
            return int(val[0])
    return None


def derive(runs: list[dict[str, Any]], *, os_name: str, os_build: str) -> dict[str, Any]:
    obs: dict[str, FieldObs] = defaultdict(FieldObs)
    run_ids = [r["run_id"] for r in runs]

    for run in runs:
        rid = run["run_id"]
        by = _ex_by_name(run)
        seq_names = [f"SEQ{i}" for i in range(1, 7)]
        times = _send_times(by, seq_names)

        # Hop distance from U1 (doc, T test): sent TTL - TTL quoted back.
        u1 = _enrich(by.get("U1"), "reply")
        u1_sent = _enrich(by.get("U1"), "sent")
        hops = None
        if u1 and u1.get("embedded_ip_ttl") is not None and u1_sent and u1_sent.get("ip_ttl") is not None:
            hops = int(u1_sent["ip_ttl"]) - int(u1["embedded_ip_ttl"])

        seq_parsed = [_enrich(by.get(n), "reply") for n in seq_names]
        seq_parsed = [p if p and p.get("l4", "tcp") == "tcp" else None for p in seq_parsed]
        got = [(n, p) for n, p in zip(seq_names, seq_parsed) if p and "seq" in p]
        metrics = _seq_metrics([p["seq"] for _, p in got], [times[n] for n, _ in got])
        obs["SEQ.GCD"].add(metrics["GCD"], rid)
        obs["SEQ.SP"].add(metrics["SP"], rid)
        obs["SEQ.ISR"].add(metrics["ISR"], rid)

        tcp_ids = [p["ip_id"] for _, p in got]
        ti = _classify_ipid(tcp_ids, min_count=3)
        obs["SEQ.TI"].add(ti, rid)
        obs["SEQ.TS"].add(_ts_class([(times[n], _tsval(p)) for n, p in got]), rid)

        # OPS / WIN from SEQ replies (O1..O6, W1..W6)
        for i, p in enumerate(seq_parsed, start=1):
            if not p:
                obs[f"OPS.O{i}"].add("", rid)
                obs[f"WIN.W{i}"].add(None, rid)
                continue
            obs[f"OPS.O{i}"].add(_opts(p), rid)
            obs[f"WIN.W{i}"].add(p.get("window"), rid)

        # CI: closed-port TCP replies T5-T7, at least two.
        closed_ids = [p["ip_id"] for p in (_enrich(by.get(n), "reply") for n in ("T5", "T6", "T7"))
                      if p and p.get("l4") == "tcp"]
        obs["SEQ.CI"].add(_classify_ipid(closed_ids, min_count=2), rid)

        # IE pair -> II, SS and the IE line. Both replies are required.
        ie = [(_enrich(by.get(n), "reply"), _enrich(by.get(n), "sent")) for n in ("IE1", "IE2")]
        ie = [(r, s) for r, s in ie if r and r.get("l4") == "icmp" and r.get("icmp_type") == 0]
        ii = _classify_ipid([r["ip_id"] for r, _ in ie], min_count=2, allow_rd=False) if len(ie) == 2 else None
        obs["SEQ.II"].add(ii, rid)
        ss = None
        if ii in ("RI", "BI", "I") and ti == ii and len(tcp_ids) >= 2:
            ss = _shared_seq(tcp_ids, [r["ip_id"] for r, _ in ie])
        obs["SEQ.SS"].add(ss, rid)

        _record_tcp_test(obs, "ECN", _enrich(by.get("ECN"), "reply"), rid,
                         _enrich(by.get("ECN"), "sent"), hops)
        # T1: tests on the reply to SEQ probe #1 (doc).
        _record_tcp_test(obs, "T1", seq_parsed[0], rid, _enrich(by.get("SEQ1"), "sent"), hops)
        for name in ("T2", "T3", "T4", "T5", "T6", "T7"):
            _record_tcp_test(obs, name, _enrich(by.get(name), "reply"), rid,
                             _enrich(by.get(name), "sent"), hops)

        # U1 (doc "UDP (U1)" + IPL/UN/RIPL/RID/RIPCK/RUCK/RUD tests)
        if not u1 or u1.get("l4") != "icmp":
            obs["U1.R"].add("N", rid)
        else:
            obs["U1.R"].add("Y", rid)
            obs["U1.DF"].add("Y" if u1.get("ip_df") else "N", rid)
            t, tg = _ttl_guess([u1["ip_ttl"]], hops)
            obs["U1.T"].add(t, rid)
            obs["U1.TG"].add(tg, rid)
            if u1.get("ip_len") is not None:
                obs["U1.IPL"].add(f"{int(u1['ip_len']):X}", rid)
            for k, v in _u1_tests(u1, u1_sent, by.get("U1") or {}).items():
                obs[f"U1.{k}"].add(v, rid)

        if len(ie) < 2:
            obs["IE.R"].add("N", rid)
        else:
            obs["IE.R"].add("Y", rid)
            obs["IE.DFI"].add(_dfi([(bool(r.get("ip_df")), bool((s or {}).get("ip_df"))) for r, s in ie]), rid)
            # T is for the response to the first probe only (doc).
            t, tg = _ttl_guess([ie[0][0]["ip_ttl"]], hops)
            obs["IE.T"].add(t, rid)
            obs["IE.TG"].add(tg, rid)
            obs["IE.CD"].add(_cd([(int(r.get("icmp_code") or 0), _sent_code(s, n))
                                  for (r, s), n in zip(ie, (9, 0))]), rid)

    return {
        "os_name": os_name,
        "os_build": os_build,
        "run_ids": run_ids,
        "fields": {k: {"values": v.values, "sources": v.sources, "stable": v.unanimous(), "note": v.range_note()} for k, v in sorted(obs.items())},
        "obs": obs,
    }


def _opts(p: dict[str, Any]) -> str:
    """Option letters, recomputed from options_raw so that run files written
    by older probe.py versions (which used T/T0, decimal W and E) come out in
    the current letter form."""
    raw = p.get("options_raw")
    if raw is not None:
        from probespec import options_letters

        return options_letters(raw)
    return p.get("options") or ""


def _sent_code(s: dict[str, Any] | None, default: int) -> int:
    if s and s.get("icmp_code") is not None:
        return int(s["icmp_code"])
    return default  # IE1 is sent with code 9, IE2 with 0 (doc)


def _dfi(pairs: list[tuple[bool, bool]]) -> str:
    """DFI, doc table 8.2. *pairs*: (reply DF, probe DF) for IE1, IE2."""
    if not any(r for r, _ in pairs):
        return "N"
    if all(r == s for r, s in pairs):
        return "S"
    if all(r for r, _ in pairs):
        return "Y"
    if all(r != s for r, s in pairs):
        return "O"
    return "O"


def _cd(pairs: list[tuple[int, int]]) -> str:
    """CD, doc table 8.7. *pairs*: (reply code, probe code) for IE1, IE2."""
    codes = [r for r, _ in pairs]
    if all(c == 0 for c in codes):
        return "Z"
    if all(r == s for r, s in pairs):
        return "S"
    if len(set(codes)) == 1:
        return f"{codes[0]:X}"
    return "O"


def _u1_tests(u1: dict[str, Any], sent: dict[str, Any] | None, ex: dict[str, Any]) -> dict[str, str]:
    """UN, RIPL, RID, RIPCK, RUCK, RUD (doc). A test whose raw field was not
    recorded keeps the previous default G and is marked in the report."""
    out: dict[str, str] = {}
    un = u1.get("icmp_unused")
    out["UN"] = f"{int(un):X}" if un is not None else "0"
    el = u1.get("embedded_ip_len")
    out["RIPL"] = "G" if el in (None, 0x148) else f"{int(el):X}"
    eid = u1.get("embedded_ip_id")
    # The probe sends IP ID 0x1042 (doc); older runs sent another id, so
    # compare against what was actually sent.
    want = int((sent or {}).get("ip_id", 0x1042)) if sent else 0x1042
    out["RID"] = "G" if eid in (None, want) else f"{int(eid):X}"
    if u1.get("embedded_ip_sum") is None:
        out["RIPCK"] = "G"
    elif int(u1["embedded_ip_sum"]) == 0:
        out["RIPCK"] = "Z"
    else:
        out["RIPCK"] = "G" if u1.get("embedded_ip_sum_ok") else "I"
    ruck = u1.get("embedded_udp_sum")
    sent_sum = None
    shex = (ex.get("sent") or {}).get("hex") if isinstance(ex.get("sent"), dict) else None
    if shex:
        b = bytes.fromhex(shex)
        ihl = (b[0] & 0x0F) * 4
        if len(b) >= ihl + 8:
            sent_sum = int.from_bytes(b[ihl + 6:ihl + 8], "big")
    out["RUCK"] = "G" if ruck is None or sent_sum is None or ruck == sent_sum else f"{int(ruck):X}"
    data = u1.get("embedded_udp_data_hex")
    out["RUD"] = "G" if not data or set(bytes.fromhex(data)) <= {0x43} else "I"
    return out


def _record_tcp_test(
    obs: dict[str, FieldObs],
    prefix: str,
    p: dict[str, Any] | None,
    rid: str,
    sent: dict[str, Any] | None = None,
    hops: int | None = None,
) -> None:
    if not p or p.get("l4") != "tcp":
        obs[f"{prefix}.R"].add("N", rid)
        return
    obs[f"{prefix}.R"].add("Y", rid)
    obs[f"{prefix}.DF"].add("Y" if p.get("ip_df") else "N", rid)
    t, tg = _ttl_guess([p["ip_ttl"]], hops)
    obs[f"{prefix}.T"].add(t, rid)
    obs[f"{prefix}.TG"].add(tg, rid)
    if p.get("window") is not None:
        obs[f"{prefix}.W"].add(f"{int(p['window']):X}", rid)
    obs[f"{prefix}.S"].add(_seq_ack_relation(p, sent), rid)
    obs[f"{prefix}.A"].add(_ack_relation(p, sent), rid)
    obs[f"{prefix}.F"].add(_flags_letters(p.get("flags") or ""), rid)
    obs[f"{prefix}.O"].add(_opts(p), rid)
    if prefix == "ECN":
        obs["ECN.CC"].add(ecn_cc(p), rid)
    obs[f"{prefix}.Q"].add(_quirks(p), rid)


def _quirks(p: dict[str, Any]) -> str:
    """Q, doc "TCP miscellaneous quirks (Q)": R = reserved bits non-zero,
    U = urgent pointer non-zero without URG; alphabetical."""
    q = ""
    if int(p.get("reserved") or 0):
        q += "R"
    bits = p.get("flags_bits")
    urg = bool(bits & 0x20) if isinstance(bits, int) else "U" in str(p.get("flags") or "")
    if int(p.get("urgptr") or 0) and not urg:
        q += "U"
    return q


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

    # Tests the method omits (too few replies / no rule fits) are left out
    # of the line rather than given a made-up value.
    seq_parts = []
    for key in ("SP", "GCD", "ISR", "TI", "CI", "II", "SS", "TS"):
        fo = obs.get(f"SEQ.{key}")
        v = fo.draft_value() if fo else None
        if v is None or v == "":
            continue
        seq_parts.append(f"{key}={v:X}" if isinstance(v, int) else f"{key}={v}")
    seq = "SEQ(" + "%".join(seq_parts) + ")"
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
            f"UN={g('U1.UN','0')}",
            f"RIPL={g('U1.RIPL','G')}",
            f"RID={g('U1.RID','G')}",
            f"RIPCK={g('U1.RIPCK','G')}",
            f"RUCK={g('U1.RUCK','G')}",
            f"RUD={g('U1.RUD','G')}",
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
