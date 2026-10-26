"""Unit tests for fingerprint-lab parsing/derivation (synthetic packets only)."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rfc1918 import assert_allowed_targets, is_private_target  # noqa: E402
from packetutil import (  # noqa: E402
    build_probe,
    parse_reply,
    packet_to_hex,
    synthesize_tcp_reply,
    synthesize_icmp_echo_reply,
    synthesize_icmp_port_unreach,
)
from probespec import SEQ_PROBES, all_probe_defs, ProbeDef  # noqa: E402
from derive import derive, render_personality, _classify_ipid, _gcd_list, _seq_metrics  # noqa: E402
from probe import build_send_plan, run_once  # noqa: E402


# ---------------------------------------------------------------------------
# RFC1918 gate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip,ok",
    [
        ("10.0.0.1", True),
        ("192.168.1.10", True),
        ("172.16.5.5", True),
        ("127.0.0.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("fd12:3456:789a::1", True),
        ("2001:4860:4860::8888", False),
        ("not-an-ip", False),
    ],
)
def test_is_private_target(ip, ok):
    assert is_private_target(ip) is ok


def test_assert_allowed_requires_flag():
    with pytest.raises(SystemExit):
        assert_allowed_targets(["192.168.0.1"], i_own_flag=False)


def test_assert_allowed_rejects_public():
    with pytest.raises(SystemExit):
        assert_allowed_targets(["8.8.8.8"], i_own_flag=True)


def test_assert_allowed_ok_private():
    assert_allowed_targets(["10.1.2.3"], i_own_flag=True)


# ---------------------------------------------------------------------------
# Probe construction (offline)
# ---------------------------------------------------------------------------

def test_all_probes_build():
    for pdef in all_probe_defs():
        pkt = build_probe(
            pdef,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.10",
            open_tcp=22,
            closed_tcp=1,
            closed_udp=40000,
            ip_id=1,
            tcp_seq=1000,
            tcp_sport=45000,
        )
        assert len(bytes(pkt)) > 20
        assert packet_to_hex(pkt)


def test_dry_run_plan_has_six_seq_and_no_send():
    plan = build_send_plan(
        target="10.0.0.10",
        open_tcp=22,
        closed_tcp=1,
        closed_udp=40000,
        src_ip="10.0.0.2",
    )
    names = [p["name"] for p in plan]
    assert names[:6] == [f"SEQ{i}" for i in range(1, 7)]
    assert "ECN" in names and "U1" in names and "IE1" in names
    assert len(plan) == len(all_probe_defs())


def test_run_once_dry_run_json_shape(tmp_path):
    doc = run_once(
        target="10.0.0.10",
        open_tcp=22,
        closed_tcp=1,
        closed_udp=40000,
        dry_run=True,
        src_ip="10.0.0.2",
        cmdline=["probe.py", "--dry-run", "10.0.0.10"],
        run_index=0,
    )
    assert doc["dry_run"] is True
    assert doc["tool_version"]
    assert doc["run_id"]
    assert len(doc["exchanges"]) == len(all_probe_defs())
    for ex in doc["exchanges"]:
        assert ex["sent"]["hex"]
        assert ex["reply"] is None


# ---------------------------------------------------------------------------
# Reply parsing
# ---------------------------------------------------------------------------

def test_parse_synack_reply():
    pkt = synthesize_tcp_reply(
        src="10.0.0.10",
        dst="10.0.0.2",
        sport=22,
        dport=45000,
        seq=0x11112222,
        ack=1001,
        flags="SA",
        window=64240,
        ttl=64,
        ip_id=5,
        df=True,
        options=[("MSS", 1460), ("NOP", None), ("NOP", None), ("SAckOK", b""), ("NOP", None), ("WScale", 7)],
    )
    parsed = parse_reply(pkt)
    assert parsed["l4"] == "tcp"
    assert parsed["window"] == 64240
    assert parsed["ip_ttl"] == 64
    assert parsed["ip_df"] is True
    assert "M5B4" in parsed["options"]  # 1460 == 0x5B4
    assert "W7" in parsed["options"]


def test_parse_icmp_echo_reply():
    pkt = synthesize_icmp_echo_reply(
        src="10.0.0.10", dst="10.0.0.2", ttl=128, ip_id=9, df=False
    )
    parsed = parse_reply(pkt)
    assert parsed["l4"] == "icmp"
    assert parsed["icmp_type"] == 0
    assert parsed["ip_ttl"] == 128


def test_parse_port_unreach():
    emb = build_probe(
        SEQ_PROBES[0],
        src_ip="10.0.0.2",
        dst_ip="10.0.0.10",
        open_tcp=22,
        closed_tcp=1,
        closed_udp=40000,
        ip_id=42,
        tcp_seq=1,
        tcp_sport=45000,
    )
    # Replace with UDP-shaped embed: just reuse IP layer
    from scapy.all import IP, UDP, Raw  # type: ignore

    emb = IP(src="10.0.0.2", dst="10.0.0.10", id=42, ttl=64) / UDP(sport=45000, dport=40000) / Raw(b"C" * 20)
    pkt = synthesize_icmp_port_unreach(
        src="10.0.0.10", dst="10.0.0.2", ttl=64, ip_id=7, df=False, embedded=emb
    )
    parsed = parse_reply(pkt)
    assert parsed["l4"] == "icmp"
    assert parsed["icmp_type"] == 3
    assert parsed["embedded_ip_id"] == 42


# ---------------------------------------------------------------------------
# Derivation math
# ---------------------------------------------------------------------------

def test_classify_ipid():
    # Rules from the published method (IP ID sequence generation algorithm).
    assert _classify_ipid([0, 0, 0], min_count=3) == "Z"
    assert _classify_ipid([1, 2, 3, 4], min_count=3) == "I"
    assert _classify_ipid([0, 256, 512], min_count=3) == "BI"
    assert _classify_ipid([10, 10, 10], min_count=3) == "A"
    assert _classify_ipid([1, 2000, 4001], min_count=3) == "RI"
    assert _classify_ipid([1, 30000, 60001], min_count=3) == "RD"
    assert _classify_ipid([1, 30000], min_count=2, allow_rd=False) == "RI"  # RD not allowed for II
    assert _classify_ipid([1, 100, 200], min_count=3) is None  # no rule fits: omitted
    assert _classify_ipid([1, 2], min_count=3) is None  # too few responses


def test_gcd_and_seq_metrics():
    assert _gcd_list([10, 20, 35]) == 5
    m = _seq_metrics([1000, 2000, 3000, 4000], [0.0, 0.1, 0.2, 0.3])
    assert m["GCD"] == 1000
    assert m["ISR"] == round(8 * math.log2(10000))
    assert m["SP"] == 0  # constant rate
    m = _seq_metrics([0, 2 ** 31, 2 ** 31 + 5], [0.0, 0.1, 0.2])
    assert m["SP"] is None  # SP needs >= 4 responses
    assert m["ISR"] > 0xFF  # no clamp at FF


def _synthetic_run(run_id: str, *, window: int = 64240, ttl: int = 64, ip_id_base: int = 10) -> dict:
    """Build a minimal run JSON with parsed SEQ/ECN/T*/IE/U1 replies."""
    exchanges = []
    seq = 0x10000000
    for i in range(1, 7):
        exchanges.append(
            {
                "name": f"SEQ{i}",
                "kind": "syn_seq",
                "gap_before_sec": 0.0 if i == 1 else 0.1,
                "timeout": False,
                "reply_parsed": {
                    "l4": "tcp",
                    "seq": seq + i * 10000,
                    "ack": 1,
                    "window": window,
                    "flags": "SA",
                    "options": "M5B4ST0NW7",
                    "options_raw": [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)],
                    "ip_id": ip_id_base + i,
                    "ip_ttl": ttl,
                    "ip_df": True,
                },
            }
        )
    exchanges.append(
        {
            "name": "ECN",
            "kind": "ecn",
            "gap_before_sec": 0.2,
            "timeout": False,
            "reply_parsed": {
                "l4": "tcp",
                "seq": seq,
                "ack": 1,
                "window": window,
                "flags": "SA",
                "options": "M5B4",
                "options_raw": [("MSS", 1460)],
                "ip_id": ip_id_base + 10,
                "ip_ttl": ttl,
                "ip_df": True,
            },
        }
    )
    for name, flags in [("T2", ""), ("T3", "SA"), ("T4", "R"), ("T5", "RA"), ("T6", "R"), ("T7", "RA")]:
        timeout = name == "T2"
        exchanges.append(
            {
                "name": name,
                "kind": "tcp_unusual",
                "gap_before_sec": 0.2,
                "timeout": timeout,
                "reply_parsed": None
                if timeout
                else {
                    "l4": "tcp",
                    "seq": seq,
                    "ack": 1,
                    "window": 0 if "R" in flags else window,
                    "flags": flags,
                    "options": "",
                    "options_raw": [],
                    "ip_id": ip_id_base + 20,
                    "ip_ttl": ttl,
                    "ip_df": True,
                },
            }
        )
    for i, name in enumerate(("IE1", "IE2"), start=1):
        exchanges.append(
            {
                "name": name,
                "kind": "icmp",
                "gap_before_sec": 0.2,
                "timeout": False,
                "reply_parsed": {
                    "l4": "icmp",
                    "icmp_type": 0,
                    "icmp_code": 0,
                    "ip_id": ip_id_base + 30 + i,
                    "ip_ttl": ttl,
                    "ip_df": False,
                },
            }
        )
    exchanges.append(
        {
            "name": "U1",
            "kind": "udp",
            "gap_before_sec": 0.2,
            "timeout": False,
            "reply_parsed": {
                "l4": "icmp",
                "icmp_type": 3,
                "icmp_code": 3,
                "ip_id": ip_id_base + 40,
                "ip_ttl": ttl,
                "ip_df": False,
                "ip_len": 56,
                "embedded_ip_id": 42,
                "embedded_ip_len": 328,
            },
        }
    )
    return {
        "run_id": run_id,
        "tool_version": "0.1.0",
        "exchanges": exchanges,
        "target": "10.0.0.10",
    }


def test_derive_stable_across_identical_runs():
    runs = [_synthetic_run("aaa"), _synthetic_run("bbb")]
    result = derive(runs, os_name="Lab OS Test", os_build="pytest-1")
    text = render_personality(result)
    assert text.startswith("# Draft honeyd personality")
    assert "Fingerprint Lab OS Test" in text
    assert "SEQ(" in text and "OPS(" in text and "WIN(" in text
    assert "U1(" in text and "IE(" in text
    assert "aaa" in text and "bbb" in text
    varying = [k for k, v in result["fields"].items() if not v["stable"]]
    assert varying == []


def test_derive_flags_variance():
    a = _synthetic_run("r1", window=64240)
    b = _synthetic_run("r2", window=65535)
    result = derive([a, b], os_name="Var OS", os_build="b")
    assert any(not v["stable"] for k, v in result["fields"].items() if k.startswith("WIN."))
    text = render_personality(result)
    assert "VARIED" in text or "VARIES" in text


def test_classify_constant_hex():
    # constant IP ID → hex string of that value
    assert _classify_ipid([10, 10, 10]) == "A"
