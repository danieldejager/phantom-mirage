"""Probe shapes and response tests vs. the published method description.

https://nmap.org/book/osdetect-methods.html

Expected byte strings below are derived from that page's probe text
(window sizes, option order/values, flags, ICMP/UDP fields). All inputs are
synthetic; no packets are sent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

from probespec import METHOD_DOC_URL, all_probe_defs, options_letters  # noqa: E402
from derive import _cd, _dfi, _ts_class, _seq_metrics  # noqa: E402

scapy = pytest.importorskip("scapy.all")
from probe import build_send_plan  # noqa: E402

TS = "080affffffff00000000"
EXPECT_OPTS = {  # TCP option bytes per the doc's probe list
    "SEQ1": "03030a0102040" "5b4" + TS + "0402",
    "SEQ2": "020405780303000402" + TS + "00",
    "SEQ3": TS + "01010303050102040280",
    "SEQ4": "0402" + TS + "03030a00",
    "SEQ5": "020402180402" + TS + "03030a00",
    "SEQ6": "020401090402" + TS,
    "ECN": "03030a01020405b404020101",
    "T2": "03030a0102040109" + TS + "0402",
    "T7": "03030f0102040109" + TS + "0402",
}
EXPECT_WIN = {"SEQ1": 1, "SEQ2": 63, "SEQ3": 4, "SEQ4": 4, "SEQ5": 16, "SEQ6": 512, "ECN": 3,
              "T2": 128, "T3": 256, "T4": 1024, "T5": 31337, "T6": 32768, "T7": 65535}
EXPECT_FLAGS = {"ECN": "SEC", "T2": "", "T3": "SFUP", "T4": "A", "T5": "S", "T6": "A", "T7": "FPU"}


def _plan():
    return {x["name"]: scapy.IP(bytes(x["packet"])) for x in build_send_plan(
        target="10.0.0.21", open_tcp=22, closed_tcp=1, closed_udp=40000, src_ip="10.0.0.5")}


def test_doc_url_cited():
    assert METHOD_DOC_URL == "https://nmap.org/book/osdetect-methods.html"
    for f in ("probespec.py", "probe.py", "derive.py"):
        assert METHOD_DOC_URL in (LAB / f).read_text()


def test_probe_set_names():
    assert [p.name for p in all_probe_defs()] == [
        "SEQ1", "SEQ2", "SEQ3", "SEQ4", "SEQ5", "SEQ6", "IE1", "IE2", "U1", "ECN",
        "T2", "T3", "T4", "T5", "T6", "T7"]


@pytest.mark.parametrize("name", sorted(EXPECT_WIN))
def test_tcp_probe_window_and_options(name):
    t = _plan()[name][scapy.TCP]
    assert t.window == EXPECT_WIN[name]
    if name in EXPECT_OPTS:
        assert bytes(t)[20:t.dataofs * 4].hex() == EXPECT_OPTS[name]


def test_tcp_flags_and_ack():
    p = _plan()
    for n, f in EXPECT_FLAGS.items():
        assert str(p[n][scapy.TCP].flags) == f or set(str(p[n][scapy.TCP].flags)) == set(f), n
    acks = {p[n][scapy.TCP].ack for n in p if scapy.TCP in p[n] and n != "ECN"}
    assert len(acks) == 1 and acks.pop() != 0  # one random non-zero ack
    assert p["ECN"][scapy.TCP].ack == 0
    assert p["ECN"][scapy.TCP].urgptr == 0xF7F5
    assert p["ECN"][scapy.TCP].reserved == 4  # as observed on the wire (see probespec)


def test_df_bits():
    p = _plan()
    df = {n: bool(p[n].flags.DF) for n in p}
    assert {n for n, v in df.items() if v} == {"IE1", "T2", "T4", "T6"}


def test_icmp_and_udp():
    p = _plan()
    i1, i2 = p["IE1"], p["IE2"]
    assert (i1.tos, i1[scapy.ICMP].code, i1[scapy.ICMP].seq, len(bytes(i1[scapy.ICMP].payload))) == (0, 9, 295, 120)
    assert (i2.tos, i2[scapy.ICMP].code, i2[scapy.ICMP].seq, len(bytes(i2[scapy.ICMP].payload))) == (4, 0, 296, 150)
    assert i2[scapy.ICMP].id == i1[scapy.ICMP].id + 1
    u = p["U1"]
    assert u.id == 0x1042 and bytes(u[scapy.UDP].payload) == b"C" * 300


def test_options_letters():
    assert options_letters([("MSS", 1410), ("SACK", None), ("TS", (1, 0)), ("NOP", None), ("WS", 9)]) == "M582ST10NW9"
    assert options_letters([("MSS", 1410), ("NOP", None), ("NOP", None), ("TS", (5, 7)), ("NOP", None),
                            ("WS", 9)]) == "M582NNT11NW9"
    assert options_letters([("TS", (0, 7)), ("EOL", None)]) == "T01L"


def test_dfi_and_cd():
    assert _dfi([(False, False), (False, False)]) == "N"
    # pairs are (reply, probe) for IE1 (DF, code 9) and IE2 (no DF, code 0)
    assert _dfi([(True, True), (False, False)]) == "S"
    assert _dfi([(True, True), (True, False)]) == "Y"
    assert _dfi([(False, True), (True, False)]) == "O"
    assert _cd([(0, 9), (0, 0)]) == "Z"
    assert _cd([(9, 9), (0, 0)]) == "S"
    assert _cd([(7, 9), (7, 0)]) == "7"
    assert _cd([(1, 9), (2, 0)]) == "O"


def test_ts_class():
    t = [i * 0.1 for i in range(6)]
    assert _ts_class([(x, 0) for x in t]) == "0"
    assert _ts_class([(x, None) for x in t]) == "U"
    assert _ts_class([(x, 1000 + int(x * 100)) for x in t]) == "7"  # 100 Hz
    assert _ts_class([(x, 1000 + int(x * 1000)) for x in t]) == "A"  # 1000 Hz
    # Per-connection random TS offsets: diffs mod 2^32 over 0.1 s.
    vals = [3_000_000_000, 1_000_000_000, 4_000_000_000, 500_000_000, 2_500_000_000, 100_000_000]
    assert _ts_class(list(zip(t, vals))) == "22"


def test_seq_metrics_hex_above_ff():
    m = _seq_metrics([0, 1_200_000_000, 3_900_000_000, 800_000_000, 2_000_000_000, 4_100_000_000],
                     [i * 0.1 for i in range(6)])
    assert m["ISR"] > 0xFF  # no clamp; rendered as hex


def test_noted_deviations_are_documented():
    """Page-vs-wire deviations must be marked and quote the page."""
    src = (LAB / "probespec.py").read_text()
    assert src.count("# NOTED DEVIATION") == 2  # ECN reserved bit, IE2 DF
    assert "immediately precedes the" in src and "The second ping query is similar" in src
    p = _plan()
    tcp = bytes(p["ECN"][scapy.TCP])
    assert tcp[12] & 0x0F == 0x08 and not tcp[12] & 0x01  # wire: first reserved bit
    assert not p["IE2"].flags.DF
