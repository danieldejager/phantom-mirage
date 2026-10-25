"""ECN line / CC (scoring gate F13) tests. SYNTHETIC data only, nothing sent."""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "tests"))

import build_db  # noqa: E402
import check_db  # noqa: E402
from derive import ecn_cc  # noqa: E402
from packetutil import parse_reply  # noqa: E402

WS = LAB / "tests" / "fixtures" / "synthetic" / "ws2022" / "run-900001-1-fwon"


@pytest.mark.parametrize("bits,cc", [
    (0x12, "N"),          # SYN+ACK
    (0x52, "Y"),          # + ECE
    (0xD2, "S"),          # + ECE + CWR
    (0x92, "O"),          # + CWR only
])
def test_cc_from_flag_bits(bits, cc):
    assert ecn_cc({"flags_bits": bits, "flags": "garbage"}) == cc


@pytest.mark.parametrize("letters,cc", [("SA", "N"), ("SAE", "Y"), ("SAEC", "S"), ("SAC", "O")])
def test_cc_from_letters_for_pre_0_2_runs(letters, cc):
    assert ecn_cc({"flags": letters}) == cc


def test_parse_reply_records_flag_bits():
    from scapy.all import IP, TCP  # type: ignore
    pkt = IP(src="10.0.0.22", dst="10.0.0.10") / TCP(sport=3389, dport=40001, flags="SAEC", seq=1, ack=2)
    parsed = parse_reply(pkt)
    assert parsed["flags_bits"] == 0xD2
    assert ecn_cc(parsed) == "S"


def _case_with_ecn_bits(tmp_path: Path, bits: int) -> Path:
    d = tmp_path / WS.name
    shutil.copytree(WS, d)
    for p in sorted(d.glob("run-*.json")):
        doc = json.loads(p.read_text())
        for ex in doc["exchanges"]:
            if ex["name"] == "ECN":
                ex["reply_parsed"]["flags_bits"] = bits
        p.write_text(json.dumps(doc, indent=2, sort_keys=True))
    return d


@pytest.mark.parametrize("bits,cc", [(0x12, "N"), (0x52, "Y"), (0xD2, "S"), (0x92, "O")])
def test_block_ecn_line_cc_and_field_set(tmp_path, bits, cc):
    d = _case_with_ecn_bits(tmp_path, bits)
    assert build_db.main(["block", str(d), "-o", str(tmp_path / "o")]) == 0
    text = (tmp_path / "o" / "ws2022-fwon.fp").read_text()
    m = re.search(r"^ECN\((.*)\)$", text, flags=re.M)
    fields = [f.split("=", 1)[0] for f in m[1].split("%")]
    assert fields == ["R", "DF", "T", "TG", "W", "O", "CC", "Q"]
    assert f"%CC={cc}%" in m[0]
    inc = tmp_path / "inc"
    inc.write_text("ws2022-fwon\n")
    db = tmp_path / "db"
    assert build_db.main(["assemble", str(tmp_path / "o" / "ws2022-fwon.fp"), "--include", str(inc),
                          "-o", str(db)]) == 0
    assert check_db.check(db.read_text(), ["ws2022-fwon"]) == []
    # Real personality.c loader, when a built binary is available.
    from test_build_db import _binary, _verify
    if _binary() is not None:
        r = _verify(_binary(), db, 'create a\nset a personality "ws2022-fwon"\nbind 10.255.0.1 a\n', tmp_path)
        assert r.returncode == 0, r.stdout + r.stderr


def test_cc_disagreement_between_runs_is_refused(tmp_path, capsys):
    d = _case_with_ecn_bits(tmp_path, 0x52)
    p = sorted(d.glob("run-*.json"))[0]
    doc = json.loads(p.read_text())
    for ex in doc["exchanges"]:
        if ex["name"] == "ECN":
            ex["reply_parsed"]["flags_bits"] = 0xD2
    p.write_text(json.dumps(doc))
    assert build_db.main(["block", str(d), "-o", str(tmp_path / "o")]) == 2
    assert "ECN.CC" in capsys.readouterr().err


def test_build_db_refuses_unparseable_ecn_render():
    with pytest.raises(build_db.BuildError):
        build_db._check_ecn_line("Fingerprint x\nECN(R=Y%S=O%RD=0)\n")
    build_db._check_ecn_line("Fingerprint x\nECN(R=N)\n")
