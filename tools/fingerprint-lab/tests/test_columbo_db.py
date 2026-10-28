"""The default personality file fingerprints/columbo-v1.db (issue #150).

It is the project's own fingerprint database, committed byte for byte as
published, and pinned by sha256 in fingerprints/columbo-v1.db.sha256.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))

import check_db  # noqa: E402

FP = LAB.parents[1] / "fingerprints"
DB = FP / "columbo-v1.db"
PINNED = "38f8d4cbde86b925a35d6157477913f148e7894c189fdfa1deeedbba9a94775f"
PERSONAS = ["ubuntu2404", "ws2022-fwoff", "ws2019-fwoff", "ws2025-fwoff",
            "win11-fwon", "win11-fwoff"]


def test_sha256_matches_pin():
    assert hashlib.sha256(DB.read_bytes()).hexdigest() == PINNED


def test_sha256_file_matches_pin():
    digest, name = (FP / "columbo-v1.db.sha256").read_text().split()
    assert (digest, name) == (PINNED, "columbo-v1.db")


def test_six_personas_parse_cleanly():
    blocks, _, errors = check_db.parse_db(DB.read_text())
    assert errors == []
    assert [b["name"] for b in blocks] == PERSONAS


def test_check_db_passes():
    assert check_db.check(DB.read_text(), expect=PERSONAS) == []
