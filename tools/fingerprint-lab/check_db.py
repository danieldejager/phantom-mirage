#!/usr/bin/env python3
"""Check a Phantom Mirage OS fingerprint database file built by build_db.py.

Checks (all offline, read-only):
  * expected personas: with --expect FILE, the set of Fingerprint names in
    the database must equal the names listed (one per line), nothing missing
    and nothing extra; names must be known personas, unique, and in the
    fixed persona order; the '#@ db-personas' header must agree.
  * provenance: every block has its '#@' header, '#@ persona' matching the
    Fingerprint name.
  * config selection: with --config FILE..., every `personality "<name>"`
    used in those configs must name a persona in the database.
  * syntax: an INDEPENDENT re-implementation of the block layout rules of
    personality.c's personality_parse (no comment or blank line inside a
    block, one line per test group, ECN only with the fields parse_ecn
    accepts). This is not the C parser; the real loader check is
    `phantom-mirage --verify-config -p <db>` (see README).

Exit 0 when all checks pass, 1 otherwise. No network access.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from build_db import PERSONA_ORDER, read_name_list  # noqa: E402

GROUPS = ["SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"]
ECN_FIELDS = {"R", "DF", "T", "TG", "W", "O", "CC", "Q"}
PERS_RE = re.compile(r'\bpersonality\s+"([^"]+)"')


def parse_db(text: str) -> tuple[list[dict], list[str], list[str]]:
    """Return (blocks, header db-personas list, errors)."""
    errors: list[str] = []
    blocks: list[dict] = []
    header_list: list[str] = []
    pending_hdr: dict[str, str] = {}
    cur: dict | None = None
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            cur = None
            m = re.match(r"^#@ ([a-z-]+): (.*)$", line)
            if m:
                if m[1] == "db-personas":
                    header_list = [] if m[2] == "none" else m[2].split(",")
                else:
                    pending_hdr[m[1]] = m[2]
            continue
        if line.startswith("Fingerprint "):
            name = line[len("Fingerprint "):].strip()
            if not name[:1].isalnum():
                errors.append(f"{n}: bad name {name!r}")
            cur = {"name": name, "line": n, "hdr": pending_hdr, "groups": {}}
            pending_hdr = {}
            blocks.append(cur)
            continue
        if cur is None:
            errors.append(f"{n}: line outside a Fingerprint block (a comment or blank line ends a block): {line}")
            continue
        m = re.match(r"^([A-Z0-9]+)\((.*)\)$", line)
        if not m or m[1] not in GROUPS:
            errors.append(f"{n}: not a known test group line: {line}")
            continue
        if m[1] in cur["groups"]:
            errors.append(f"{n}: {m[1]} repeated in {cur['name']}")
        cur["groups"][m[1]] = m[2]
        if m[1] == "ECN" and m[2] != "R=N":
            bad = {f.split("=", 1)[0] for f in m[2].split("%")} - ECN_FIELDS
            if bad:
                errors.append(f"{n}: ECN has fields parse_ecn rejects: {sorted(bad)}")
    for b in blocks:
        missing = [g for g in GROUPS if g not in b["groups"]]
        if missing:
            errors.append(f"{b['line']}: {b['name']} lacks {missing}")
        if b["hdr"].get("persona") != b["name"]:
            errors.append(f"{b['line']}: {b['name']} has no matching '#@ persona' provenance header")
    return blocks, header_list, errors


def check(text: str, expect: list[str] | None = None, configs: dict[str, str] | None = None) -> list[str]:
    blocks, header_list, errors = parse_db(text)
    names = [b["name"] for b in blocks]
    if len(set(names)) != len(names):
        errors.append(f"duplicate personas: {names}")
    unknown = [n for n in names if n not in PERSONA_ORDER]
    if unknown:
        errors.append(f"unknown personas (not in the fixed persona list): {unknown}")
    known = [n for n in names if n in PERSONA_ORDER]
    if known != sorted(known, key=PERSONA_ORDER.index):
        errors.append(f"personas not in fixed order: {names}")
    if header_list != names:
        errors.append(f"'#@ db-personas' header {header_list} != file contents {names}")
    if expect is not None:
        miss = [n for n in expect if n not in names]
        extra = [n for n in names if n not in expect]
        if miss:
            errors.append(f"expected personas missing from database: {miss}")
        if extra:
            errors.append(f"database has personas not in the expected list: {extra}")
    for path, ctext in sorted((configs or {}).items()):
        for n, line in enumerate(ctext.splitlines(), start=1):
            for name in PERS_RE.findall(line):
                if name not in names:
                    errors.append(f"{path}:{n}: personality {name!r} is not in the database")
    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="check_db.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("db", type=Path)
    p.add_argument("--expect", type=Path, help="expected persona list, one per line")
    p.add_argument("--config", type=Path, nargs="*", default=[], help="configs whose personality names must resolve")
    a = p.parse_args(argv)
    errors = check(
        a.db.read_text(encoding="utf-8"),
        read_name_list(a.expect) if a.expect else None,
        {str(c): c.read_text(encoding="utf-8") for c in a.config},
    )
    for e in errors:
        print(f"check_db.py: {e}", file=sys.stderr)
    if not errors:
        print("check_db.py: OK", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
