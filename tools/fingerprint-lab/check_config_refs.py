#!/usr/bin/env python3
"""List shipped-config references that would keep a decoy on the bundled
third-party nmap-os-db instead of our database file.

Report only: nothing is changed. Finding kinds (sorted by path and line):

  NMAP_OS_DB_REF     a line naming nmap-os-db (or the legacy nmap.prints)
  DEFAULT_PERS_FILE  a line that starts the sensor binary with no -p on that
                     line, so the default <datadir>/nmap-os-db (or
                     PHANTOM_MIRAGE_DATADIR/nmap-os-db) is loaded unless -p
                     arrives another way (heuristic: e.g. "$@" may carry it)
  PERSONA_NOT_OURS   `personality "<name>"` naming a persona that is not in
                     our fixed persona list, so it would fail to load with
                     our file as the only personality file

Scope is the shipped config only (docker/, Dockerfile, config.sample,
config.ethernet, sample-config/, scripts/, debian/, release/, Makefile.am,
console/ outside its tests). Exit 0 unless --strict and something is found.
No network access.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from build_db import PERSONA_ORDER  # noqa: E402

SHIPPED = ["Dockerfile", "Makefile.am", "config.sample", "config.ethernet",
           "docker", "sample-config", "scripts", "debian", "release", "console"]
SKIP_PARTS = {"tests", "__pycache__", ".git"}
SKIP_FILES = {"changelog"}  # debian/changelog is history, not config
DB_RE = re.compile(r"nmap-os-db|nmap\.prints")
BIN_RE = re.compile(r"(?:^|[\s/;&|(])(?:phantom-mirage|honeyd)(?=\s|$)(?![-\w])")
EXEC_HINT = re.compile(r"\bexec\b|ExecStart=|DAEMON=|start-stop-daemon|^\s*/usr/s?bin/")
PERS_RE = re.compile(r'\bpersonality\s+"([^"]+)"')


def _files(root: Path) -> list[Path]:
    out = []
    for name in SHIPPED:
        p = root / name
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out += [f for f in p.rglob("*") if f.is_file()
                    and not (SKIP_PARTS & set(f.relative_to(root).parts))
                    and f.name not in SKIP_FILES]
    return sorted(out)


def scan(root: Path) -> list[tuple[str, int, str, str]]:
    found = []
    for f in _files(root):
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = f.relative_to(root).as_posix()
        for n, line in enumerate(text.splitlines(), start=1):
            s = line.strip()
            if DB_RE.search(s):
                found.append((rel, n, "NMAP_OS_DB_REF", s))
            if BIN_RE.search(s) and EXEC_HINT.search(s) and not re.search(r"(?:^|\s)-p(?:\s|$)", s) \
                    and not s.startswith("#") and "--stop" not in s:
                found.append((rel, n, "DEFAULT_PERS_FILE", s))
            for name in PERS_RE.findall(s):
                if name not in PERSONA_ORDER:
                    found.append((rel, n, "PERSONA_NOT_OURS", name))
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="check_config_refs.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", type=Path, default=_HERE.parents[1], help="repo root")
    p.add_argument("--strict", action="store_true", help="exit 1 if anything is found")
    a = p.parse_args(argv)
    found = scan(a.root)
    for rel, n, kind, detail in found:
        print(f"{rel}:{n}: {kind}: {detail}")
    kinds = sorted({k for _, _, k, _ in found})
    summary = ", ".join(f"{k}={sum(1 for x in found if x[2] == k)}" for k in kinds) or "none"
    print(f"check_config_refs.py: {len(found)} finding(s): {summary}", file=sys.stderr)
    return 1 if (a.strict and found) else 0


if __name__ == "__main__":
    raise SystemExit(main())
