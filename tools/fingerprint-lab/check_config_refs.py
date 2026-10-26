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

The kinds above are reported, never fatal. One kind FAILS the check:

  MOVED_PERSONA_DRIFT `personality "<name>"` where <name> is a bundled
                     persona listed in the moved-persona list
                     (moved-personas.txt, empty today), i.e. it has already
                     moved to our database and the shipped config still uses
                     the old name.

A second kind FAILS the check:

  OUR_PERSONA_ON_BUNDLED_DB a shipped file that selects one of OUR personas
                     (`personality "<persona>"`, persona in build_db
                     PERSONA_ORDER) and on any line names nmap-os-db, starts
                     the sensor without -p, or passes -p a file other than
                     phantom-mirage-os.db. Our personas exist only in our
                     file, so such a config either fails to load or would be
                     served from the bundled third-party file.

moved-personas.txt has one `<bundled name> => <our persona>` per line; `#`
starts a comment. Our persona must be one of build_db.PERSONA_ORDER.

Scope is the shipped config only (docker/, Dockerfile, config.sample,
config.ethernet, sample-config/, scripts/, debian/, release/, Makefile.am,
console/ outside its tests). Exit 1 if any MOVED_PERSONA_DRIFT is found (or,
with --strict, if anything at all is found); exit 2 on a bad moved list;
otherwise 0. No network access.
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


MOVED_DEFAULT = _HERE / "moved-personas.txt"
FAIL_KINDS = {"MOVED_PERSONA_DRIFT", "OUR_PERSONA_ON_BUNDLED_DB"}
OUR_DB_NAME = "phantom-mirage-os.db"
P_ARG_RE = re.compile(r"(?:^|\s)-p\s+(\S+)")


class MovedListError(ValueError):
    pass


def read_moved(path: Path | None) -> dict[str, str]:
    """Parse the moved-persona list: bundled name -> our persona."""
    if path is None or not path.exists():
        return {}
    moved: dict[str, str] = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        old, sep, new = (x.strip() for x in line.partition("=>"))
        if not sep or not old or not new:
            raise MovedListError(f"{path.name}:{n}: expected '<bundled name> => <persona>'")
        if new not in PERSONA_ORDER:
            raise MovedListError(f"{path.name}:{n}: {new!r} is not one of our personas")
        if old in moved:
            raise MovedListError(f"{path.name}:{n}: {old!r} listed twice")
        moved[old] = new
    return moved


def scan(root: Path, moved: dict[str, str] | None = None) -> list[tuple[str, int, str, str]]:
    moved = moved or {}
    found = []
    for f in _files(root):
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = f.relative_to(root).as_posix()
        ours = sorted({n for n in PERS_RE.findall(text) if n in PERSONA_ORDER})
        for n, line in enumerate(text.splitlines(), start=1):
            s = line.strip()
            if DB_RE.search(s):
                found.append((rel, n, "NMAP_OS_DB_REF", s))
            if BIN_RE.search(s) and EXEC_HINT.search(s) and not re.search(r"(?:^|\s)-p(?:\s|$)", s) \
                    and not s.startswith("#") and "--stop" not in s:
                found.append((rel, n, "DEFAULT_PERS_FILE", s))
            for name in PERS_RE.findall(s):
                if name in moved:
                    found.append((rel, n, "MOVED_PERSONA_DRIFT", f"{name} (moved to {moved[name]})"))
                elif name not in PERSONA_ORDER:
                    found.append((rel, n, "PERSONA_NOT_OURS", name))
            if ours and not s.startswith("#"):
                bad = None
                if DB_RE.search(s):
                    bad = "names the bundled nmap-os-db"
                elif any(k == "DEFAULT_PERS_FILE" and r == rel and ln == n for r, ln, k, _ in found):
                    bad = "starts the sensor without -p (default nmap-os-db)"
                else:
                    for arg in P_ARG_RE.findall(s):
                        if BIN_RE.search(s) and Path(arg.strip("'\"")).name != OUR_DB_NAME:
                            bad = f"-p {arg} is not {OUR_DB_NAME}"
                if bad:
                    found.append((rel, n, "OUR_PERSONA_ON_BUNDLED_DB",
                                  f"{','.join(ours)}: {bad}"))
    return sorted(found)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="check_config_refs.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root", type=Path, default=_HERE.parents[1], help="repo root")
    p.add_argument("--moved", type=Path, default=MOVED_DEFAULT, help="moved-persona list")
    p.add_argument("--strict", action="store_true", help="exit 1 if anything is found")
    a = p.parse_args(argv)
    try:
        moved = read_moved(a.moved)
    except MovedListError as e:
        print(f"check_config_refs.py: {e}", file=sys.stderr)
        return 2
    found = scan(a.root, moved)
    for rel, n, kind, detail in found:
        tag = "FAIL" if kind in FAIL_KINDS else "report"
        print(f"{rel}:{n}: {tag}: {kind}: {detail}")
    kinds = sorted({k for _, _, k, _ in found})
    summary = ", ".join(f"{k}={sum(1 for x in found if x[2] == k)}" for k in kinds) or "none"
    print(f"check_config_refs.py: {len(found)} finding(s): {summary}", file=sys.stderr)
    failed = [f for f in found if f[2] in FAIL_KINDS]
    print(f"check_config_refs.py: {len(failed)} failure(s) for {len(moved)} moved persona(s) "
          "and our-persona configs",
          file=sys.stderr)
    return 1 if (failed or (a.strict and found)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
