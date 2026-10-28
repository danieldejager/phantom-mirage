#!/usr/bin/env python3
"""Rebuild fingerprints/phantom-mirage-os.db and its provenance sidecars.

Reads a LOCAL-ONLY sources file (persona -> capture run dir names; it holds
lab run ids, so it is not in the repository) and fingerprints/personas.txt
(include list), finds each named run dir under --captures-root, and runs the same code as `build_db.py block` and
`build_db.py assemble`. Output is byte-for-byte reproducible from the same
captures. Only run-*.json and tool-versions.txt of each run dir are read.

  python3 build_shipped_db.py --captures-root DIR [--sources FILE] [--out DIR] [--check]

--sources defaults to $PM_SOURCES, else <captures-root>/phantom-mirage-sources.txt.

--check rebuilds into a temporary dir and exits 1 if any file differs from
the committed one (nothing is written).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import build_db  # noqa: E402
from build_db import BuildError  # noqa: E402

REPO = _HERE.parents[1]
FP_DIR = REPO / "fingerprints"
DB_NAME = "phantom-mirage-os.db"


def read_sources(path: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        persona, sep, rest = line.partition(":")
        dirs = rest.split()
        if not sep or not dirs or persona.strip() not in build_db.PERSONA_ORDER:
            raise BuildError(f"{path.name}:{n}: expected '<persona>: <run dir> ...'")
        if persona.strip() in out:
            raise BuildError(f"{path.name}:{n}: persona listed twice")
        out[persona.strip()] = dirs
    return out


def read_limits(path: Path) -> dict[str, list[str]]:
    """fingerprints/limits.txt: '<persona>: <one line>' per extra '#@ limit:'
    line, in file order. Must hold no lab run numbers or UUIDs."""
    out: dict[str, list[str]] = {}
    if not path.is_file():
        return out
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        persona, sep, text = raw.partition(":")
        if not sep or persona.strip() not in build_db.PERSONA_ORDER or not text.strip():
            raise BuildError(f"{path.name}:{n}: expected '<persona>: <limit text>'")
        out.setdefault(persona.strip(), []).append(text.strip())
    return out


def imported_blocks(sources: dict) -> list[str]:
    """fingerprints/imported/<persona>.fp: blocks taken byte for byte from a
    published database (no local captures). Each must match its committed
    sidecar's block_sha256; a persona may not be both imported and rebuilt."""
    out = []
    for path in sorted((FP_DIR / "imported").glob("*.fp")):
        text = path.read_text(encoding="utf-8")
        name = build_db.block_persona(text)
        if name != path.stem:
            raise BuildError(f"imported/{path.name} holds persona {name!r}")
        if name in sources:
            raise BuildError(f"{name} is both imported and listed in the sources file")
        side = json.loads((FP_DIR / f"{name}.provenance.json").read_text(encoding="utf-8"))
        if side.get("block_sha256") != hashlib.sha256(text.encode("utf-8")).hexdigest():
            raise BuildError(f"imported/{path.name} does not match {name}.provenance.json block_sha256")
        out.append(text)
    return out


def default_sources(root: Path) -> Path:
    env = os.environ.get("PM_SOURCES")
    return Path(env) if env else root / "phantom-mirage-sources.txt"


def find_dir(root: Path, name: str) -> Path:
    hits = sorted({p.resolve() for p in root.rglob(name) if p.is_dir()})
    if not hits:
        raise BuildError(f"run dir {name} not found under {root}")
    # The same capture may be unpacked twice; identical inputs are fine.
    first = hits[0]
    for h in hits[1:]:
        for f in [*first.glob("run-*.json"), first / "tool-versions.txt"]:
            other = h / f.name
            if not other.is_file() or other.read_bytes() != f.read_bytes():
                raise BuildError(f"run dir {name} found twice with different inputs: {hits}")
    return first


def build(root: Path, out: Path, sources_file: Path | None = None) -> list[str]:
    sources_file = sources_file or default_sources(root)
    if not sources_file.is_file():
        raise BuildError(f"sources file {sources_file} not found (local only; see FINGERPRINT-DB.md)")
    sources = read_sources(sources_file)
    include = build_db.read_name_list(FP_DIR / "personas.txt")
    notes = read_limits(FP_DIR / "limits.txt")
    blocks = []
    written = []
    for persona in [p for p in build_db.PERSONA_ORDER if p in sources]:
        inps = []
        for name in sources[persona]:
            d = find_dir(root, name)
            inps.append(build_db.load_inputs(sorted(d.glob("run-*.json")), d / "tool-versions.txt", d.name))
        got, block, sidecar = build_db.build_block(inps, notes.get(persona, []))
        if got != persona:
            raise BuildError(f"sources file lists {persona}, but those captures are {got}")
        blocks.append(block)
        if persona in include:
            (out / f"{persona}.provenance.json").write_text(sidecar, encoding="utf-8")
            written.append(f"{persona}.provenance.json")
    blocks += imported_blocks(sources)
    text, _ = build_db.assemble(blocks, include)
    (out / DB_NAME).write_text(text, encoding="utf-8")
    return [DB_NAME, *written]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="build_shipped_db.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--captures-root", type=Path, required=True)
    p.add_argument("--sources", type=Path, default=None)
    p.add_argument("--out", type=Path, default=FP_DIR)
    p.add_argument("--check", action="store_true", help="compare with the committed files only")
    a = p.parse_args(argv)
    try:
        if a.check:
            with tempfile.TemporaryDirectory() as t:
                files = build(a.captures_root, Path(t), a.sources)
                diff = [f for f in files if (Path(t) / f).read_bytes() != (a.out / f).read_bytes()
                        or not (a.out / f).is_file()]
            for f in diff:
                print(f"build_shipped_db.py: differs: {f}", file=sys.stderr)
            print(f"build_shipped_db.py: {len(files)} file(s) checked, {len(diff)} differ", file=sys.stderr)
            return 1 if diff else 0
        a.out.mkdir(parents=True, exist_ok=True)
        for f in build(a.captures_root, a.out, a.sources):
            print(f"wrote {a.out / f}", file=sys.stderr)
        return 0
    except BuildError as e:
        print(f"build_shipped_db.py: refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
