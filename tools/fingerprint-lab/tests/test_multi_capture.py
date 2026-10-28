"""build_db.py: several captures per persona, run dir suffixes, host-data
scrubbing, and the committed fingerprints/ database (issue #150).

Unit tests use SYNTHETIC fixtures only. The committed-database tests read
fingerprints/ in this repo; the rebuild test runs only when PM_CAPTURE_ROOT
points at the lab captures.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parents[1]
sys.path.insert(0, str(LAB))

import build_db  # noqa: E402
import build_shipped_db  # noqa: E402
import check_config_refs  # noqa: E402
import check_db  # noqa: E402

SYN = LAB / "tests" / "fixtures" / "synthetic"
WS = SYN / "ws2022" / "run-900001-1-fwon"
UB = SYN / "ubuntu2404" / "run-900002-1-fwon"
FP = REPO / "fingerprints"


def _capture(tmp: Path, src: Path, name: str, *, restart: bool = False, tag: str = "r",
             edit=None, tv_edit=None) -> Path:
    """Copy a synthetic capture under a new run dir name, giving its runs
    fresh run_ids (as a second capture would have)."""
    d = tmp / "caps" / name
    shutil.copytree(src, d)
    for p in sorted(d.glob("run-*.json")):
        doc = json.loads(p.read_text())
        doc["run_id"] = f"{doc['run_id']}-{tag}"
        if edit:
            edit(doc)
        p.unlink()
        (d / f"run-{doc['run_id']}.json").write_text(json.dumps(doc, indent=2, sort_keys=True))
    tv = (d / "tool-versions.txt").read_text()
    tv += f"restart={'1' if restart else '0'}\n"
    if tv_edit:
        tv = tv_edit(tv)
    (d / "tool-versions.txt").write_text(tv)
    return d


def _block(out: Path, *dirs: Path) -> int:
    return build_db.main(["block", *map(str, dirs), "-o", str(out)])


def _pair(tmp, **kw):
    a = _capture(tmp, WS, "run-900011-1-fwon-p3389", tag="a")
    b = _capture(tmp, WS, "run-900012-1-fwon-restart-p3389", restart=True, tag="b", **kw)
    return a, b


# ---- name selection -----------------------------------------------------

@pytest.mark.parametrize("name,expect", [
    ("run-1-1-fwon", ("1", "1", "on", False, None)),
    ("run-40301571937-1-fwoff-p135", ("40301571937", "1", "off", False, "135")),
    ("run-40321836463-1-fwoff-restart-p135", ("40321836463", "1", "off", True, "135")),
    ("run-40277330569-1-fwon-restart", ("40277330569", "1", "on", True, None)),
])
def test_run_dir_name_parsing(name, expect):
    m = build_db.parse_run_dir_name(name)
    assert (m["lab_run_id"], m["attempt"], m["firewall"], m["restart"], m["port"]) == expect


@pytest.mark.parametrize("name", ["run-1-1", "run-1-1-fwoff-p", "run-1-1-fwoff-x135", "run-1-1-fwoff-p135-restart"])
def test_run_dir_name_refused(name):
    with pytest.raises(build_db.BuildError):
        build_db.parse_run_dir_name(name)


@pytest.mark.parametrize("src,fw,persona", [(WS, "fwon", "ws2022-fwon"), (WS, "fwoff", "ws2022-fwoff"),
                                            (UB, "fwon", "ubuntu2404")])
def test_persona_name_from_target_and_firewall(tmp_path, src, fw, persona):
    tv_edit = (lambda t: t.replace("firewall=on", "firewall=off")) if fw == "fwoff" else None
    d = _capture(tmp_path, src, f"run-900020-1-{fw}", tv_edit=tv_edit)
    assert _block(tmp_path / "o", d) == 0
    assert (tmp_path / "o" / f"{persona}.fp").read_text().count(f"Fingerprint {persona}\n") == 1


# ---- several captures ---------------------------------------------------

def test_two_captures_merge_and_record_port(tmp_path):
    a, b = _pair(tmp_path)
    assert _block(tmp_path / "o", a, b) == 0
    fp = (tmp_path / "o" / "ws2022-fwon.fp").read_text()
    side = json.loads((tmp_path / "o" / "ws2022-fwon.provenance.json").read_text())
    assert "#@ limit:" not in fp
    assert "#@ ports: open_tcp=3389 closed_tcp=1 closed_udp=40000\n" in fp
    assert "lab-run" not in fp and "900011" not in fp and "900012" not in fp
    assert "#@ captures: 2 (second after a restart)\n" in fp and "#@ probe-runs: 6\n" in fp
    assert side["ports"]["open_tcp"] == 3389 and side["limits"] == []
    assert [c["restart"] for c in side["captures"]] == [False, True]
    assert side["block_sha256"] == hashlib.sha256(fp.encode()).hexdigest()


def test_two_captures_order_independent(tmp_path):
    a, b = _pair(tmp_path)
    assert _block(tmp_path / "1", a, b) == 0
    assert _block(tmp_path / "2", b, a) == 0
    for f in ("ws2022-fwon.fp", "ws2022-fwon.provenance.json"):
        assert (tmp_path / "1" / f).read_bytes() == (tmp_path / "2" / f).read_bytes()


def test_single_capture_limit_recorded(tmp_path):
    assert _block(tmp_path, WS) == 0
    fp = (tmp_path / "ws2022-fwon.fp").read_text()
    assert "#@ captures: 1\n" in fp and "#@ limit: single capture" in fp


def test_sidecar_has_no_lab_host_names_or_addresses(tmp_path):
    a, b = _pair(tmp_path)
    assert _block(tmp_path / "o", a, b) == 0
    for p in (tmp_path / "o").iterdir():
        t = p.read_text()
        assert "10.0.0.22" not in t and "SYNTHETIC-ws2022" not in t and "SYNTHETIC-EXAMPLE" not in t, p.name


def _refused(tmp, capsys, needle, *dirs):
    out = tmp / "out"
    assert _block(out, *dirs) == 2
    err = capsys.readouterr().err
    assert "refused" in err and needle in err, err
    assert not out.exists() or not any(out.iterdir())


def test_refuse_stable_field_disagreement_across_captures(tmp_path, capsys):
    def win(doc):
        for ex in doc["exchanges"]:
            rp = ex.get("reply_parsed") or {}
            if ex["name"].startswith("SEQ") and rp.get("window") == 65535:
                rp["window"] = 65000
    a, b = _pair(tmp_path, edit=win)
    _refused(tmp_path, capsys, "runs disagree on fields with no range rule", a, b)


def test_refuse_captures_of_different_personas(tmp_path, capsys):
    a = _capture(tmp_path, WS, "run-900011-1-fwon", tag="a")
    b = _capture(tmp_path, WS, "run-900012-1-fwoff", tag="b",
                 tv_edit=lambda t: t.replace("firewall=on", "firewall=off"))
    _refused(tmp_path, capsys, "captures disagree on persona", a, b)


def test_refuse_captures_of_different_builds(tmp_path, capsys):
    a = _capture(tmp_path, WS, "run-900011-1-fwon", tag="a", tv_edit=lambda t: t + "target_os_build=1\n")
    b = _capture(tmp_path, WS, "run-900012-1-fwon", tag="b", tv_edit=lambda t: t + "target_os_build=2\n")
    _refused(tmp_path, capsys, "target_os_build", a, b)


def test_refuse_captures_on_different_ports(tmp_path, capsys):
    a = _capture(tmp_path, WS, "run-900011-1-fwon", tag="a")
    b = _capture(tmp_path, WS, "run-900012-1-fwon", tag="b",
                 edit=lambda d: d["ports"].__setitem__("open_tcp", 135),
                 tv_edit=lambda t: t.replace("open_tcp=3389", "open_tcp=135"))
    _refused(tmp_path, capsys, "captures disagree on ports", a, b)


def test_refuse_same_capture_twice(tmp_path, capsys):
    _refused(tmp_path, capsys, "same capture was given twice", WS, WS)


def test_refuse_port_suffix_mismatch(tmp_path, capsys):
    d = _capture(tmp_path, WS, "run-900011-1-fwon-p135")
    _refused(tmp_path, capsys, "says -p135", d)


def test_refuse_restart_flag_mismatch(tmp_path, capsys):
    d = _capture(tmp_path, WS, "run-900011-1-fwon-restart")  # restart=0 in tool-versions
    _refused(tmp_path, capsys, "restart mismatch", d)


def test_refuse_mixed_probe_versions_across_captures(tmp_path, capsys):
    a = _capture(tmp_path, WS, "run-900011-1-fwon", tag="a")
    b = _capture(tmp_path, WS, "run-900012-1-fwon", tag="b",
                 edit=lambda d: d.__setitem__("tool_version", "9.9.9"))
    _refused(tmp_path, capsys, "different probe.py versions", a, b)


# ---- our personas never ride on the bundled file ------------------------

def test_our_persona_on_bundled_db_fails(tmp_path, capsys):
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "a.conf").write_text('set w personality "ws2019-fwoff"\n')
    (tmp_path / "docker" / "run.sh").write_text(
        'set w personality "ws2025-fwoff"\nexec /usr/bin/phantom-mirage -d -p /usr/share/phantom-mirage/nmap-os-db\n')
    (tmp_path / "docker" / "ok.sh").write_text(
        'set w personality "ws2022-fwoff"\nexec /usr/bin/phantom-mirage -d -p /x/phantom-mirage-os.db\n')
    (tmp_path / "docker" / "nop.sh").write_text(
        'set w personality "ubuntu2404"\nexec /usr/bin/phantom-mirage -d\n')
    got = [(r, k) for r, _, k, _ in check_config_refs.scan(tmp_path) if k == "OUR_PERSONA_ON_BUNDLED_DB"]
    assert got == [("docker/nop.sh", "OUR_PERSONA_ON_BUNDLED_DB"), ("docker/run.sh", "OUR_PERSONA_ON_BUNDLED_DB")]
    assert check_config_refs.main(["--root", str(tmp_path)]) == 1
    assert "FAIL: OUR_PERSONA_ON_BUNDLED_DB" in capsys.readouterr().out


def test_real_repo_has_no_our_persona_on_bundled_db():
    found = check_config_refs.scan(REPO)
    assert not [f for f in found if f[2] == "OUR_PERSONA_ON_BUNDLED_DB"], found


# ---- the committed database ---------------------------------------------

SHIPPED = ["ubuntu2404", "ws2022-fwoff", "ws2019-fwoff", "ws2025-fwoff", "win11-fwon", "win11-fwoff"]
# Built here from local captures; win11-* are imported byte for byte from columbo-v1.db.
REBUILT = ["ubuntu2404", "ws2022-fwoff", "ws2019-fwoff", "ws2025-fwoff"]
IMPORTED = ["win11-fwon", "win11-fwoff"]


def _blocks():
    blocks, _, errors = check_db.parse_db((FP / "phantom-mirage-os.db").read_text())
    assert not errors, errors
    return {b["name"]: b for b in blocks}


def test_shipped_db_passes_check_db_and_lists_exact_personas():
    assert build_db.read_name_list(FP / "personas.txt") == SHIPPED
    errs = check_db.check((FP / "phantom-mirage-os.db").read_text(), expect=SHIPPED)
    assert errs == []
    assert set(_blocks()) == set(SHIPPED)


def b_fw(name):
    return "on" if name.endswith("-fwon") or name == "ubuntu2404" else "off"


def test_shipped_sidecars_match_blocks():
    text = (FP / "phantom-mirage-os.db").read_text()
    for name in SHIPPED:
        side = json.loads((FP / f"{name}.provenance.json").read_text())
        m = re.search(rf"(^#@ persona: {re.escape(name)}\n.*?)(?:\n\n|\Z)", text, re.M | re.S)
        assert side["block_sha256"] == hashlib.sha256((m[1].rstrip("\n") + "\n").encode()).hexdigest()
        assert side["persona"] == name and "min-max" in side["sp_isr_method"]
        assert side["target"]["firewall"] == b_fw(name)


def test_shipped_files_have_no_lab_addresses_or_host_names():
    ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for p in sorted(q for q in FP.rglob("*") if q.is_file()):
        t = p.read_text()
        # OS build numbers like 10.0.20348.5761 have four dotted parts too;
        # allow only those, on target_os_build / os-build lines.
        for line in t.splitlines():
            if ip.search(line):
                assert "os_build" in line or "os-build" in line, (p.name, line)
        for bad in ("pm-t-", "pm-probe", '"ip"', '"vm"', '"probe_host"'):
            assert bad not in t, (p.name, bad)


def test_shipped_windows_personas_name_their_port():
    b = _blocks()
    for name in ("ws2022-fwoff", "ws2019-fwoff", "ws2025-fwoff"):
        assert b[name]["hdr"]["ports"].startswith("open_tcp=135 "), name
        side = json.loads((FP / f"{name}.provenance.json").read_text())
        assert side["ports"]["open_tcp"] == 135
    assert b["ubuntu2404"]["hdr"]["ports"].startswith("open_tcp=22 ")
    for name in IMPORTED:
        assert b[name]["hdr"]["ports"] == "open_tcp=3389", name
        assert json.loads((FP / f"{name}.provenance.json").read_text())["ports"]["open_tcp"] == 3389


def test_shipped_db_matches_measured_facts():
    b = {k: v["groups"] for k, v in _blocks().items()}
    w6 = {k: re.search(r"W6=([0-9A-F]+)", b[k]["WIN"])[1] for k in ("ws2019-fwoff", "ws2022-fwoff", "ws2025-fwoff")}
    assert {k: int(v, 16) for k, v in w6.items()} == {"ws2019-fwoff": 65392, "ws2022-fwoff": 65500,
                                                     "ws2025-fwoff": 65535}
    assert "TS=U" in b["ws2019-fwoff"]["SEQ"]
    assert "O=M582NW8NNS" in b["ws2019-fwoff"]["ECN"]
    for k in ("ws2019-fwoff", "ws2022-fwoff", "ws2025-fwoff"):
        assert b[k]["T3"] == "R=N"

    def strip_seq(g):
        return {k: re.sub(r"(SP|ISR)=[0-9A-F-]+", r"\1=*", v) for k, v in g.items()}
    a, c = strip_seq(b["ws2022-fwoff"]), strip_seq(b["ws2025-fwoff"])
    assert [k for k in a if a[k] != c[k]] == ["WIN"]
    assert a["WIN"].replace("W6=FFDC", "W6=FFFF") == c["WIN"]


def test_shipped_limits_recorded():
    b = _blocks()
    assert b["ws2022-fwoff"]["hdr"]["captures"] == "1"
    assert b["ws2022-fwoff"]["hdr"]["limit"].startswith("single capture")
    assert b["ws2019-fwoff"]["hdr"]["captures"] == "2 (second after a restart)"
    assert b["ws2025-fwoff"]["hdr"]["captures"] == "2 (second after a restart)"


def test_shipped_db_has_no_class_or_cpe_lines():
    # Our blocks carry only measured groups; Class and CPE lines are never generated.
    text = (FP / "phantom-mirage-os.db").read_text()
    assert "Class " not in text and "CPE " not in text


@pytest.mark.skipif(not os.environ.get("PM_CAPTURE_ROOT"), reason="set PM_CAPTURE_ROOT to the lab captures")
def test_shipped_db_rebuilds_byte_for_byte():
    assert build_shipped_db.main(["--captures-root", os.environ["PM_CAPTURE_ROOT"], "--check"]) == 0


from test_build_db import _binary, _verify  # noqa: E402

SHIPPED_SEL = ('create u\nset u personality "ubuntu2404"\nadd u tcp port 22 open\n'
               'create a\nset a personality "ws2022-fwoff"\nadd a tcp port 135 open\n'
               'create b\nset b personality "ws2019-fwoff"\nadd b tcp port 135 open\n'
               'create c\nset c personality "ws2025-fwoff"\nadd c tcp port 135 open\n'
               'bind 10.255.0.1 u\nbind 10.255.0.2 a\nbind 10.255.0.3 b\nbind 10.255.0.4 c\n')


@pytest.mark.skipif(_binary() is None, reason="no built phantom-mirage (set PHANTOM_MIRAGE_BIN)")
def test_shipped_db_loadable_by_personality_c(tmp_path):
    r = _verify(_binary(), FP / "phantom-mirage-os.db", SHIPPED_SEL, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


# ---- no lab identifiers in shipped output (review on #161) --------------

LEAKS = {
    "lab-run": re.compile(r"lab-run|lab_run"),
    "10+ digit run number": re.compile(r"(?<![0-9a-fA-F])[0-9]{10,}(?![0-9a-fA-F])"),
    "UUID": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "-azure": re.compile(r"-azure", re.I),
    "oracle tool version": re.compile(r"nmap_version|nmap_pkg|p0f_version|Nmap version"),
    "run dir name": re.compile(r"run-[0-9]+-[0-9]+-fw"),
}


def _leaks(text):
    return [k for k, rx in LEAKS.items() if rx.search(text)]


def test_shipped_files_have_no_lab_identifiers():
    files = [FP / "phantom-mirage-os.db", *sorted(FP.glob("*.provenance.json")), *sorted((FP / "imported").glob("*.fp"))]
    assert len(files) == 9
    for p in files:
        assert _leaks(p.read_text()) == [], p.name


def test_no_sources_file_in_repo():
    assert not (FP / "sources.txt").exists()


def test_leak_patterns_fire():
    for bad in ("#@ lab-run: 1", "x 12345678901 y", "01234567-89ab-cdef-0123-456789abcdef",
                "7.0.0-1017-azure", '"nmap_pkg": "7.94"', "run-1-1-fwoff"):
        assert _leaks(bad), bad
    assert not _leaks("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 10.0.12345.1")


def test_synthetic_build_has_no_lab_identifiers(tmp_path):
    a, b = _pair(tmp_path)
    assert _block(tmp_path / "o", a, b) == 0
    for p in (tmp_path / "o").iterdir():
        t = p.read_text()
        assert "lab_run" not in t and "lab-run" not in t and "synthetic-ws2022-000" not in t
        assert not LEAKS["UUID"].search(t) and "run-9000" not in t, p.name


def test_shipped_records_derive_provenance_and_input_hashes():
    import build_db as bd
    text = (FP / "phantom-mirage-os.db").read_text()
    assert text.count(f"#@ derive: fingerprint-lab/derive.py {bd.DERIVE['version']} commit "
                      f"{bd.DERIVE['commit']} sha256 {bd.DERIVE['sha256']}\n") == len(REBUILT)
    for name in IMPORTED:
        side = json.loads((FP / f"{name}.provenance.json").read_text())
        assert side["derive"]["version"] == bd.DERIVE["version"] and side["captures"] == []
    for name in REBUILT:
        side = json.loads((FP / f"{name}.provenance.json").read_text())
        assert side["derive"] == bd.DERIVE
        for c in side["captures"]:
            assert re.fullmatch(r"[0-9a-f]{64}", c["inputs"]["tool_versions_sha256"])
            assert c["inputs"]["runs"] and all(re.fullmatch(r"[0-9a-f]{64}", r["sha256"])
                                               for r in c["inputs"]["runs"])


def test_ubuntu_ts_limit_line():
    b = _blocks()["ubuntu2404"]
    assert re.search(r"(^|%)TS=22($|%|\))", b["groups"]["SEQ"]), b["groups"]["SEQ"]
    text = (FP / "phantom-mirage-os.db").read_text()
    assert ("#@ limit: TS=22 comes from this capture only; an after-restart capture was not merged "
            "because one of its runs read TS=23 (6 runs seen across both captures: 5 read TS=22, "
            "1 read TS=23); the decoy check allows TS 22 and 23\n") in text


def test_extra_limit_must_be_one_line(tmp_path):
    inp = build_db.load_inputs(sorted(WS.glob("run-*.json")), WS / "tool-versions.txt", WS.name)
    with pytest.raises(build_db.BuildError):
        build_db.build_block(inp, ["a\nb"])
    _, block, _ = build_db.build_block(inp, ["note one"])
    assert "#@ limit: note one\nFingerprint " in block


# ---- imported win11 blocks ----------------------------------------------

def test_imported_blocks_are_in_db_and_sidecars():
    text = (FP / "phantom-mirage-os.db").read_text()
    assert sorted(p.stem for p in (FP / "imported").glob("*.fp")) == sorted(IMPORTED)
    for name in IMPORTED:
        blk = (FP / "imported" / f"{name}.fp").read_text()
        assert blk in text
        side = json.loads((FP / f"{name}.provenance.json").read_text())
        assert side["block_sha256"] == hashlib.sha256(blk.encode()).hexdigest()
        assert side["source"]["asset"] == "columbo-v1.db"
        assert "imported" in blk and "#@ firewall: " + b_fw(name) in blk


def test_imported_blocks_feed_build(monkeypatch):
    assert [build_db.block_persona(t) for t in build_shipped_db.imported_blocks({})] == ["win11-fwoff", "win11-fwon"]
    with pytest.raises(build_db.BuildError):
        build_shipped_db.imported_blocks({"win11-fwon": ["x"]})
