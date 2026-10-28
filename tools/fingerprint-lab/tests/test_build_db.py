"""Tests for build_db.py, check_db.py and check_config_refs.py.

All inputs are SYNTHETIC fixtures (tests/fixtures/synthetic); no packets are
sent and nothing is read from the network.
"""

from __future__ import annotations

import builtins
import io
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1]
REPO = LAB.parents[1]
sys.path.insert(0, str(LAB))

import build_db  # noqa: E402
import check_config_refs  # noqa: E402
import check_db  # noqa: E402

SYN = LAB / "tests" / "fixtures" / "synthetic"
GOLDEN = SYN / "golden"
WS = SYN / "ws2022" / "run-900001-1-fwon"
UB = SYN / "ubuntu2404" / "run-900002-1-fwon"
FORBIDDEN = {"nmap.xml", "nmap.txt", "p0f.log", "personality.txt", "derive-report.json", "nmap-os-db"}


def _block(run_dir: Path, out: Path, *extra: str) -> int:
    return build_db.main(["block", str(run_dir), "-o", str(out), *extra])


def _copy_case(src: Path, tmp: Path, name: str | None = None) -> Path:
    dst = tmp / "case" / (name or src.name)
    shutil.copytree(src, dst)
    return dst


def _edit_runs(d: Path, fn, which=None):
    for i, p in enumerate(sorted(d.glob("run-*.json"))):
        if which is None or i in which:
            doc = json.loads(p.read_text())
            fn(doc)
            p.write_text(json.dumps(doc, indent=2, sort_keys=True))


def _edit_tv(d: Path, old: str, new: str):
    p = d / "tool-versions.txt"
    t = p.read_text()
    assert old in t
    p.write_text(t.replace(old, new))


# ---- expected persona list ----------------------------------------------

def test_persona_order_is_the_issue_list():
    assert build_db.PERSONA_ORDER == [
        "ubuntu2404",
        "ws2022-fwon", "ws2022-fwoff", "ws2019-fwon", "ws2019-fwoff",
        "ws2025-fwon", "ws2025-fwoff", "win11-fwon", "win11-fwoff",
    ]


# ---- golden -------------------------------------------------------------

@pytest.mark.parametrize("case,persona", [(WS, "ws2022-fwon"), (UB, "ubuntu2404")])
def test_golden_block_and_sidecar(tmp_path, case, persona):
    assert _block(case, tmp_path) == 0
    for suffix in (".fp", ".provenance.json"):
        got = (tmp_path / f"{persona}{suffix}").read_bytes()
        assert got == (GOLDEN / f"{persona}{suffix}").read_bytes(), suffix


def test_golden_assembled_db(tmp_path):
    db = tmp_path / "x.db"
    rc = build_db.main(["assemble", str(GOLDEN / "ws2022-fwon.fp"), str(GOLDEN / "ubuntu2404.fp"),
                        "--include", str(SYN / "include.txt"), "-o", str(db)])
    assert rc == 0
    assert db.read_bytes() == (GOLDEN / "SYNTHETIC-example.db").read_bytes()


def test_sidecar_matches_block_and_inputs():
    side = json.loads((GOLDEN / "ws2022-fwon.provenance.json").read_text())
    fp = (GOLDEN / "ws2022-fwon.fp").read_bytes()
    assert side["persona"] == "ws2022-fwon"
    assert side["block_sha256"] == build_db._sha256(fp)
    (cap,) = side["captures"]
    assert [i["run"] for i in cap["inputs"]["runs"]] == ["c1r1", "c1r2", "c1r3"]
    for k in ("nmap_os_db", "ip", "vm", "probe_host", "kernel", "nmap_version", "p0f_version"):
        assert k not in cap["tool_versions"]
    assert "single capture" in side["limits"][0]
    assert "min-max" in side["sp_isr_method"] and "n-1" in side["sp_isr_method"]
    assert any("SEQ.SP" in r for r in side["rules_applied"])


def test_range_rule_applied_only_to_sp_isr():
    text = (GOLDEN / "ws2022-fwon.fp").read_text()
    assert "SP=1C-22" in text and "ISR=95-97" in text and "GCD=3E8%" in text
    assert "#@ ranges: " in text
    assert "#@ ranges: none" in (GOLDEN / "ubuntu2404.fp").read_text()


# ---- determinism --------------------------------------------------------

def test_deterministic_shuffled_order_and_location(tmp_path):
    runs = sorted(WS.glob("run-*.json"))
    outs = []
    for seed in range(4):
        order = runs[:]
        random.Random(seed).shuffle(order)
        out = tmp_path / f"o{seed}"
        rc = build_db.main(["block", "--runs", *map(str, order), "--tool-versions",
                            str(WS / "tool-versions.txt"), "--run-name", WS.name, "-o", str(out)])
        assert rc == 0
        outs.append(sorted((p.name, p.read_bytes()) for p in out.iterdir()))
    moved = _copy_case(WS, tmp_path)
    _block(moved, tmp_path / "moved")
    outs.append(sorted((p.name, p.read_bytes()) for p in (tmp_path / "moved").iterdir()))
    assert all(o == outs[0] for o in outs)


def test_assemble_order_independent(tmp_path):
    a, b = str(GOLDEN / "ubuntu2404.fp"), str(GOLDEN / "ws2022-fwon.fp")
    inc = str(SYN / "include.txt")
    build_db.main(["assemble", a, b, "--include", inc, "-o", str(tmp_path / "1")])
    build_db.main(["assemble", b, a, "--include", inc, "-o", str(tmp_path / "2")])
    assert (tmp_path / "1").read_bytes() == (tmp_path / "2").read_bytes()


# ---- never reads nmap/p0f/derive outputs --------------------------------

def test_planted_markers_absent_and_forbidden_files_never_opened(tmp_path, monkeypatch):
    opened: list[str] = []
    real_open, real_rb, real_rt = builtins.open, Path.read_bytes, Path.read_text

    def track(name):
        opened.append(os.path.basename(str(name)))

    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (track(f), real_open(f, *a, **k))[1])
    monkeypatch.setattr(io, "open", builtins.open)
    monkeypatch.setattr(Path, "read_bytes", lambda s: (track(s), real_rb(s))[1])
    monkeypatch.setattr(Path, "read_text", lambda s, *a, **k: (track(s), real_rt(s, *a, **k))[1])
    for case in (WS, UB):
        assert (case / "nmap.xml").exists() and (case / "p0f.log").exists()
        assert _block(case, tmp_path) == 0
    monkeypatch.undo()
    assert not FORBIDDEN & set(opened), opened
    for p in tmp_path.iterdir():
        assert "SYNTHETIC-MARKER" not in p.read_text(), p.name


# ---- refusals -----------------------------------------------------------

def _refused(tmp_path, d: Path, capsys, needle: str):
    out = tmp_path / "out"
    assert _block(d, out) == 2
    err = capsys.readouterr().err
    assert "refused" in err and needle in err, err
    assert not out.exists() or not any(out.iterdir())


def test_refuse_fewer_than_three_runs(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    sorted(d.glob("run-*.json"))[0].unlink()
    _refused(tmp_path, d, capsys, "at least 3")


@pytest.mark.parametrize("field,value,needle", [
    ("target", "10.0.0.99", "target"),
    ("ports", {"open_tcp": 1, "closed_tcp": 2, "closed_udp": 3}, "ports"),
    ("tool_version", "9.9.9", "tool_version"),
])
def test_refuse_mixed(tmp_path, capsys, field, value, needle):
    d = _copy_case(WS, tmp_path)
    _edit_runs(d, lambda doc: doc.__setitem__(field, value), which={1})
    _refused(tmp_path, d, capsys, needle)


def test_refuse_dry_run_top_level(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    _edit_runs(d, lambda doc: doc.__setitem__("dry_run", True))
    _refused(tmp_path, d, capsys, "dry")


def test_refuse_dry_run_exchange(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    _edit_runs(d, lambda doc: doc["exchanges"][0].__setitem__("dry_run", True), which={2})
    _refused(tmp_path, d, capsys, "dry")


def test_refuse_missing_tool_versions(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    (d / "tool-versions.txt").unlink()
    _refused(tmp_path, d, capsys, "tool-versions")


def test_refuse_run_dir_without_firewall_state(tmp_path, capsys):
    d = _copy_case(WS, tmp_path, "run-900001-1")
    _refused(tmp_path, d, capsys, "run-")


def test_refuse_tool_versions_without_firewall(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    _edit_tv(d, " firewall=on", "")
    _refused(tmp_path, d, capsys, "firewall")


def test_refuse_firewall_mismatch(tmp_path, capsys):
    d = _copy_case(WS, tmp_path, "run-900001-1-fwoff")
    _refused(tmp_path, d, capsys, "firewall")


def test_refuse_linux_firewall_off(tmp_path, capsys):
    d = _copy_case(UB, tmp_path, "run-900002-1-fwoff")
    _edit_tv(d, "firewall=on", "firewall=off")
    _refused(tmp_path, d, capsys, "firewall")


def test_refuse_tool_versions_ip_mismatch(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    _edit_tv(d, "ip=10.0.0.22", "ip=10.0.0.99")
    _refused(tmp_path, d, capsys, "ip")


def test_refuse_duplicate_run_id(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)
    _edit_runs(d, lambda doc: doc.__setitem__("run_id", "synthetic-ws2022-0001"))
    _refused(tmp_path, d, capsys, "run_id")


def test_refuse_field_disagreement_outside_range_rule(tmp_path, capsys):
    d = _copy_case(WS, tmp_path)

    def bump_window(doc):
        for ex in doc["exchanges"]:
            r = ex.get("reply_parsed")
            if isinstance(r, dict) and r.get("l4") == "tcp":
                r["window"] = 1234
    _edit_runs(d, bump_window, which={0})
    _refused(tmp_path, d, capsys, "disagree")


# ---- assembler ----------------------------------------------------------

def test_assemble_excludes_unlisted_and_rejects_bad_lists(tmp_path, capsys):
    inc = tmp_path / "inc"
    inc.write_text("ws2022-fwon\n")
    db = tmp_path / "db"
    assert build_db.main(["assemble", str(GOLDEN / "ubuntu2404.fp"), str(GOLDEN / "ws2022-fwon.fp"),
                          "--include", str(inc), "-o", str(db)]) == 0
    assert "Fingerprint ubuntu2404" not in db.read_text()
    assert "excluded" in capsys.readouterr().err
    for bad in ("ws2022-fwon\nnot-a-persona\n", "ws2022-fwon\nws2019-fwon\n"):
        inc.write_text(bad)
        assert build_db.main(["assemble", str(GOLDEN / "ws2022-fwon.fp"),
                              "--include", str(inc), "-o", str(tmp_path / "db2")]) == 2
    inc.write_text("ws2022-fwon\n")
    assert build_db.main(["assemble", str(GOLDEN / "ws2022-fwon.fp"), str(GOLDEN / "ws2022-fwon.fp"),
                          "--include", str(inc), "-o", str(tmp_path / "db3")]) == 2


# ---- check_db (expected personas + INDEPENDENT syntax check) ------------

GOLD_DB = (GOLDEN / "SYNTHETIC-example.db").read_text() if (GOLDEN / "SYNTHETIC-example.db").exists() else ""


def test_check_db_golden_ok():
    assert check_db.check(GOLD_DB, ["ws2022-fwon", "ubuntu2404"],
                          {"c": 'set a personality "ws2022-fwon"\nset b personality "ubuntu2404"\n'}) == []


def test_check_db_expected_mismatch():
    errs = check_db.check(GOLD_DB, ["ws2022-fwon", "ubuntu2404", "ws2019-fwon"])
    assert any("missing" in e for e in errs)
    errs = check_db.check(GOLD_DB, ["ws2022-fwon"])
    assert any("not in the expected" in e for e in errs)


def test_check_db_config_name_not_in_db():
    errs = check_db.check(GOLD_DB, None, {"c": 'set a personality "Linux 2.6.32"\n'})
    assert any("Linux 2.6.32" in e for e in errs)


def test_independent_syntax_rejects_comment_or_blank_inside_block():
    for insert in ("# note", ""):
        bad = GOLD_DB.replace("WIN(", insert + "\nWIN(", 1)
        assert any("outside a Fingerprint block" in e for e in check_db.check(bad))


def test_independent_syntax_rejects_unparseable_ecn_fields():
    bad = GOLD_DB.replace("%CC=N%Q=)", "%S=O%A=S+%F=AS%RD=0%Q=)", 1)
    assert any("parse_ecn" in e for e in check_db.check(bad))


def test_independent_syntax_requires_provenance_header():
    bad = GOLD_DB.replace("#@ persona: ubuntu2404\n", "", 1)
    assert any("provenance" in e for e in check_db.check(bad))


# ---- real loader (personality.c) if a built binary is available ---------

def _binary() -> Path | None:
    for c in (os.environ.get("PHANTOM_MIRAGE_BIN"), str(REPO / "phantom-mirage")):
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return Path(c)
    return None


def _verify(binary: Path, db: Path, conf_text: str, tmp: Path) -> subprocess.CompletedProcess:
    conf = tmp / "t.conf"
    conf.write_text(conf_text)
    return subprocess.run(
        [str(binary), "--verify-config", "-f", str(conf), "-i", "lo", "--disable-webserver",
         "-p", str(db), "-x", str(REPO / "xprobe2.conf"), "-a", str(REPO / "nmap.assoc"),
         "-0", str(REPO / "pf.os"), "-m", str(REPO / "nmap-mac-prefixes")],
        capture_output=True, text=True, timeout=60)


SEL = ('create a\nset a personality "ws2022-fwon"\nadd a tcp port 3389 open\n'
       'create b\nset b personality "ubuntu2404"\nadd b tcp port 22 open\n'
       'bind 10.255.0.1 a\nbind 10.255.0.2 b\n')


@pytest.mark.skipif(_binary() is None, reason="no built phantom-mirage (set PHANTOM_MIRAGE_BIN)")
def test_loadable_by_personality_c(tmp_path):
    r = _verify(_binary(), GOLDEN / "SYNTHETIC-example.db", SEL, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(_binary() is None, reason="no built phantom-mirage (set PHANTOM_MIRAGE_BIN)")
def test_bundled_only_name_fails_with_our_file(tmp_path):
    conf = 'create a\nset a personality "Linux 2.6.32"\nbind 10.255.0.1 a\n'
    r = _verify(_binary(), GOLDEN / "SYNTHETIC-example.db", conf, tmp_path)
    assert r.returncode != 0
    assert "Unknown personality" in r.stdout + r.stderr


# A block shaped like the 0.3.0 output for a real Linux target: timestamp
# option with two digits (T11), NOP-padded O3/ECN strings, SP/ISR above FF,
# II/SS omitted, S=A on T4/T6 and CD=S. Values are synthetic.
METHOD_SHAPED = """Fingerprint method-shaped
SEQ(SP=102%GCD=1%ISR=109%TI=Z%CI=Z%TS=22)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FAF0%W2=FAF0%W3=FAF0%W4=FAF0%W5=FAF0%W6=FAF0)
ECN(R=Y%DF=Y%T=40%TG=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%TG=40%W=FAF0%S=O%A=S+%F=AS%O=M5B4ST11NW7%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%TG=40%CD=S)
"""


@pytest.mark.skipif(_binary() is None, reason="no built phantom-mirage (set PHANTOM_MIRAGE_BIN)")
def test_verify_config_accepts_method_shaped_block(tmp_path):
    db = tmp_path / "m.db"
    db.write_text(METHOD_SHAPED)
    conf = 'create a\nset a personality "method-shaped"\nadd a tcp port 22 open\nbind 10.255.0.1 a\n'
    r = _verify(_binary(), db, conf, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(_binary() is None, reason="no built phantom-mirage (set PHANTOM_MIRAGE_BIN)")
def test_verify_config_rejects_bad_timestamp_option(tmp_path):
    db = tmp_path / "bad.db"
    db.write_text(METHOD_SHAPED.replace("O1=M5B4ST11NW7", "O1=M5B4SQNW7"))
    conf = 'create a\nset a personality "method-shaped"\nbind 10.255.0.1 a\n'
    r = _verify(_binary(), db, conf, tmp_path)
    assert r.returncode != 0


@pytest.mark.parametrize("old", ["0.2.0", "0.3.0", "0.3.1"])
def test_refuse_pre_032_probe_runs(tmp_path, capsys, old):
    d = _copy_case(WS, tmp_path)
    _edit_runs(d, lambda doc: doc.__setitem__("tool_version", old))
    _refused(tmp_path, d, capsys, "0.3.2")


# ---- config-reference lint ----------------------------------------------

def test_config_refs_synthetic_tree(tmp_path):
    (tmp_path / "docker").mkdir()
    (tmp_path / "docker" / "entrypoint.sh").write_text("exec /usr/bin/phantom-mirage -d \"$@\"\n"
                                                      "exec /usr/bin/phantom-mirage -p /x.db -d\n")
    (tmp_path / "config.sample").write_text('set a personality "Old OS"\nset b personality "ws2022-fwon"\n')
    (tmp_path / "Makefile.am").write_text("data = nmap-os-db\n")
    (tmp_path / "debian" / "tests").mkdir(parents=True)
    (tmp_path / "debian" / "tests" / "t").write_text("nmap-os-db\n")
    got = [(r, n, k) for r, n, k, _ in check_config_refs.scan(tmp_path)]
    assert got == [("Makefile.am", 1, "NMAP_OS_DB_REF"),
                   ("config.sample", 1, "PERSONA_NOT_OURS"),
                   ("docker/entrypoint.sh", 1, "DEFAULT_PERS_FILE")]
    assert check_config_refs.main(["--root", str(tmp_path)]) == 0
    assert check_config_refs.main(["--root", str(tmp_path), "--strict"]) == 1


def test_config_refs_real_repo_reports_known_findings():
    if not (REPO / "docker" / "phantom-mirage.conf").exists():
        pytest.skip("not run from a phantom-mirage checkout")
    kinds = {(r, k) for r, _, k, _ in check_config_refs.scan(REPO)}
    # docker/phantom-mirage.conf now uses columbo-v1.db personas (#150)
    assert ("docker/phantom-mirage.conf", "PERSONA_NOT_OURS") not in kinds
    assert ("docker/entrypoint.sh", "DEFAULT_PERS_FILE") in kinds
    assert ("Makefile.am", "NMAP_OS_DB_REF") in kinds


# ---- moved-persona drift (fails only for moved personas) ----------------

def _tree(tmp_path):
    (tmp_path / "docker").mkdir(parents=True)
    (tmp_path / "docker" / "x.conf").write_text('set a personality "Old OS A"\nset b personality "Old OS B"\n')
    return tmp_path


def test_moved_list_shipped_empty_and_today_repo_passes():
    assert check_config_refs.read_moved(check_config_refs.MOVED_DEFAULT) == {}
    if (REPO / "docker" / "phantom-mirage.conf").exists():
        found = check_config_refs.scan(REPO, {})
        assert sum(1 for f in found if f[2] == "PERSONA_NOT_OURS") >= 27  # 29 before #150 (docker conf), 28 before config.sample used ws2022-fwoff
        assert check_config_refs.main(["--root", str(REPO)]) == 0


def test_moved_persona_use_fails_others_only_reported(tmp_path, capsys):
    root = _tree(tmp_path / "r")
    moved = tmp_path / "moved.txt"
    moved.write_text("# example\nOld OS A => ws2022-fwon\n")
    rc = check_config_refs.main(["--root", str(root), "--moved", str(moved)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAIL: MOVED_PERSONA_DRIFT: Old OS A (moved to ws2022-fwon)" in out
    assert "report: PERSONA_NOT_OURS: Old OS B" in out
    moved.write_text("")
    assert check_config_refs.main(["--root", str(root), "--moved", str(moved)]) == 0


@pytest.mark.parametrize("bad", ["Old OS A\n", "Old OS A => not-ours\n", "A => ws2022-fwon\nA => ubuntu2404\n"])
def test_bad_moved_list_exit_2(tmp_path, bad):
    moved = tmp_path / "m"
    moved.write_text(bad)
    assert check_config_refs.main(["--root", str(_tree(tmp_path / "r")), "--moved", str(moved)]) == 2
