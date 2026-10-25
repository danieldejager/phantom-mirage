# SYNTHETIC fixtures (example data only)

Everything under this directory is **invented example data** for the
`build_db.py` tests. It is not a capture of any real system; no packet was
sent to produce it, and no entry here may be copied into the shipped
database.

- `*/run-<id>-<attempt>-fw<on|off>/` mimic the lab capture layout. The
  `run-*.json` and `tool-versions.txt` files are the generator's inputs.
  `nmap.xml`, `nmap.txt`, `p0f.log`, `personality.txt` and
  `derive-report.json` only hold `SYNTHETIC-MARKER-...` strings so the tests
  can prove the generator never reads them.
- `golden/` is the expected generator output for these inputs.
- `include.txt` is an example include list (personas that "passed").

Regenerate inputs with `python3 make_fixtures.py`; regenerate goldens with the
commands in `tools/fingerprint-lab/README.md` (Fingerprint database section).
