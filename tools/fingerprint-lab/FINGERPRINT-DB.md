# Fingerprint database generator (issue #150)

`build_db.py` turns lab runs into `Fingerprint` blocks for a separate
Phantom Mirage personality file, `fingerprints/phantom-mirage-os.db`.
`check_db.py` checks such a file. `check_config_refs.py` lists the shipped
config that still points at the bundled `nmap-os-db`.

All three scripts are offline. They open no sockets and send no packets.
They change nothing outside the output paths you give them.

**Status:** this change ships the tooling, the tests and the SYNTHETIC
fixtures only. It does **not** create `fingerprints/phantom-mirage-os.db`,
because no persona has passed scoring yet. An empty or placeholder file
would be one more thing to install, and it would claim nothing useful. The
file is added later from real, scored runs. The bundled `nmap-os-db` and the
shipped configs are not changed.

## Inputs (and nothing else)

For one lab run directory `run-<id>-<attempt>-fw<on|off>/`, the generator
reads:

- the `run-*.json` files written by `probe.py` (at least 3)
- `tool-versions.txt`, written by the capture script
- the directory name, which gives the firewall state

It never opens `nmap.xml`, `nmap.txt`, `p0f.log`, `personality.txt`,
`derive-report.json`, or any nmap-os-db, p0f or Satori data. The tests plant
marker files with those names and check two things: the marker files are
never opened, and no marker text appears in the output. The `nmap_os_db=`
line of `tool-versions.txt` is dropped from the provenance.

## Usage

```sh
# one block (+ sidecar) per run directory
python3 build_db.py block path/to/ws2022/run-123-1-fwon -o blocks/
#   or explicitly:
python3 build_db.py block --runs a.json b.json c.json \
    --tool-versions tool-versions.txt --run-name run-123-1-fwon -o blocks/

# assemble only the personas that passed scoring, in the fixed order
python3 build_db.py assemble blocks/*.fp --include passed.txt \
    -o ../../fingerprints/phantom-mirage-os.db

# check it: expected personas, provenance headers, independent syntax,
# and that a config's personality names all resolve
python3 check_db.py ../../fingerprints/phantom-mirage-os.db \
    --expect passed.txt --config my.conf

# real loader check (personality.c), needs a built binary, no root needed
./phantom-mirage --verify-config -f my.conf -i lo --disable-webserver \
    -p fingerprints/phantom-mirage-os.db -x xprobe2.conf -a nmap.assoc \
    -0 pf.os -m nmap-mac-prefixes

# list shipped references to the bundled file; fails only for personas
# listed in moved-personas.txt (empty today), reports everything else
python3 check_config_refs.py            # add --strict to exit 1 on any finding
```

`passed.txt` has one persona per line. Lines starting with `#` are comments.
A block that is not on the list is left out, and the assembler notes it on
stderr. An unknown name on the list, a name listed twice, or a listed name
with no block is refused. Refusals print `build_db.py: refused: <reason>`
and exit with status 2.

## Persona names

The order is fixed. The assembler always writes personas in this order:

`ubuntu2404`, `ws2022-fwon`, `ws2022-fwoff`, `ws2019-fwon`, `ws2019-fwoff`,
`ws2025-fwon`, `ws2025-fwoff`, `win11-fwon`, `win11-fwoff`.

Linux has a single persona, captured with the firewall on. Windows has one
persona for each firewall state. Configs select a persona with
`set <template> personality "<name>"`.

## Format

Each block is one honeyd `Fingerprint` entry, preceded by `#@ key: value`
provenance lines. In `personality_parse`, a comment line or a blank line ends
the current block. For that reason:

- the `#@` header comes before the `Fingerprint` line
- there are no comment or blank lines inside a block
- blocks are separated by one blank line

The test groups are `SEQ OPS WIN ECN T1-T7 U1 IE`, one line each. The ECN
line uses only the fields that `parse_ecn` accepts: `R DF T TG W O CC Q`.
The file begins with a fixed comment header and a
`#@ db-personas: a,b,...` line.

Header keys, in order: `persona`, `target`, `firewall`, `lab-run`,
`probe-runs`, `probe-tool`, `captured-utc`, `tool-source-commit`,
`tool-versions-sha256`, `generator`, `ranges`.

## Provenance sidecar

`<persona>.provenance.json` sits next to each block. It uses sorted keys and
an indent of 2. It records:

- the persona, generator and version
- the target and the lab run (id, attempt, firewall)
- each input run file with its basename, run_id and sha256
- the sha256 of `tool-versions.txt` and its parsed values (without `nmap_os_db`)
- the rules applied
- the raw derived fields of each run, before any rule
- the sha256 of the block

The sidecar is not part of the database file.

## Refusals

The generator refuses, with a non-zero exit and nothing written, on any of:

- fewer than 3 run JSONs
- a missing `tool-versions.txt`
- a dry run, flagged at the top level or on any exchange
- runs that disagree on `target`, `ports` or `tool_version`, or are missing them
- runs captured with a `probe.py` older than 0.3.2 (0.3.1 dropped RST
  replies to T2/T7 in its reply matcher, so closed-port results can be
  missing; 0.3.0 probes used
  base + index sequence numbers rather than a random one per probe; before
  0.3.0 the probes did not
  match the published probe set, so O3, the ECN options and T4/T6 `S` were
  measured against different packets; re-capture)
- a duplicate `run_id`
- an unknown target
- a run directory name without `-fwon` or `-fwoff`
- no `firewall=` in `tool-versions.txt`, or a value that differs from the directory name
- Linux with the firewall off
- a `tool-versions.txt` ip or ports value that differs from the runs
- any field that differs between runs, other than the range rule below

### Field-disagreement rules

The rules are deliberately minimal:

- `SEQ.SP` and `SEQ.ISR`: when the runs differ, the generator writes the
  `min-max` hex range of the runs (for example `SP=50-56`). `personality.c`
  accepts that syntax. This matches gate F5 of the scoring sheet, where the
  numeric SEQ values must fall inside the control's three-run range.
- Every other field must be identical in every run, including `GCD`,
  `TI/CI/II`, `SS`, `TS`, options, windows, T1-T7, U1 and IE. Otherwise the
  build is refused. Each range the generator uses is listed in
  `#@ ranges:` and in `rules_applied`.

## Selecting the file with `-p`, and the one-file consequence

`-p FILE` sets the personality file. Without `-p`, honeyd loads
`<datadir>/nmap-os-db`, or `$PHANTOM_MIRAGE_DATADIR/nmap-os-db` when that
variable is set. Only **one** personality file is loaded. Run with
`-p fingerprints/phantom-mirage-os.db` and every `personality "<name>"` in
the config must be one of our personas. Any other name fails at load with
`Unknown personality`, including every name in today's shipped configs.
The tests show this against the real binary. Configs therefore move over
as a whole, not one template at a time. `check_config_refs.py` lists what
would need to move.

### Moved-persona list

When a bundled persona is replaced by one of ours, add a line
`<bundled name> => <our persona>` to `moved-personas.txt`. From then on,
`check_config_refs.py` **fails** (exit 1, `FAIL: MOVED_PERSONA_DRIFT`) if any
shipped config still uses the old name. Every other use is printed as
`report:` and does not fail. The list is empty today, so the 29 current
bundled-name uses do not fail the check. A malformed list (bad syntax, an
unknown persona, a duplicate) exits 2.

## Known limits

- ECN `CC` (scoring gate F13) follows nmap's definition for the reply to the
  ECN probe (SYN with ECE+CWR): `Y` = ECE only, `N` = neither, `S` = ECE and
  CWR, `O` = any other combination (CWR without ECE; `personality.c` maps `O`
  to CWR only). From tool_version 0.2.0, `probe.py` records the raw TCP flag
  bits as `flags_bits` in each TCP `reply_parsed`. Runs from 0.1.0 lack it.
  For those, `derive.py` falls back to scapy's flag letters (`E` = ECE,
  `C` = CWR), which 0.1.0 already recorded. `derive.py` renders the ECN line
  directly in the `parse_ecn` field set, and `build_db.py` only verifies that
  the field set is right; it no longer rewrites the line.
- The fields come from `derive.py`, which follows the response-test rules
  in <https://nmap.org/book/osdetect-methods.html>. SP uses the sample
  (n-1) standard deviation of the per-probe ISN rates; on our first real
  capture this reproduces the oracle's SP exactly (the population form is 1
  lower). Linux gives each connection a random timestamp offset, so the
  TSval differences wrap and TS comes out as a large class (e.g. `22`), as
  the oracle also reports. `TG` is still written next to `T`, and `T1`
  keeps `W` and `O`; `personality.c` reads them.
- The generator adds nothing to the derived fields beyond the range rule.
- `win11` is a Parallels guest (Daniel's VM is its control). The fixed target
  table `capture/targets.sh` lives in the separate lab repository, not in this
  one, so win11 is not added here. Until it is, the generator's ip and ports
  cross-check for win11 relies on `tool-versions.txt` alone.
- Loading by `personality.c` is checked only when a built binary is present.
  Set `PHANTOM_MIRAGE_BIN`, or build at the repo root. Otherwise those tests
  are skipped and only the independent syntax check in `check_db.py` runs.
  That check is a separate re-implementation of the layout rules, not the C
  parser.
- No CI workflow runs the fingerprint-lab tests. `build.yml` ignores
  `tools/fingerprint-lab/**`, `docs/**` and `*.md`.
