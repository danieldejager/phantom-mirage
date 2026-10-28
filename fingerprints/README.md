# Phantom Mirage personality file

`phantom-mirage-os.db` holds Fingerprint blocks measured in the Phantom
Mirage lab and built by `tools/fingerprint-lab/build_db.py` (issue #150).
It is not derived from, and does not include, the bundled `nmap-os-db`.

Personas: `ubuntu2404`, `ws2022-fwoff`, `ws2019-fwoff`, `ws2025-fwoff`,
`win11-fwon`, `win11-fwoff` (Windows 11, measured open port 3389).

The two `win11-*` blocks are not rebuilt here: they are copied byte for
byte from the project's own fingerprint database (`columbo-v1.db`) and kept
in `imported/<persona>.fp`. Their sidecars record what that release
publishes (6 probe runs, probe and derive 0.3.2); capture input hashes,
the derive commit and closed ports are not available and are left null.
`build_shipped_db.py` takes them from `imported/` as they are.

- `personas.txt`: the include list, in database order.
- `limits.txt`: extra `#@ limit:` lines per persona.
- `imported/<persona>.fp`: blocks copied from a published database.
- `<persona>.provenance.json`: provenance sidecar per persona (not loaded).

No lab identifiers are shipped. The mapping from persona to lab capture
runs is internal: it lives in a local-only sources file outside the
repository (see FINGERPRINT-DB.md), and the run ids are in PR #161.

Select it with `-p fingerprints/phantom-mirage-os.db`. Only one personality
file is loaded, so every personality in the config must then be one of the
names above. Rebuild or verify with `tools/fingerprint-lab/build_shipped_db.py`.
See `tools/fingerprint-lab/FINGERPRINT-DB.md` for the method and limits.
