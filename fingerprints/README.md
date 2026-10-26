# Phantom Mirage personality file

`phantom-mirage-os.db` holds Fingerprint blocks measured in the Phantom
Mirage lab and built by `tools/fingerprint-lab/build_db.py` (issue #150).
It is not derived from, and does not include, the bundled `nmap-os-db`.

Personas: `ubuntu2404`, `ws2022-fwoff`, `ws2019-fwoff`, `ws2025-fwoff`.

- `personas.txt`: the include list, in database order.
- `limits.txt`: extra `#@ limit:` lines per persona.
- `<persona>.provenance.json`: provenance sidecar per persona (not loaded).

No lab identifiers are shipped. The mapping from persona to lab capture
runs is internal: it lives in a local-only sources file outside the
repository (see FINGERPRINT-DB.md), and the run ids are in PR #161.

Select it with `-p fingerprints/phantom-mirage-os.db`. Only one personality
file is loaded, so every personality in the config must then be one of the
names above. Rebuild or verify with `tools/fingerprint-lab/build_shipped_db.py`.
See `tools/fingerprint-lab/FINGERPRINT-DB.md` for the method and limits.
