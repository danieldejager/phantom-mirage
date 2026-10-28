# Default personality file: `columbo-v1.db`

`columbo-v1.db` is the project's own fingerprint database, release v1,
committed byte for byte as published and pinned by sha256 in
`columbo-v1.db.sha256`
(`38f8d4cbde86b925a35d6157477913f148e7894c189fdfa1deeedbba9a94775f`).
It is the default personality file for the installed service (Debian
`pm-start` and init script) and the Docker image; both refuse to start if
the file does not match the pinned sha256. `-p FILE` still overrides it
(Docker: `PHANTOM_MIRAGE_PERSONALITIES` or a `-p` argument). The compiled-in
default of the bare binary is unchanged (`nmap-os-db`, still shipped).

Personas: `ubuntu2404`, `ws2022-fwoff`, `ws2019-fwoff`, `ws2025-fwoff`,
`win11-fwon`, `win11-fwoff`. Only one personality file is loaded, so every
`personality` in the config must be one of these names when it is used.
`config.sample` names `OpenBSD 4.0 (x86)`, which is not in this file, so
anyone using it with the new default file must change that personality
(the Debian package does this for you via `debian/mkconf.sh`).

Checks: `cd fingerprints && sha256sum -c columbo-v1.db.sha256` and
`tools/fingerprint-lab/tests/test_columbo_db.py` (both run in CI).
To update it, replace both files with a new published release and change
the pin in the test, the CI step and this README.

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
