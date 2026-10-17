# Honeyd architecture documentation

> TODO (Quill): overview of what Honeyd is, how to read these docs, plain-English walkthrough (`00-walkthrough.md`) and glossary.

## Index

| File | Contents |
|---|---|
| [00-walkthrough.md](00-walkthrough.md) | Plain-English walkthrough (TODO, Quill) |
| [01-system-context.md](01-system-context.md) | C4 context and container diagrams |
| [02-components.md](02-components.md) | Internal modules and call relationships |
| [03-data-model.md](03-data-model.md) | In-memory entities (ER diagrams) |
| [04-packet-flow.md](04-packet-flow.md) | Sequence diagrams: TCP, UDP, ICMP, fingerprint spoofing, routing |
| [05-configuration.md](05-configuration.md) | Config language mapped to structs |
| [06-build-and-dependencies.md](06-build-and-dependencies.md) | Build system, dependencies, modern-Linux build issues |
| [07-security-and-modernisation-notes.md](07-security-and-modernisation-notes.md) | Unsafe areas, privileges, Docker notes |
| [NOTES-for-writers.md](NOTES-for-writers.md) | Entry points, key structs and functions with file:line refs |

All references are to the `master` branch (commit `a0f3d64`).
