# Honeyd architecture documentation

Honeyd is a single C program that pretends to be a whole network of computers. It answers traffic sent to unused IP addresses and makes each one look like a real machine, with its own operating system, open ports, services, network delay and position behind routers. Because no legitimate user has a reason to touch those addresses, anything that does is worth investigating. That makes Honeyd a honeynet: an early-warning decoy for scanning, worms and lateral movement.

This copy is Niels Provos' Honeyd 1.5/1.6 (2002 to 2007) plus later DataSoft/Nova additions. It reports version 1.6d.

## How to read these docs

1. **Start with [00-walkthrough.md](00-walkthrough.md).** It explains how Honeyd works in about ten minutes, in plain English, with no C required.
2. **Look up unfamiliar terms** in the [glossary](08-glossary.md).
3. **Go to the numbered pages** for diagrams and evidence. Every page cites source files and line numbers you can check.
4. **Read [07](07-security-and-modernisation-notes.md) before running it anywhere real.** It covers the known defects and how to contain the daemon.

All diagrams are Mermaid and render directly on GitHub.

## Index

| File | Contents |
|---|---|
| [00-walkthrough.md](00-walkthrough.md) | Plain-English walkthrough: how Honeyd works in 10 minutes |
| [01-system-context.md](01-system-context.md) | C4 context and container diagrams |
| [02-components.md](02-components.md) | Internal modules and call relationships |
| [03-data-model.md](03-data-model.md) | In-memory entities (ER diagrams) |
| [04-packet-flow.md](04-packet-flow.md) | Sequence diagrams: TCP, UDP, ICMP, fingerprint spoofing, routing |
| [05-configuration.md](05-configuration.md) | Config language mapped to structs |
| [06-build-and-dependencies.md](06-build-and-dependencies.md) | Build system, dependencies, modern-Linux build issues |
| [07-security-and-modernisation-notes.md](07-security-and-modernisation-notes.md) | Unsafe areas, privileges, Docker notes |
| [08-glossary.md](08-glossary.md) | Plain-English definitions of terms and acronyms |
| [09-gaps.md](09-gaps.md) | What Honeyd does not do: gaps proven in code, and open questions for a live test |
| [10-target-architecture.md](10-target-architecture.md) | Proposed deployment: Raspberry Pi sensors running Honeyd in Docker, feeding the customer's SIEM |
| [NOTES-for-writers.md](NOTES-for-writers.md) | Entry points, key structs and functions with file:line refs |

All references are to the `master` branch (commit `a0f3d64`).
