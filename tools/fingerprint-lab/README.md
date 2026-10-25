# Fingerprint lab

Capture OS stack replies from **hosts you own** and derive draft honeyd
personality entries for Phantom Mirage. Measurements only — nothing here is
copied from any third-party OS fingerprint database.

## Safety rules (enforced by `probe.py`)

- `--i-own-these-hosts` is required on every invocation, including `--dry-run`;
  without it `probe.py` exits before building any packet.
- Exactly one target IP per invocation (positional argument). The tool opens
  sockets only to that IP.
- Targets must be private, exactly: IPv4 `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16` or loopback `127.0.0.0/8`; IPv6 ULA `fc00::/7` or `::1`.
  Everything else (link-local, `0.0.0.0/8`, documentation and benchmark
  ranges, CGNAT, multicast, unspecified, public, IPv4-mapped IPv6) is
  refused. Literal IPs only: hostnames are refused without any DNS lookup.
- `*_proxy` environment variables are dropped at start-up.

Operating rules (not enforced by code):

- Measure **our own hosts only**. Never import or copy a third-party OS
  fingerprint database.
- Lab probes stay inside the lab VNet (`10.0.0.0/24`) or the local Parallels
  host-only network. Decoy testing stays inside `192.168.1.240/29`.
- Never probe production or the public Internet.
- `nmap -O`, p0f and Satori are **test checks only**. They are never shipped
  or vendored into this repository.

## Azure reference lab (primary)

The reference hosts live in a private Azure lab (repo
`danieldejager/phantom-mirage-lab`): one VNet `10.0.0.0/24`, no public IPs.

| Host               | VM name           | IP        | Open TCP | Closed TCP | Closed UDP | Notes                            |
|--------------------|-------------------|-----------|----------|------------|------------|----------------------------------|
| Probe              | `pm-probe`        | 10.0.0.10 | -        | -          | -          | Runs `probe.py` / `derive.py`    |
| Ubuntu 24.04       | `pm-t-ubuntu2404` | 10.0.0.21 | 22       | 1          | 40000      |                                  |
| Windows Server 2022| `pm-t-ws2022`     | 10.0.0.22 | 3389     | 1          | 40000      | Capture firewall on **and** off  |
| Windows Server 2019| `pm-t-ws2019`     | 10.0.0.23 | 3389     | 1          | 40000      | Capture firewall on **and** off  |
| Windows Server 2025| `pm-t-ws2025`     | 10.0.0.24 | 3389     | 1          | 40000      | Capture firewall on **and** off  |

Captures are run through a manual, approval-gated GitHub Actions capture
workflow in the lab repo (planned / in review). There is no manual CLI access
to Azure. The workflow runs these fixed commands on `pm-probe` as root, from
this directory:

```
# Ubuntu 24.04
python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 22 --closed-tcp 1 --closed-udp 40000 --output /opt/pm/runs/ubuntu2404 10.0.0.21

# Windows Server 2022 (repeat for 2019 = 10.0.0.23, 2025 = 10.0.0.24)
python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 3389 --closed-tcp 1 --closed-udp 40000 --output /opt/pm/runs/ws2022-fw-on  10.0.0.22
#   ...switch the Windows firewall off on the target, then:
python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 3389 --closed-tcp 1 --closed-udp 40000 --output /opt/pm/runs/ws2022-fw-off 10.0.0.22

# Derive one draft personality per target / firewall state
python3 derive.py --os-name "Linux Ubuntu 24.04" --os-build "<uname -r>" -o /opt/pm/runs/ubuntu2404/personality.txt /opt/pm/runs/ubuntu2404/run-*.json
python3 derive.py --os-name "Microsoft Windows Server 2022" --os-build "<build>" -o /opt/pm/runs/ws2022-fw-on/personality.txt /opt/pm/runs/ws2022-fw-on/run-*.json
```

Add `--dry-run` to any `probe.py` command to print the probe set without
sending. `derive.py` also accepts `--json-report <file>` for a per-field
observation report.

### Azure path caveat

Captures taken through Azure's virtual network may differ from physical or
other-hypervisor paths for some fields (TTL, IP ID, TCP timestamps). This is
unverified. Validate a derived decoy over the same Azure path (a sensor VM in
the lab, planned), not only from a different network.

### Cost and cleanup

Lab VMs are destroyed after each session; disks bill while they exist. Copy
the run JSONs (and derived personalities) out of `/opt/pm/runs` before
destroying the lab.

## Local Parallels lab (ARM guests)

Windows 11 ARM and Ubuntu ARM stay on a Parallels Desktop **Host-Only**
network on Apple Silicon (e.g. `10.211.55.0/24`, static guest IPs).

| Guest          | IP           | Open TCP | Closed TCP | Closed UDP | Notes                           |
|----------------|--------------|----------|------------|------------|---------------------------------|
| Ubuntu 24.04   | 10.211.55.10 | 22       | 1          | 40000      | ARM64                           |
| Windows 11     | 10.211.55.20 | 3389     | 1          | 40000      | ARM; capture firewall on **and** off |

```
sudo python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 22 --closed-tcp 1 --closed-udp 40000 --output ../../fingerprint-runs/ubuntu2404-arm 10.211.55.10
sudo python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 3389 --closed-tcp 1 --closed-udp 40000 --output ../../fingerprint-runs/win11-fw-on 10.211.55.20
```

### Emulation

Timing fields (ISN rate / SP / ISR, timestamp Hz) from emulated guests are
unreliable. We do not use CPU emulation for any shipped personality; x64
references come from the Azure lab.

## Outputs

- `probe.py` writes `run-<uuid>.json` with run id, timestamp, tool version,
  exact command line, and every probe/reply (raw hex + parsed fields).
  From tool_version 0.2.0, each parsed TCP packet also carries `flags_bits`
  (the raw flag byte, including ECE 0x40 and CWR 0x80). The field is
  additive: older runs without it still derive, from the flag letters.
- `derive.py` prints a draft `Fingerprint …` block in honeyd syntax, with a
  comment header recording run ids and the operator-supplied OS name/build,
  and flags fields that vary across runs.

## What honeyd consumes

Field groups parsed by `personality.c`: `SEQ`, `OPS`, `WIN`, `ECN`, `T1`–`T7`,
`U1`, `IE`. Our entries are derived only from lab measurements of those
behaviours (TTL, window sizes, TCP option order, ISN class/GCD, IP-ID
behaviour, DF bits, ICMP quirks, etc.).

## Fingerprint database

To turn scored runs into `fingerprints/phantom-mirage-os.db` (selected with
`-p`), see [FINGERPRINT-DB.md](FINGERPRINT-DB.md) (`build_db.py`,
`check_db.py`, `check_config_refs.py`).

## Tests

```
cd tools/fingerprint-lab
python3 -m pytest -q
# also run the personality.c loader tests against a built binary:
PHANTOM_MIRAGE_BIN=/path/to/phantom-mirage python3 -m pytest -q
```

Tests use synthetic scapy packets and offline helpers only — they never send
probes.
