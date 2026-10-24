# Fingerprint lab

Capture OS stack replies from **hosts you own** and derive draft honeyd
personality entries for Phantom Mirage. Measurements only — nothing here is
copied from any third-party OS fingerprint database.

## Safety rules

- Targets must be RFC1918 IPv4, RFC4193 ULA IPv6, or loopback.
- `--i-own-these-hosts` is required on every real or dry-run invocation.
- The tool opens sockets only to the target IPs you pass on the command line.
- Do **not** run probes against production, cloud tenants, or the public Internet.
- Lab VMs first; never point this at a network you do not control.
- `nmap -O`, p0f and Satori are **test checks only** and are never shipped or
  vendored into this repository.

## Exact operator commands

Create a run directory, then capture (lab VMs must exist and be reachable):

```
cd tools/fingerprint-lab
python3 probe.py --dry-run --i-own-these-hosts --open-tcp 22 --closed-tcp 1 --closed-udp 40000 --output ../../fingerprint-runs/ubuntu2404 10.211.55.10
sudo python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 22 --closed-tcp 1 --closed-udp 40000 --output ../../fingerprint-runs/ubuntu2404 10.211.55.10
python3 derive.py --os-name "Linux Ubuntu 24.04 ARM64" --os-build "6.8.0-lab" -o ../../fingerprint-runs/ubuntu2404/personality.txt ../../fingerprint-runs/ubuntu2404/run-*.json
python3 -m pytest -q
```

Windows example (RDP open, ephemeral closed):

```
sudo python3 probe.py --i-own-these-hosts --runs 3 --open-tcp 3389 --closed-tcp 1 --closed-udp 40000 --output ../../fingerprint-runs/win11-fw-on 10.211.55.20
```

## Host-only lab setup (Apple Silicon)

Use a host-only / shared network so guest IPs are fixed and unreachable from
other LANs.

### Parallels Desktop

1. Create a **Host-Only** network (e.g. `10.211.55.0/24`).
2. Attach each guest NIC to that network; set static IPs (table below).
3. On each Linux guest: install `openssh-server` (open TCP 22); leave TCP 1 and
   UDP 40000 closed.
4. On each Windows guest: enable Remote Desktop (open TCP 3389) **or** a
   simple listener; capture once with Windows Firewall **on** and once **off**.

### UTM

1. Use a **Shared Network** or Emulated VLAN with static DHCP mappings /
   guest-side static IPs in `10.211.55.0/24` (or another RFC1918 block).
2. For x86_64 guests on Apple Silicon, use UTM emulation (qemu). Expect slower
   timers — see timing note below.
3. Same open/closed port convention as Parallels.

### Planned VMs

| Guest                         | Arch / how          | Suggested IP   | Open TCP | Closed TCP | Closed UDP | Notes                          |
|------------------------------|---------------------|----------------|----------|------------|------------|--------------------------------|
| Ubuntu 24.04                 | ARM64 native        | 10.211.55.10   | 22       | 1          | 40000      | Primary Linux reference        |
| Windows 11                   | ARM native          | 10.211.55.20   | 3389     | 1          | 40000      | Capture firewall on **and** off |
| Windows Server 2022          | x64 via UTM emu     | 10.211.55.30   | 3389     | 1          | 40000      | Emulated; cross-check timing   |
| Windows Server 2019          | x64 via UTM emu     | 10.211.55.31   | 3389     | 1          | 40000      | Emulated; cross-check timing   |
| Windows Server 2025          | x64 via UTM emu     | 10.211.55.32   | 3389     | 1          | 40000      | Emulated; cross-check timing   |
| Rocky Linux 9 (optional)     | ARM64 native        | 10.211.55.40   | 22       | 1          | 40000      | Optional RHEL-class reference  |
| FreeBSD 14 (optional)        | ARM64 native        | 10.211.55.50   | 22       | 1          | 40000      | Optional BSD reference         |

### Timing note

Timing-based fields (ISN rate / SP / ISR, timestamp Hz) from **emulated** VMs
are less reliable than native runs. Treat UTM-emulated Windows Server captures
as drafts and cross-check against native hardware or ARM-native guests before
shipping a personality.

## Outputs

- `probe.py` writes `run-<uuid>.json` with run id, timestamp, tool version,
  exact command line, and every probe/reply (raw hex + parsed fields).
- `derive.py` prints a draft `Fingerprint …` block in honeyd syntax, with a
  comment header recording run ids and the operator-supplied OS name/build,
  and flags fields that vary across runs.

## What honeyd consumes

Field groups parsed by `personality.c`: `SEQ`, `OPS`, `WIN`, `ECN`, `T1`–`T7`,
`U1`, `IE`. Our entries are derived only from lab measurements of those
behaviours (TTL, window sizes, TCP option order, ISN class/GCD, IP-ID
behaviour, DF bits, ICMP quirks, etc.).

## Tests

```
cd tools/fingerprint-lab
python3 -m pytest -q
```

Tests use synthetic scapy packets and offline helpers only — they never send
probes.
