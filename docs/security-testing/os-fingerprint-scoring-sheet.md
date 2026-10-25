# OS fingerprint scoring sheet (draft v0.1, for #146)

Status: design only. Nothing here is run until Daniel approves a test. Decoy probes stay inside `192.168.1.240/29`. Probes of the real reference VMs stay inside the lab network. Every command is posted in the project room as it is run.

This sheet extends B1 to B6 in `decoy-realism-acceptance-criteria.md`. It is the exact field-by-field comparison and the pass rule for #146.

## 1. Method in one paragraph

For each persona we scan two targets with the same tools, from the same probe host, on the same day: the real VM (the control) and the decoy built from our own captures. The real VM is the answer key. The decoy passes when each field matches the control, and when nmap and p0f give the same answer for the decoy as they give for the control. nmap and p0f are test oracles only. Their databases are never shipped.

## 2. Why the control matters (honest limits)

- The nmap database and the p0f database both lag the newest operating systems. Windows Server 2025, Windows 11 and Ubuntu 24.04 may not exist in them by name. If the control itself is labelled as an older release, the decoy must get the same label. We never tune a decoy to win a name the real host does not win.
- Because of that, "top match is the intended OS" is checked in two parts: (a) the control's top match is recorded, and (b) the decoy's top match equals the control's top match. If the control's top match is not the intended OS family at all, the persona claim is downgraded to what the control actually scores, and the claim in the product text must say so.
- nmap and p0f can both be fooled by a decoy that matches them and still differs from the real stack in a field they do not weigh. That is why the field diff in section 4 is the primary evidence and the two tools are the secondary check.

## 3. Test set-up (record all of it with every run)

| Item | Requirement |
|------|-------------|
| Probe host | Linux, root, same host for control and decoy. Record kernel, `nmap --version`, `p0f -h` version and the nmap database revision |
| Ports | One open TCP port and one closed TCP port, the same numbers on the control and the decoy. One closed UDP port. Record them |
| Path | Record hop count to each target. Compare initial TTL (observed TTL plus hops, rounded up to 32, 64, 128 or 255), never the observed TTL |
| Control | The real VM at the same patch level the persona claims. Rebuild or snapshot it so the three control runs are comparable |
| Repeats | 3 runs for the control and 3 runs for the decoy, at least 10 minutes apart. The decoy runs also include one run after a decoy restart (to catch a field that resets or changes) |
| Capture | `tcpdump -i <if> -w <run>.pcap host <target>` for every run, plus `nmap -O -v --osscan-guess -oX <run>.xml` and the nmap `-d` fingerprint line |
| Passive | p0f reads the same pcap (`p0f -r <run>.pcap`) and also one live connection from a real client |
| Evidence | Raw pcap, XML, command lines and times under `evidence/fingerprint/<persona>/<run>/`, in the private repo only |

## 4. Field-by-field scoring

Scoring per field: **2** matches the control exactly (deterministic fields) or sits inside the control's own run-to-run range (random fields), **1** differs but is explained and agreed as an engine limit in a linked issue, **0** differs without an explanation, **N** not measurable in this set-up. Fields marked **Gate** must score 2 for the persona to pass.

| # | Field | What is compared (control vs decoy) | How measured | Rule | Gate |
|---|-------|--------------------------------------|--------------|------|------|
| F1 | Initial TTL | Initial TTL on SYN-ACK, RST, ICMP echo reply and UDP unreachable | pcap, normalised for hops | Equal on all four packet types | Yes |
| F2 | DF bit | DF on SYN-ACK, RST, ICMP echo reply, ICMP port unreachable | pcap | Equal on each | Yes |
| F3 | TCP options and order | Option kinds in order on the SYN-ACK, including MSS value, window scale value, SACK permitted, timestamp presence and NOP padding | pcap, nmap `O1` to `O6` | Exact string equality for all six nmap probes | Yes |
| F4 | TCP window | Window value on the SYN-ACK and on RSTs, for each of the six nmap probes (`W1` to `W6`) | nmap, pcap | Equal. If the control's window varies by run, the decoy's must fall inside the control's three-run range | Yes |
| F5 | Initial sequence numbers (SEQ) | ISN class and the nmap SEQ values: `SP`, `GCD`, `ISR`, `TI`, `CI`, `II`, `SS` | nmap `-O` SEQ line, plus 20 or more SYN probes 100 ms apart for the ISN series | Same class. Each numeric value inside the control's three-run range. A fixed, counting or repeating ISN fails | Yes |
| F6 | ACK number behaviour | ACK value in the replies to the nmap probes (`T2` to `T7`): `S` (zero, same, S+1 or other), `A` | nmap | Equal for every probe | Yes |
| F7 | TCP flags in replies | Flags returned for SYN to open, SYN to closed, ACK, FIN, NULL, XMAS and SYN+FIN+URG+PSH probes (`T1` to `T7`) | nmap, pcap | Equal for every probe, including no reply where the control gives none | Yes |
| F8 | IP ID | IP ID class (`TI`, `CI`, `II`): zero, incremental, random, broken little-endian. Shared counter across TCP, ICMP and UDP or separate | nmap SEQ, 20 mixed probes | Same class and same counter-sharing as the control | Yes |
| F9 | TCP timestamps | Timestamp option present or not, clock rate (ticks per second from two timestamps 1 s and 10 s apart), value is monotonic, and the implied uptime is plausible and stable across connections and the decoy restart | pcap, nmap `TS` and `-O` uptime line | Same presence and the same clock-rate class as the control. Uptime is believable and does not reset per connection | Yes where the control uses timestamps |
| F10 | Closed TCP port reply | RST flags, window, sequence and ACK values, options, IP fields | nmap `T5`, `T6`, `T7`, pcap | Equal to the control's reply | Yes |
| F11 | Closed UDP port reply | ICMP port unreachable: type and code, returned IP total length (`RIPL`), returned ID (`RID`), checksum and UDP length echo fields (`RIPCK`, `RUCK`, `RUD`), TOS, unused field | nmap `U1` | Equal. Also compare the rate limit: 50 UDP probes in 1 second give the same reply count as the control, within 1 reply | Yes |
| F12 | ICMP echo | Echo reply to the two nmap ICMP probes (`IE`): code, TOS, DF, data length and data echo, and the code handling when the probe has a non-zero code | nmap `IE`, `ping` | Equal on every field | Yes |
| F13 | ECN | Reply to the ECN probe (SYN with ECE and CWR): ECN flags in the reply, options, window | nmap `ECN` | Equal | Yes |
| F14 | Timing under probes | SYN-ACK latency median and spread over 100 SYNs, and behaviour at 1000 SYNs in 5 seconds (SYN cookies, backlog, drops) | `hping3` or `nping`, pcap | Median within 2 ms of the control after allowing for path difference. Non-zero jitter. Same flood behaviour class (answers, slows, or drops) | No, but reported |
| F15 | Fragmentation and reassembly | Reply to overlapping and tiny fragments, and to a large ping that needs fragmenting | `nmap -f`, `fragroute` or `scapy` in the lab | Same reply or silence as the control | No, reported. Engine gap issue if it differs |
| F16 | Other stack behaviour seen by nmap | Remaining nmap OS fields not listed above (`R`, `RD`, `Q`, `CC`, `T` retained for completeness) | nmap fingerprint line | Equal | No, reported |

Notes:
- Where the engine cannot reproduce a field, score it 1 only with a linked issue and a decision from Forge on fix or drop. A persona with any field at 0 on a Gate row is not shipped.
- Expected option strings and window sizes for each operating system are not written here. They come from the capture of our own VM. We do not assume them from memory.

## 5. Pass rule per persona

A persona passes only when all of the following hold on three repeat runs of the decoy, plus the post-restart run:

1. Every Gate field (F1 to F13) scores 2 against the control, on every run.
2. nmap `-O --osscan-guess`: the decoy's top match is identical to the control's top match (same name and version string), with a match score within 3 points of the control's score, and no other OS family above 50 percent.
3. p0f: the decoy gets the same OS label and the same signature class as the control, on all three runs, from both the pcap and one live connection. No run returns "unknown" if the control does not.
4. The control's own top match is recorded. If it is not the intended persona (for example the nmap database has no Windows Server 2025 entry), the persona claim in the product is limited to what the control scores.
5. Open and closed ports and the service banners satisfy A1 to A3, so that the stack and the services tell one story.
6. Results are identical in kind across the three runs. A top match that flips between runs fails.
7. The field diff, raw captures and commands are in the evidence folder, and every difference is explained or tracked in an issue.

One failed rule fails the persona. Passing is reported as "matches the measured control on these fields and these tool versions on this date", never as "undetectable".

## 6. Scoring sheet template (one per persona per run)

| Persona | Date and time (Melbourne) | Run (1, 2, 3, restart) | Probe host and tool versions | Control build and patch level |
|---------|---------------------------|------------------------|------------------------------|-------------------------------|
| | | | | |

| Field | Control value | Decoy value | Score (2, 1, 0, N) | Note or issue |
|-------|---------------|-------------|--------------------|---------------|
| F1 TTL | | | | |
| F2 DF | | | | |
| F3 Options and order | | | | |
| F4 Window | | | | |
| F5 SEQ | | | | |
| F6 ACK number | | | | |
| F7 Flags | | | | |
| F8 IP ID | | | | |
| F9 Timestamps | | | | |
| F10 Closed TCP | | | | |
| F11 Closed UDP | | | | |
| F12 ICMP echo | | | | |
| F13 ECN | | | | |
| F14 Timing | | | | |
| F15 Fragments | | | | |
| F16 Other | | | | |

| Tool check | Control result | Decoy result | Same? |
|------------|----------------|--------------|-------|
| nmap top match and score | | | |
| p0f label (pcap) | | | |
| p0f label (live) | | | |

Persona verdict: pass or fail, with the failing rule numbers.

## 7. Persona order and constraints

Order set by Jarvis: Windows Server 2022, Ubuntu 24.04, Windows Server 2019, Windows Server 2025, Windows 11, then optional Rocky 9 and FreeBSD 14.

- Captures from UTM-emulated VMs are drafts. Timing and timestamp fields (F5, F8, F9, F14) from emulated hosts do not count toward a pass.
- Windows 11 ARM and Linux ARM controls run a different CPU architecture from the sensor. Report the difference. Do not use an ARM control for F9 and F14 without saying so.
- Decoy probes: only `192.168.1.240/29`, only after Daniel approves a test, each command posted as run. Control probes: only the lab network.
- No third-party fingerprint database content is imported or shipped. Personalities come from our own run files.

## 8. Decisions recorded (Jarvis, 25 Oct 2026)

1. "Top match and p0f agree" means the same label and the same Gate field values as the real VM. Winning a newer name that the tool databases lack is not required, and no persona claims a name the real VM does not get.
2. Lab probe host is `pm-probe` (Ubuntu, root). For the real decoy range on the LAN, a small Linux probe VM image with the same fixed scripts is used. The Windows VM never runs raw scans.
3. Three runs plus one post-restart run, 10 minutes apart, are accepted.

## 9. Azure sensor VM caveat

Azure gives every secondary IP on a NIC the same MAC address, and its virtual switch may alter some stack fields. So the Azure sensor VM validates stack fields (F1 to F16) over the same path as the real targets, but it cannot test per-persona MAC identity (C1 and C2 in the acceptance criteria). Those checks stay on the real `192.168.1.240/29` range after the owner approves a test.
