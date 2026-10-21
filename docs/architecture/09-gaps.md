# 09 – Gaps: what Honeyd does not do

This page lists what Honeyd is missing as a system. It's in two parts:

- **Proven in code:** each item cites the file, line or search that proves it. The proof is that the feature is absent or deliberately refused.
- **Needs a live test:** questions that reading the code can't settle.

All references are to `master` @ `a0f3d64`, the default branch. Other branches differ: `bcastNameFix` differs from `master` in 39 files.

## Proven in code

| # | Gap | Evidence | Why it matters |
|---|---|---|---|
| 1 | **No IPv6.** Fake hosts only exist on IPv4. | Protocol dispatch handles only `IP_PROTO_TCP`, `IP_PROTO_UDP` and `IP_PROTO_ICMP` over IPv4 (honeyd.c:3049–3056); the template protocol lookup is the same three only (honeyd.c:1263–1267). Capture diverts only ARP (`honeyd_recv_cb`, honeyd.c:3373). No IPv6 header is parsed anywhere. The one IPv6 reference in the subsystem library refuses IPv6 sockets with `EPROTONOSUPPORT` (honeyd_overload.c:430–434). The `ipv6` branch is an unmerged DataSoft attempt last touched January 2013. | Attackers scanning or moving over IPv6 never see the decoys. |
| 2 | **OS fingerprints stop at 2012.** | `nmap-os-db` header: `$Id: nmap-os-db 28604 2012-05-17`. 3,572 fingerprints. The newest Windows is 7 and the newest Linux is 3.1. There are no Windows 8, 10, 11 or Server 2012+ entries (search of the file). | Decoys can only imitate old systems, which current scanners and attackers will find out of place. |
| 3 | **No structured log output.** | No C file mentions JSON (search). Logs are plain text lines written by `log.c` (for example `fprintf(logfp, …)` log.c:235), plus about 390 `syslog()` calls and the custom stats feed. | Getting events into Sentinel or another SIEM needs a parser or a new output module. |
| 4 | **No alerting.** | No webhook, HTTP client or email notification code in the daemon (search for curl, webhook, sendmail). The only mail code is the optional SMTP decoy (subsystems/smtp.c). | Honeyd records a hit but never tells anyone. Someone or something must watch the logs. |
| 5 | **No isolation of services.** | No `chroot`, `seccomp`, `unshare` or `prctl` anywhere (search). Scripts are started with plain `execvp`/`execv` (command.c:432, 588). Honeyd only drops to `nobody` and applies per-template uid, gid and file limits (see [07](07-security-and-modernisation-notes.md)). | Scripts read attacker input. A flaw in one runs on the host itself. |
| 6 | **Control socket has no access control.** | The socket is bound with no `chmod`, `umask` or peer-credential check (ui.c:388). `ui_new()` accepts any connection (ui.c:311–316). Commands can add a port action that runs any command. | Anyone who can reach the socket can run code on the sensor. |
| 7 | **Python features are Python 2 only.** | `Py_InitModule` and `PyString_*` (pyextend.c:737, 800, 901) don't exist in Python 3. configure looks for `python2.4`. | The web UI, `internal` Python services and the Python scripts (including `smb-autofail.py` and `mssql.py`) can't be used on a current distribution without porting. |
| 8 | **No TLS.** | No OpenSSL or other TLS library is linked or called (search for `SSL_`, `openssl`). | Can't present a real HTTPS, RDP-with-TLS, LDAPS or any other encrypted service. |
| 9 | **No session or packet capture to disk.** | No `pcap_dump` (search). Recording of keystrokes or uploaded files exists only where an individual script writes its own log. | No reliable record of what an attacker typed or dropped, which tools like Cowrie provide. |
| 10 | **Decoy services are dated and shallow.** | 111 files under `scripts/`. SSH is `scripts/linux/ssh.sh`, 37 lines that print a version banner and log input, with no SSH protocol. Windows services are Windows 2000-era (`scripts/win32/`). SMB is a single Python 2 stub (`scripts/misc/smb-autofail.py`). There's no RDP, Modbus, S7 or other OT protocol. The backdoor emulators are for MyDoom and Kuang2. | Anyone who gets past the first banner quickly sees a fake. There's nothing to attract OT-focused attackers. |
| 11 | **No central configuration or health monitoring.** | Each sensor reads its own config file (`-f`) and has its own local control socket. `honeydstats` does collect signed statistics from several sensors over UDP (HMAC-SHA1, stats.c:101–135), so central *statistics* exist. Central config and health checks don't. | Running several sensors means configuring and checking each one by hand. |
| 12 | **No deception tokens.** | No code plants fake credentials, files or other lures. Honeyd only answers network traffic. | It can't catch an attacker who uses stolen material, only one who scans. |

## Needs a live test (not provable from code)

| Question | How to settle it |
|---|---|
| Can modern `nmap -O` or an attacker tell the decoys are fake? | Run Honeyd in an isolated container network and scan it with current nmap. |
| How convincing is each service script past its banner? | Interact with each enabled service manually. |
| Are the packet parsers exploitable beyond the known `determine_path()` overflow? | Fuzz the receive path (`honeyd_recv_cb` → `honeyd_input`) with AFL or libFuzzer under ASan. See [07](07-security-and-modernisation-notes.md). |
| Do the Python 2 scripts run at all on the target host? | Only if Python 2 is installed. Test, or port them to Python 3. |

## Suggested priority (recommendation, not fact)

1. **Make it safe to run:** fix the known defects and the control socket (items 5 and 6), and run it in a container.
2. **Make it visible:** JSON output and an alert path into the SIEM (items 3 and 4).
3. **Make it believable:** refresh fingerprints and add modern and OT decoy services (items 2, 8 and 10). OT decoys suit customers running industrial, port and utility networks.
4. **IPv6** (item 1): review the unmerged `ipv6` branch before writing anything new.
