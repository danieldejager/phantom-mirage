# Decoy ports: tripwire or banners (#129)

On a fresh Debian install every decoy uses the `default` template from
`debian/mkconf.sh`: ICMP echo answered, TCP 21, 22, 23, 80, 443, 445 and
3389 open, every other TCP port refused (RST). What the open ports do is
chosen at build time with `PM_DECOY` (default `tripwire`), and can be
switched per port in `/etc/phantom-mirage/phantom-mirage.conf`: each of
21/22/23/80 has two lines there, one commented; swap which one is
commented and restart.

| | `tripwire` (default) | `banners` |
|---|---|---|
| What an attacker sees | Ports accept the connection and say nothing | 21/22/23/80 greet like one Debian 12 host (below); 443/445/3389 silent |
| `nmap -sV` | every port `?` (unrecognised) | ftp vsftpd 3.0.3, ssh OpenSSH 9.2p1 Debian, telnet, http Apache 2.4.62 (Debian); 443/445/3389 `?` |
| Strengths | Nothing runs per connection; simplest; any connect is a detection | More believable lure; survives a casual `-sV` sweep |
| Risks | Decoys are fingerprintable as decoys | One sandboxed shell script per connection (more attack surface, CPU per connect); banner versions age and need updating; a mismatched or stale banner is itself a fingerprint |

Banners (`scripts/mirage/banner.sh`, shell builtins only, no files, no
network; runs under `--sandbox-scripts`):

* 21: `220 (vsFTPd 3.0.3)`; `USER` gets 331, `PASS` gets `530 Login incorrect.`
* 22: `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`, then closes after the client ident (no key exchange)
* 23: telnet option negotiation, `Debian GNU/Linux 12`, `login:`/`Password:`, always `Login incorrect` (3 tries)
* 80: `HTTP/1.1 200 OK`, `Server: Apache/2.4.62 (Debian)`, the Apache "It works!" page

443, 445 and 3389 stay silent tripwires in both modes: a believable
answer needs a real TLS, SMB or RDP implementation, which a static
script cannot give. Nothing sent to any port is executed or stored.
