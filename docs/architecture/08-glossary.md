# 08 – Glossary

Plain-English definitions for terms used in this folder. Where a term maps to code, the struct, file or keyword is given in `code` style.

| Term | Meaning |
|---|---|
| **Action** | What a port does when traffic arrives: run a script, `open`, `closed`/`reset`, `filtered`/`block`, `proxy`, `internal` (Python), optionally wrapped in `tarpit`. Code: `struct action`, `enum status` (honeyd.h). |
| **ARP** | Address Resolution Protocol. How machines on a local network find which network card owns an IP address. Honeyd can answer ARP for fake hosts given an Ethernet address (arp.c). |
| **arpd** | A separate tool (not in this repo) that claims unused addresses on a LAN so their traffic reaches Honeyd. |
| **Autotools** | The old GNU build system (`autogen.sh`, `configure`, `make`) Honeyd uses. See [06](06-build-and-dependencies.md). |
| **Bind** | Attach a real IP address to a template, which creates a fake host. Config keyword `bind`. Code: `template_clone()`. |
| **Broadcast script** | A DataSoft/Nova addition that makes a fake host periodically send broadcast UDP so it looks alive. Config keyword `broadcast`. |
| **C4 diagram** | A common way to draw software architecture at levels: context (the system and its users), containers (programs and data stores), components (modules inside). Used in [01](01-system-context.md) and [02](02-components.md). |
| **Control socket** | `/var/run/honeyd.sock`, the local channel `honeydctl` uses to send commands to the running daemon. Access to it amounts to code execution. |
| **Daemon** | A program that runs in the background as a service. `honeyd` is the daemon. |
| **DataSoft / Nova** | The group whose fork of Honeyd this code is based on. They added the newer nmap fingerprint parser, broadcast scripts, DHCP-assigned hosts and some environment variables. |
| **DHCP** | How devices get an IP address automatically. Honeyd can make a fake host request its address via DHCP (`dhcp` keyword, dhcpclient.c). |
| **Dynamic template** | A template that picks one of several other templates per packet, based on conditions such as the attacker's OS, source IP or time of day. Code: `struct condition` (condition.h). |
| **ER diagram** | Entity-relationship diagram. Shows the kinds of thing in a system and how they relate (one host has many ports, and so on). Used in [03](03-data-model.md). |
| **Event loop** | The single loop at the heart of Honeyd that waits for packets and timers and runs the matching handler. Provided by *libevent*. Honeyd has no threads. |
| **Fingerprint (OS)** | The small, characteristic ways an operating system's network stack behaves. Tools like nmap use them to guess a machine's OS, and Honeyd imitates them. |
| **Forged / crafted packet** | A packet Honeyd builds by hand, with every field chosen to match the fake host, rather than letting the real OS build it. |
| **GRE** | Generic Routing Encapsulation, a way to tunnel packets inside other packets. Honeyd can receive and send traffic for remote networks over GRE (gre.c). |
| **Hook** | A point in Honeyd's packet handling where plugins are called so they can see packets (hooks.c). |
| **Honeynet** | A network of honeypots. Honeyd simulates one from a single machine. |
| **Honeypot** | A decoy system with no legitimate users. Any interaction with it is suspicious, which makes it a useful early-warning sensor. |
| **honeydctl** | The command-line tool for changing the running daemon. It uses the same language as the config file. |
| **honeydstats** | A separate optional program that collects signed statistics sent by Honeyd over UDP. |
| **ICMP** | The network control protocol behind `ping`, "port unreachable" and "time exceeded" messages. |
| **IP ID** | A number in every IP packet. Different operating systems generate it in different patterns (sequential, random, zero), which nmap uses to fingerprint them. Honeyd mimics the pattern. |
| **ISN** | Initial Sequence Number, the starting counter of a TCP connection. Its predictability is part of an OS fingerprint. |
| **LD_PRELOAD** | A Linux mechanism to load a library before a program starts, so the library can intercept the program's calls. `libhoneyd.so` uses it to run real servers as *subsystems*. |
| **libdnet / libdumbnet** | Library Honeyd uses to send raw IP packets and Ethernet frames. Debian calls it libdumbnet. |
| **libevent** | Library providing Honeyd's event loop and timers. |
| **libpcap** | Library Honeyd uses to capture packets from the network interface. Same library as tcpdump and Wireshark. |
| **Mermaid** | Text-based diagram format that GitHub draws directly in the page. All diagrams in this folder use it. |
| **nmap / xprobe2** | Network scanners that guess a machine's OS by probing it. Honeyd's fingerprint files come from their databases, so their probes get convincing answers. |
| **Passive fingerprinting** | Guessing the *attacker's* OS just by looking at their packets, using `pf.os` (osfp.c, pf_osfp.c). The guess is passed to scripts as `HONEYD_REMOTE_OS`. |
| **Personality** | The OS a template imitates on the wire, chosen from the nmap fingerprint database. Config: `set <t> personality "<name>"`. Code: `struct personality` (personality.h). |
| **Plugin** | A compiled add-on loaded into Honeyd at startup (plugins.c). Configured with the `option` keyword. |
| **Port** | A numbered endpoint for TCP or UDP on a host (80 for web, 53 for DNS). Each template lists ports and their actions. Code: `struct port`. |
| **Proxy (action)** | Relay a connection on a fake host to a real machine, so the attacker talks to a real service. |
| **RED** | Random Early Detection, a way routers drop packets as links get busy. Honeyd can simulate it on fake links (`drop between`). |
| **Route / router (simulated)** | Fake routers and links defined with `route ...`, with delay, loss and bandwidth, so traceroute and timing look like a real network. Code: `struct router`, `struct router_entry`, `struct link_entry` (router.h). |
| **Script (service script)** | A small program (shell, Perl and so on) started for each connection to act out a service. It reads attacker data on input and writes replies on output (`scripts/`, `cmd_fork` in command.c). |
| **Socketpair** | A connected pair of local sockets. Honeyd uses one to wire each script's input and output to the fake connection. |
| **Subsystem** | A real server program run inside a fake host, with its networking redirected through Honeyd by `libhoneyd.so`. Config: `add <t> subsystem "<cmd>"`. Code: `struct subsystem`. |
| **Tarpit** | An action that slows a connection to a crawl (tiny window, one byte at a time) to waste an attacker's or worm's time. |
| **TCP / UDP** | The two main transport protocols. TCP sets up connections with a handshake; UDP sends single messages. |
| **Template** | The core idea in Honeyd: a recipe for a kind of host (personality, ports, actions, network card, uptime, user ID). Bind IPs to it to create fake hosts. Code: `struct template` (template.h), stored in `templtree`, managed in config.c. |
| **TTL** | Time To Live, a hop counter in every IP packet that each router decreases by one. When it reaches zero the router sends back "time exceeded". Honeyd simulates this for traceroute. |
| **Uptime** | How long a fake host claims to have been running. Affects TCP timestamp values. Config: `set <t> uptime N`. |
| **Virtual host** | One fake machine (an IP bound to a template). |
| **yacc / flex (parse.y, lex.l)** | Tools that generate the config-file parser. In Honeyd, parsing a statement immediately builds or changes the in-memory structures. |
