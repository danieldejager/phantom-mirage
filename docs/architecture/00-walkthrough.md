# 00 – How Phantom Mirage works in 10 minutes

This page is the plain-English version of the rest of this folder. It doesn't assume you read C. Every claim here comes from Forge's code-based pages (01 to 07) and `NOTES-for-writers.md`. Follow the links for the evidence and the file and line references (all are to `master` @ `a0f3d64`). Words in *italics* are defined in the [glossary](08-glossary.md).

## 1. The one-sentence version

Phantom Mirage is one program that pretends to be a whole network of computers. It answers network traffic sent to IP addresses nobody really uses, and makes each fake address look like a real machine with its own operating system, open ports, services, network delay and position behind routers.

Anything that talks to those addresses is suspicious by definition, because no real user or system has a reason to. That makes Phantom Mirage a *honeypot*: a decoy that gives you early warning of scanning, worms and attackers moving around inside a network.

## 2. The cast

| Part | What it is | In plain words |
|---|---|---|
| `phantom-mirage` | The main program (the *daemon*) | Does all the pretending. One process, one *event loop*, no threads. |
| Config file | Text file passed with `-f` | Describes the fake network: which hosts exist, what they look like, what they run. |
| `phantom-mirage-ctl` | Small command-line tool | Lets an operator change the fake network while it runs, using the same language as the config file. |
| Fingerprint files | `nmap-os-db`, `xprobe2.conf`, `nmap.assoc`, `pf.os`, `nmap-mac-prefixes` | Reference data describing how real operating systems and network cards behave, so Phantom Mirage can imitate them. |
| Service scripts | `scripts/` folder | Small shell or Perl programs that act out a service (a web server, a login prompt) for each connection. |
| *Subsystems* | Real server programs plus `libphantom-mirage.so` | Lets an actual program (for example an SMTP server) run "inside" a fake host. |
| `phantom-mirage-stats` | Separate program | Collects statistics that `phantom-mirage` sends it. Optional. |
| Logs | `-l` packet log, `-s` service log, syslog | The record of who touched what. This is the security value. |

Diagram: [01-system-context.md](01-system-context.md).

## 3. Getting traffic to Phantom Mirage

Phantom Mirage can only fake what it can see. The network has to deliver packets for the unused addresses to the Phantom Mirage machine. There are three ways:

1. A router sends that address range to the Phantom Mirage box.
2. A helper such as `arpd` claims the addresses on the local network.
3. Phantom Mirage answers *ARP* itself for fake hosts that have been given a network card address (`set <host> ethernet "dell"`).

This setup happens outside the code, and it's the first thing to get right in any deployment.

## 4. Startup: what happens when you run it

In order (details in `NOTES-for-writers.md`, "Startup order"):

1. **Prepare the plumbing.** Create the event loop, memory pools, plugin hooks and ARP handling.
2. **Load the reference data.** Read the operating-system and network-card fingerprint files.
3. **Open the network.** Start capturing packets on each `-i` interface (*libpcap*) and open a raw socket for sending forged packets (*libdnet*).
4. **Read the config.** Parse the config file and build the fake network in memory (section 5).
5. **Open the control socket** `/run/phantom-mirage/phantom-mirage.sock` for `phantom-mirage-ctl`.
6. **Give up root.** Switch to the `nobody` user. The already-open capture and send handles keep working.
7. **Wait for packets** forever in the event loop.

Phantom Mirage needs root (or the Linux raw-network capabilities) only long enough to open the network. That matters for how you run it safely. See [07](07-security-and-modernisation-notes.md).

## 5. The config file builds the fake network

Phantom Mirage's config language is simple. Parsing it *is* building it: each line directly creates or changes something in memory, with no intermediate step. Full mapping in [05-configuration.md](05-configuration.md).

The key idea is the *template*. A template is a recipe for a kind of host. You then *bind* real IP addresses to it.

```
create windows                               # a new recipe called "windows"
set windows personality "ws2022-fwoff"       # which OS it imitates on the wire
add windows tcp port 80 "scripts/web.sh"     # port 80 runs a fake web server script
add windows udp port 53 open                 # port 53 accepts traffic, no service
set windows default tcp action closed        # every other TCP port refuses
set windows ethernet "dell"                  # pretend to have a Dell network card
bind 10.3.0.20 windows                       # 10.3.0.20 is now one of these
```

Other things the config can describe:
- **Routers and links** with delay, packet loss and bandwidth, so `traceroute` shows a believable path (`route ...`).
- **Dynamic templates** that change what they look like depending on who is asking or when (`dynamic`, `add ... use ... if`).
- **Proxying** a port to a real machine instead of faking it (`proxy <ip>:<port>`).
- **Tarpits** that slow attackers down on purpose.
- **Hosts that get their address from DHCP** like a real device would.
- **Periodic broadcast traffic**, so fake hosts look alive (an addition by DataSoft/Nova, not in the original Honeyd).

What each port can do when traffic arrives:

| Action | What the attacker sees |
|---|---|
| A script path | A working-looking service, driven by the script |
| `open` | The port accepts the connection but nothing answers |
| `closed` / `reset` | The port refuses (TCP reset, or "port unreachable" for UDP) |
| `filtered` / `block` | Nothing at all; the packet is silently dropped |
| `proxy` | A real service on another machine, relayed through Phantom Mirage |
| `internal` | A service written in Python (only if built with Python, which needs Python 2) |

## 6. Life of a packet

This is the heart of Phantom Mirage. Sequence diagrams for each case are in [04-packet-flow.md](04-packet-flow.md).

**Arriving:**
1. **Capture.** libpcap hands Phantom Mirage a raw packet. ARP and DHCP replies go to their own handlers. Everything else goes on.
2. **Which fake host?** Phantom Mirage looks up the destination IP and finds the template bound to it. This happens for every packet. If that template is dynamic, Phantom Mirage checks its conditions, such as the attacker's guessed OS or the time of day, and swaps in the matching template (`template_dynamic()` in config.c). The same address can therefore look different depending on what Phantom Mirage has learned about the sender.
3. **Simulate the network path.** If routers are configured, Phantom Mirage walks the packet hop by hop through the fake topology. It adds up delay, applies packet loss and counts down the *TTL*. If the TTL runs out, it sends back a "time exceeded" message from the fake router's address, just as a real router would. That's how `traceroute` works against it.
4. **Wait.** Phantom Mirage sets a timer for the total delay rather than replying instantly, so timings look real.
5. **Hand to the protocol.** TCP, UDP and ICMP (ping) each have a handler. Other protocols are only logged.
6. **Look up the port** on the template and apply its action from the table above. For a script, Phantom Mirage starts a new copy of the script for this connection. Attacker data goes to the script's input and the script's output becomes the reply. Connection details reach the script as `PHANTOM_MIRAGE_*` environment variables, including Phantom Mirage's guess at the attacker's operating system.

**Replying:**
1. **Dress it up.** Before a reply leaves, Phantom Mirage adjusts low-level fields (window size, TCP options order, IP ID pattern, sequence numbers, whether "don't fragment" is set) to match the template's *personality*. This is what fools OS-detection tools such as `nmap -O`.
2. **Walk back through the fake routers**, adding delay again on the way out.
3. **Send** the forged packet with libdnet, either as raw IP or as a full Ethernet frame with the fake network card address.

## 7. Two kinds of fingerprinting

Phantom Mirage uses fingerprints in both directions, and the two are easy to confuse:

- **Active, outgoing: lying about itself.** It shapes its replies to match an nmap or xprobe2 fingerprint, so scanners report the configured OS. This is the template's *personality*.
- **Passive, incoming: reading the attacker.** It compares incoming packets against `pf.os` to guess the attacker's OS. Scripts receive this guess, and dynamic templates can change behaviour based on it (for example, "if the source OS is Windows, look like a Windows server").

## 8. Extending Phantom Mirage

- **Scripts:** the easy way to fake a service. One process per connection.
- **Subsystems:** run a real program. `libphantom-mirage.so` intercepts its network calls (*LD_PRELOAD*) so it thinks it owns the fake host's address.
- **Proxy:** pass the connection to a real machine.
- **Plugins and hooks:** compiled add-ons loaded at startup that can see every packet.
- **Python:** embedded services and a web UI. This needs Python 2, which modern systems no longer ship.

## 9. Changing things while it runs

`phantom-mirage-ctl` connects to `/run/phantom-mirage/phantom-mirage.sock` and accepts the same statements as the config file. You can add hosts, change ports and list templates live.

**This is also the biggest operational risk.** Anyone who can connect to that socket can tell Phantom Mirage to run any command when a connection arrives, so access to the socket amounts to code execution on the box. Lock it down. See section 11.

## 10. Building it today

The code is from 2002 to 2007, with later DataSoft/Nova additions. Version string: 1.7.0 (set in `configure.ac` `AC_INIT`; 1.6d before 1.7.0). It does build and run on current Linux (tested on Debian 13 with GCC 14), Until [PR #44](https://github.com/danieldejager/honeyd/pull/44) is merged it needs two compiler workarounds (`-fpermissive` and `-fcommon`) and a non-parallel `make`; after it, a plain `./configure && make -j` works. The Python features don't build at all on a modern distribution. Details and the working recipe are in [06-build-and-dependencies.md](06-build-and-dependencies.md).

## 11. What to worry about

From [07](07-security-and-modernisation-notes.md). That page separates verified facts from recommendations.

- **It's old C facing attackers.** Every packet parser is reachable by whoever sends traffic. Nobody has fuzzed or audited it here.
- **Control socket = code execution.** Restrict it to root, with mode 0600 or a root-owned directory.
- **Three concrete defects found:**
  1. A heap overflow in `determine_path()`. It's local only, triggered by relative paths on the command line.
  2. Config folders are created world-writable.
  3. The control socket issue above.
- **Scripts get attacker input** and haven't been reviewed. They're the most likely spot for command injection.
- **No sandboxing** in the code itself. The recommendation is to run it in a container with only the raw-network capabilities and a dedicated network. A draft Dockerfile and run settings are in 07.

## 12. Where to go next

| If you want to... | Read |
|---|---|
| See the big picture as a diagram | [01-system-context.md](01-system-context.md) |
| Understand which source file does what | [02-components.md](02-components.md) |
| See how hosts, ports, routers and connections relate | [03-data-model.md](03-data-model.md) (ER diagrams) |
| Follow a packet step by step | [04-packet-flow.md](04-packet-flow.md) |
| Write or read a config file | [05-configuration.md](05-configuration.md) |
| Build it | [06-build-and-dependencies.md](06-build-and-dependencies.md) |
| Decide how to run it safely | [07-security-and-modernisation-notes.md](07-security-and-modernisation-notes.md) |
| Look up a term | [08-glossary.md](08-glossary.md) |
| See what is missing | [09-gaps.md](09-gaps.md) |
