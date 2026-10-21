# 07 – Security and modernisation notes

This page separates **Facts** (verified in the code or in the build run on 2026-10-17) from **Recommendations** (opinion, to be decided). Code refs are to `master` @ `a0f3d64`.

## Facts

### Age and maintenance
- Code base is Niels Provos' Honeyd 1.5/1.6 (copyright 2002–2007) plus DataSoft/Nova additions (nmap 2nd-gen fingerprint parser in personality.c, broadcast scripts `bcast_insert`/`bcast_trigger` config.c:539–600, DHCP-assigned templates, `HONEYD_TEMPLATE_NAME`/`HONEYD_INTERFACE` env vars command.c:249–253, `~/.config/honeyd` handling honeyd.c :550–585). Version string: 1.6d.
- Build needs `-fpermissive -fcommon` on GCC 14 (see [06](06-build-and-dependencies.md)). Python support targets Python 2 (`Py_InitModule`, pyextend.c:800; configure looks for `python2.4`). debian/control depends on `python-support` and `libpcre3-dev`, both gone from current Debian.

### Privileges
- Needs raw packet access: libpcap capture (`pcap_open_live`, interface.c:369) and libdnet raw IP / Ethernet send (`ip_open` honeyd.c, `eth_open`). On Linux that means root or `CAP_NET_RAW` + `CAP_NET_ADMIN` (promiscuous mode).
- Writes `/var/run/honeyd.pid` and creates `/var/run/honeyd/honeyd.sock` (ui.h:54) before dropping privileges.
- Drops to `nobody` (default uid/gid 32767, looked up via `getpwnam("nobody")`, honeyd.c:167, 479) with `cmd_droppriv()` (command.c ~291–330, which also verifies it cannot regain root) unless `honeyd_needsroot` is set. Opened pcap/dnet handles stay usable after the drop.
- Per-template `uid`/`gid` and `maxfds` (`setrlimit RLIMIT_NOFILE`, command.c:364) are applied to forked scripts.
- No chroot, seccomp, or namespace isolation in the code. Scripts run as ordinary processes on the host with full filesystem view.

### Attack surface
- **Every packet parser is attacker-reachable C**: Ethernet/ARP (arp.c), IP/fragment reassembly (ipfrag.c), GRE decapsulation (gre.c), TCP/UDP/ICMP handlers (honeyd.c), DHCP replies (dhcpclient.c), passive fingerprinting (pf_osfp.c). `honeyd_recv_cb` (honeyd.c:3373) does basic length checks on IP headers; deeper parsers were not audited for this document.
- **Service scripts** (scripts/, Perl/sh) receive attacker data on stdin. Their quality varies; they are the most likely place for command injection (not audited).
- **Control socket** `/var/run/honeyd/honeyd.sock` (privileged): any client can issue config commands, including `add <t> tcp port N "<command>"`, which makes Honeyd execute that command when a connection arrives (as the template's uid). Treat socket access as root-equivalent. Since #14, `ui_init()` creates the socket in a root-owned `/var/run/honeyd` directory (0700) with mode 0600. It refuses a directory that is a symlink or not owned by root, only ever replaces an existing *socket*, and checks `SO_PEERCRED` on every connection: only root (or honeyd's own uid) is accepted. To let a group use `honeydctl`, start honeyd with `HONEYD_UI_GROUP=<group>`. The directory then becomes 0750 and the socket 0660 with that group, and peers whose primary gid matches are accepted. Supplementary groups pass the file permissions but fail the peer check, so run `honeydctl` with that group as the primary gid (e.g. `sg <group> honeydctl`).
- **Proxy actions** let a honeypot open outbound connections to real hosts (`proxy_connect`, honeyd.c:1349).
- **Stats** are sent over UDP with an HMAC-SHA1 keyed by the configured password (stats.c:101–135); the password is given on the command line.
- **Embedded web server** (webserver/server.py, Python 2) is started by `pyextend_webserver_init` when built with Python.

### Concrete code defects spotted while reading
- `determine_path()` honeyd.c:1065: `malloc(strlen(abspath) + strlen(*input))` is two bytes short (missing "/" and NUL) and the second `malloc(strlen(buffer))` is one byte short; both are followed by `strcpy`/`strcat` → heap overflow. Reached from command-line options (honeyd.c:3666–3697), so local-only, but it corrupts the heap on every run that passes a relative path.
- `mkdir`/`chmod(full_path, S_IRWXU|S_IRWXO)` honeyd.c:560, 570, 581 create `~/.config` and `~/.config/honeyd` with world rwx and no group bits (probably meant `S_IRWXG`, inferred).
- Globals defined in headers (`libevent_base` honeyd.h, `personalities`/`xp_fprints` personality.h) – the cause of the `-fno-common` link failure.
- `struct port_encapsulate` comment in honeyd.h admits a use-after-free risk: "hope that the underlying data does not go away. XXX: that's a bug."
- 49 `XXX`/`TODO` markers in `*.c`.

## Recommendations

### Short term (get it running safely)
1. Fix the build properly instead of flags: add `#include <string.h>` to the configure test, move header globals to `extern` + one definition, rename `configure.in` → `configure.ac`, fix the `libhoneyd.so` rule for parallel make.
2. Fix `determine_path()` (use `asprintf`) and the `mkdir` mode.
3. Build without Python (default) unless the web UI is required; porting pyextend.c to Python 3 is a separate project.
4. Create the UI socket with mode 0600 (or put it in a root-owned directory) and document that access equals code execution.

### Dockerising
A container is a good fit because it bounds the blast radius of the C parsers and the scripts. What a Dockerfile would need (proposal):

```dockerfile
# Build stage
FROM debian:13-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool bison flex \
      libpcap-dev libevent-dev libdumbnet-dev zlib1g-dev libedit-dev
COPY . /src
WORKDIR /src
RUN ./autogen.sh && CC="gcc -fpermissive -fcommon" ./configure --prefix=/usr \
    && make && make install DESTDIR=/out

# Runtime stage
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpcap0.8 libevent-2.1-7 libdumbnet1 zlib1g libedit2 perl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /
COPY honeyd.conf /etc/honeyd/honeyd.conf
ENTRYPOINT ["/usr/bin/honeyd", "-d", "-f", "/etc/honeyd/honeyd.conf", "-i", "eth0"]
```

Runtime requirements and choices:
- `--cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN` (plus `SETUID`/`SETGID` so `cmd_droppriv` and per-template uids work). Avoid `--privileged`.
- Networking: Honeyd must see traffic for the honeynet range. Options: `--network host` (simplest, least isolated), or a **macvlan/ipvlan** network attached to the honeynet VLAN so the container owns a real L2 presence and can answer ARP for its templates (preferred, inferred from how `arp.c`/`set ethernet` work). Bridge networking with port publishing will not work, since Honeyd needs raw frames for many addresses.
- Run in foreground (`-d`) so Docker supervises it; log to stdout/syslog; mount a volume for `-l`/`-s` logs.
- Read-only root filesystem with tmpfs for `/var/run`; mount config and scripts read-only.
- Make sure `nobody` exists (it does in Debian images) or pass `-u/-g`.
- Consider `seccomp`/AppArmor profiles and a non-root user namespace; the scripts still run inside the container.

### Longer term
- Fuzz the packet path (`honeyd_recv_cb` → `honeyd_input`) with libFuzzer/AFL using pcap corpora; build with ASan/UBSan in CI.
- Replace or isolate script services (run in a separate sandbox container, talk over the existing socketpair model).
- Refresh `nmap-os-db` from current nmap and check the parser still handles the format.
- Decide whether to keep libdnet (lightly maintained; Debian ships it as libdumbnet) or move send paths to raw sockets / libpcap `pcap_inject`.
