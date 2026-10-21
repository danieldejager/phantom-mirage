# 01 – System context and containers

Honeyd is a single C daemon that pretends to be many hosts. It listens on a real network interface with libpcap, decides which *virtual host* (a "template") a packet is addressed to, and writes back forged replies with libdnet so that scanners see the operating system, open ports and network topology described in a configuration file. All code references are to `master` @ `a0f3d64`.

## System context (C4 level 1)

```mermaid
flowchart LR
    attacker["Attacker / scanner<br/>(nmap, xprobe2, worms)"]
    operator["Operator / analyst"]
    honeyd["Honeyd system<br/>virtual honeynet daemon"]
    lan["Real network segment<br/>(unused IP space routed or ARP-claimed to Honeyd)"]
    real["Real hosts / upstream servers<br/>(proxy targets, external routers)"]
    syslog["syslog / log files"]
    collector["honeydstats collector"]

    attacker -- "IP packets to unused addresses" --> lan
    lan -- "captured frames (libpcap)" --> honeyd
    honeyd -- "forged replies (libdnet ip/eth)" --> lan
    honeyd -- "proxied connections" --> real
    operator -- "config file, honeydctl" --> honeyd
    honeyd -- "connection & packet logs" --> syslog
    honeyd -- "signed, tagged stats over UDP" --> collector
```

How traffic reaches Honeyd is outside the code: either the router sends the unused address range to the Honeyd box, a tool like `arpd` answers ARP for it, or Honeyd itself answers ARP for templates that have an Ethernet address (`set <t> ethernet "<vendor>"`, `arp.c`).

## Containers (C4 level 2)

```mermaid
flowchart TB
    subgraph host["Honeyd host (Linux/BSD, root at start)"]
        honeyd["honeyd daemon<br/>honeyd.c main()"]
        honeydctl["honeydctl CLI<br/>honeydctl.c"]
        uisock[("/var/run/honeyd/honeyd.sock<br/>ui.h UI_FIFO")]
        cfg[("config file<br/>-f, parse.y / lex.l")]
        fp[("fingerprint DBs<br/>nmap-os-db, xprobe2.conf,<br/>nmap.assoc, pf.os, nmap-mac-prefixes")]
        scripts["service scripts<br/>scripts/ (sh, perl, ...)<br/>forked per connection"]
        subsys["subsystems<br/>real daemons run with libhoneyd.so<br/>(LD_PRELOAD, honeyd_overload.c)"]
        py["embedded Python services &<br/>web UI (optional, pyextend.c, webserver/)"]
        plugins["plugins (dlopen,<br/>plugins.c, hooks.c)"]
        logs[("packet log -l / service log -s<br/>log.c")]
        pid[("/var/run/honeyd.pid")]
    end
    stats["honeydstats<br/>honeydstats_main.c"]
    net(("network interface(s)<br/>libpcap in, libdnet out"))

    honeydctl --> uisock --> honeyd
    cfg --> honeyd
    fp --> honeyd
    honeyd -- "fork/exec, socketpair stdin/stdout" --> scripts
    honeyd -- "fd passing over Unix socket" --> subsys
    honeyd --> py
    honeyd --> plugins
    honeyd --> logs
    honeyd --> pid
    honeyd -- "UDP stats (stats.c)" --> stats
    net <--> honeyd
```

| Container | Source | Notes |
|---|---|---|
| `honeyd` | honeyd.c and most other `.c` files (`honeyd_SOURCES` in Makefile.am) | Single-threaded libevent loop (`event_base_dispatch`, honeyd.c ~3990). |
| `honeydctl` | honeydctl.c | Connects to `UI_FIFO` (`/var/run/honeyd/honeyd.sock`, ui.h:54); commands are parsed by the same grammar as the config file (`ui` rule, parse.y:925), so templates can be changed live. |
| `honeydstats` | honeydstats_main.c, honeydstats.c, analyze.c, filter.c, keycount.c | Separate process that aggregates stats reports sent by `stats.c` (enabled with honeyd's stats options). |
| `hsniff` | hsniff.c | Stand-alone sniffer tool; not part of the honeypot path. |
| Fingerprint DBs | nmap-os-db, xprobe2.conf, nmap.assoc, pf.os, nmap-mac-prefixes | Loaded at startup in `main()`; paths overridable with `-p`, `-x`, `-a`, `-0`, `-m`. |
| Scripts | scripts/ | Emulated services; get connection details in `HONEYD_*` env vars (command.c:226–259). |
| Subsystems | subsystems/ (smtp, proxy), honeyd_overload.c | Real programs whose socket calls are intercepted by `libhoneyd.so`. |
