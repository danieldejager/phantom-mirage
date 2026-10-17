# 04 – Packet flows

All flows start in libevent: the pcap fd becomes readable, `interface_recv` (interface.c) calls `pcap_dispatch`, which calls `honeyd_recv_cb()` (honeyd.c:3373). Everything is single-threaded; "async" below means a libevent callback later in the same loop.

## 4.1 TCP SYN to a scripted service

```mermaid
sequenceDiagram
    autonumber
    participant A as Attacker
    participant P as libpcap / interface.c
    participant R as honeyd_recv_cb / honeyd_input
    participant D as honeyd_delay_packet / honeyd_dispatch
    participant T as tcp_recv_cb
    participant PE as personality.c
    participant C as generic_connect / cmd_fork (command.c)
    participant S as Script (child process)
    participant O as honeyd_ip_send / libdnet ip_send

    A->>P: SYN to 10.0.0.5:80
    P->>R: frame
    R->>R: template_find_best("10.0.0.5")
    R->>D: honeyd_delay_packet(delay=0)
    D->>T: honeyd_dispatch -> tcp_recv_cb
    T->>T: hooks_dispatch(HD_INCOMING), honeyd_port(tmpl,TCP,80)
    alt port open
        T->>T: tcp_new() add to tcpcons
        T->>PE: tcp_send(SYN|ACK) -> tcp_personality(), ip_personality()
        PE-->>O: window, DF, TTL, IP ID, options, ISN
        O->>A: SYN/ACK
        A->>P: ACK (handshake complete)
        P->>T: (same path)
        T->>C: generic_connect(tmpl, conhdr, cmd, con)
        C->>S: socketpair + fork/exec script, HONEYD_* env, drop to template uid/gid
        A->>T: payload
        T->>S: write to cmd.pfd (cmd_trigger_write)
        S-->>C: stdout data (libevent read cb)
        C->>T: tcp_senddata(ACK)
        T->>O: data segments
        O->>A: response
    else port closed / no template
        T->>O: RST|ACK (shaped by personality)
    else filtered
        T-->>T: drop silently
    end
    T->>T: honeyd_log_flownew / honeyd_log_probe (log.c)
```

Notes: `generic_connect()` (honeyd.c:1416) is also where `proxy` (`proxy_connect`), `subsystem` (`cmd_subsystem_schedule_connect`) and `PORT_PYTHON` (`cmd_python`) are chosen. The tarpit flag (`PORT_TARPIT`) sets `TCP_TARPIT` on the connection (honeyd.c:2219), which advertises a window of 5 bytes and sends at most 1 byte per segment (honeyd.c:1567, 1670).

## 4.2 UDP

```mermaid
sequenceDiagram
    autonumber
    participant A as Attacker
    participant R as honeyd_input
    participant U as udp_recv_cb / handle_udp_packet
    participant C as generic_connect
    participant S as Script
    participant I as icmp_error_send

    A->>R: UDP to 10.0.0.5:53
    R->>U: (template lookup, delay, dispatch)
    U->>U: honeyd_port(tmpl, UDP, 53)
    alt open
        U->>U: find or udp_new() in udpcons
        U->>C: generic_connect (first packet)
        C->>S: fork script with SOCK_DGRAM socketpair
        U->>S: datagram (queued in conbuffer, max 10)
        S-->>U: reply -> udp_send()
        U->>A: UDP reply
    else closed
        U->>I: ICMP port unreachable (honeyd.c ~2716)
        I->>A: shaped by icmp_error_personality()
    else filtered
        U-->>U: drop
    end
```

## 4.3 ICMP

```mermaid
sequenceDiagram
    participant A as Attacker
    participant I as icmp_recv_cb
    participant X as xprobe / nmap personality
    participant O as icmp_echo_reply etc.

    A->>I: ICMP echo / timestamp / mask / info
    I->>I: if tmpl->icmp.status is FILTERED or CLOSED, drop
    alt ICMP_ECHO
        I->>X: look up nmap IE test, else xprobe fingerprint
        X-->>I: code, TTL, DF, whether to answer
        I->>O: icmp_echo_reply(tmpl, ip, code, ttl, ...)
    else ICMP_TSTAMP / ICMP_MASK / ICMP_INFO
        I->>O: icmp_timestamp_reply / icmp_mask_reply / icmp_info_reply (xprobe-driven)
    end
    O->>A: reply via honeyd_ip_send
```

## 4.4 OS fingerprint spoofing (nmap probes)

```mermaid
sequenceDiagram
    participant N as nmap -O
    participant T as tcp_recv_cb
    participant P as tcp_personality (personality.c:743)
    participant IP as ip_personality (personality.c:207)
    participant O as honeyd_ip_send

    N->>T: probe (e.g. T2: no flags, DF, to open port)
    T->>P: tcp_personality(con, &flags, &window, &df, &id, &options)
    P->>P: tcp_personality_test() classifies probe -> t_tests[i] / seq_tests[i] / ecn_test
    P-->>T: response yes/no, flags, window, DF, TTL, TCP options order
    T->>IP: ip_personality(tmpl, &id, TCP)
    IP-->>T: IP ID per IPID_type_TI/CI/II (sequential, random, zero, constant ...)
    T->>T: ISN from TCP_ISR / TCP_ISN_gcd / TCP_SP and template time drift
    T->>O: crafted reply (or none)
    O->>N: reply that matches the configured nmap fingerprint
```

Inbound packets are also matched against the passive PF fingerprints (`honeyd_osfp_init`, osfp.c / pf_osfp.c) so the *attacker's* OS is known; this feeds `HONEYD_REMOTE_OS` (command.c:236) and `source os =` conditions for dynamic templates (condition.c).

## 4.5 Routing topology simulation

```mermaid
sequenceDiagram
    participant A as Attacker
    participant In as honeyd_input
    participant RT as honeyd_route_packet
    participant RO as router.c (router_find_nexthop, link_entry)
    participant DL as honeyd_delay_packet / honeyd_delay_cb
    participant H as honeyd_dispatch

    A->>In: packet to 10.1.2.3 (traceroute TTL=2)
    In->>In: optional GRE decapsulation (router_find_tunnel, gre_decapsulate)
    In->>RO: network_lookup(entry_routers, dst)
    In->>RT: honeyd_route_packet(ip, gw, dst, &delay)
    loop each hop while ip_ttl > 0
        RT->>RO: next hop entry
        RO-->>RT: link latency, loss, bandwidth, RED thresholds
        RT->>RT: delay += latency, decrement TTL, maybe RED drop
    end
    alt TTL expired
        RT->>A: ICMP time exceeded from router address
    else route type UNREACH
        RT->>A: ICMP unreachable from router
    else route type TUNNEL
        RT->>DL: DELAY_TUNNEL (GRE out)
    else reached
        RT->>RT: random drop by cumulative loss
        RT-->>In: FW_INTERNAL or FW_EXTERNAL
        In->>DL: honeyd_delay_packet(delay ms)
        DL-->>H: after timer: honeyd_dispatch (or send on ethernet for external hosts)
    end
```

Replies traverse the topology in reverse inside `honeyd_ip_send()` (honeyd.c:961), which uses the `reverse` network tree to find the source router, so latency is applied in both directions.
