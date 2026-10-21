# 03 – Data model (in-memory)

Phantom Mirage has no database. All state lives in C structs held in BSD `tree.h` splay trees (`SPLAY_HEAD`) and `queue.h` lists (`TAILQ_HEAD`) from `compat/sys/tree.h`. The diagrams below use Mermaid ER notation; "PK" marks the field used as the splay-tree key.

## Configuration entities

```mermaid
erDiagram
    TEMPLATE ||--o{ PORT : "ports (porttree)"
    TEMPLATE ||--o{ PORT : "bcasts (porttree, Nova broadcast scripts)"
    TEMPLATE ||--|| ACTION : "tcp / udp / icmp defaults"
    TEMPLATE }o--o| PERSONALITY : "person (cloned)"
    TEMPLATE ||--o{ SUBSYSTEM_CONTAINER : subsystems
    TEMPLATE ||--o{ CONDITION : "dynamic (TEMPLATE_DYNAMIC)"
    TEMPLATE }o--o| INTERFACE : inter
    TEMPLATE ||--o| DHCPCLIENT_REQ : dhcp_req
    PORT ||--|| ACTION : action
    PORT }o--o| SUBSYSTEM : sub
    SUBSYSTEM_CONTAINER }o--|| SUBSYSTEM : sub
    SUBSYSTEM ||--o{ TEMPLATE_CONTAINER : templates
    SUBSYSTEM ||--o{ PORT : "ports (portqueue)"
    SUBSYSTEM ||--|| COMMAND : cmd
    CONDITION }o--|| TEMPLATE : "tmpl (target)"
    PERSONALITY ||--|{ PERSONATE : "t_tests[7], seq_tests[6], ecn_test"
    PERSONALITY }o--o| XP_FINGERPRINT : xp_fprint

    TEMPLATE {
        string name PK "IP address or symbolic name"
        uint32 addrbits
        struct_spoof spoof
        uint16 ipid
        uint32 seq
        float drift
        uint16 drop_inrate
        uint16 drop_synrate
        uid_t uid
        gid_t gid
        int max_nofiles
        int flags "TEMPLATE_EXTERNAL|DYNAMIC|DYNAMIC_CHILD"
        int honeypot_instance
        addr_ptr ethernet_addr
        uint16 refcnt
    }
    PORT {
        int proto PK
        ushort number PK
        ushort srcport "broadcast only"
        int timeout "broadcast period"
        int sub_fd
    }
    ACTION {
        string action "script cmdline or proxy target"
        enum status "OPEN PROXY FILTERED CLOSED SUBSYSTEM PYTHON RESERVED"
        int flags "PORT_TARPIT"
        addrinfo_ptr aitop "resolved proxy address"
        void_ptr action_extend "python state"
    }
    PERSONALITY {
        string name PK "nmap Fingerprint line"
        enum IPID_type_TI
        enum IPID_type_CI
        enum IPID_type_II
        uint32 TCP_ISN_gcd
        uint32 TCP_ISR
        uint32 TCP_SP
        int tstamphz
        enum fragp "FRAG_OLD DROP NEW"
        bit disallow_finscan
    }
    PERSONATE {
        int window
        uchar response
        uchar flags
        uchar df
        uint ttl_min
        uint ttl_max
        enum forceack
        enum forceseq
        struct_tcp_options options
    }
    XP_FINGERPRINT {
        string os_id PK
        struct flags
        struct ttl_vals
    }
    SUBSYSTEM {
        string cmdstring
        int flags "SHARED RESTART"
        timeval tv_restart
    }
    SUBSYSTEM_CONTAINER { subsystem_ptr sub }
    TEMPLATE_CONTAINER { template_ptr tmpl }
    CONDITION {
        fnptr match "OS, src IP, time, proto, otherwise"
        void_ptr match_arg
    }
    INTERFACE {
        struct if_ent "libdnet intf_entry"
        int if_addrbits
        pcap_t if_pcap
        eth_t if_eth
        int if_dloff
        char if_filter "BPF, 1024"
    }
    DHCPCLIENT_REQ {
        int state
        eth_addr_t ea
        uint32 xid
        struct nc "leased netconf"
    }
    COMMAND {
        pid_t pid
        int pfd "socketpair to child"
        int perrfd
    }
```

Key points:
- **Templates are the virtual hosts.** `create foo` makes a named profile; `bind 10.0.0.5 foo` calls `template_clone()` (config.c:731) to make a new template *named by the IP address*. Lookup by destination IP is therefore a string lookup in the `templtree` (`template_find`, then fallback `"default"`, then dynamic resolution – config.c:254).
- Templates are reference counted (`template_ref` / `template_free` macros in template.h) because connections hold pointers to them.
- `personality_clone()` copies the parsed fingerprint into the template so per-host counters (ISN, IP ID) are independent.

## Routing topology

```mermaid
erDiagram
    ROUTER ||--o{ LINK_ENTRY : "links (linktree)"
    ROUTER ||--o| NETWORK : "routes (radix-like tree)"
    NETWORK ||--o| ROUTER_ENTRY : "data"
    ROUTER_ENTRY }o--|| ROUTER : parent
    ROUTER_ENTRY }o--o| ROUTER : "gw (next hop)"
    ROUTER_ENTRY }o--o| LINK_ENTRY : link
    ENTRY_ROUTERS ||--o{ ROUTER : "global network tree"

    ROUTER {
        addr addr PK
        addr network "entry routers only"
        int flags "ROUTER_ISENTRY"
    }
    ROUTER_ENTRY {
        addr net
        enum type "LINK NET UNREACH TUNNEL"
        addr tunnel_src
        addr tunnel_dst
    }
    LINK_ENTRY {
        addr dst PK
        int latency "ms"
        int packetloss "percent x100"
        int bandwidth
        int divider
        struct red "drop between low-high ms"
        timeval tv_busy
    }
    NETWORK {
        addr net
        uint16 depth
        ptr left_mid_right
    }
```

`entry_routers` and `reverse` (globals in router.c) are `struct network` trees used by `honeyd_input()` to choose the router where a packet enters the virtual topology.

## Connection state

```mermaid
erDiagram
    TUPLE ||--|| TCP_CON : "embedded as first member"
    TUPLE ||--|| UDP_CON : "embedded as first member"
    TCP_CON }o--|| TEMPLATE : tmpl
    UDP_CON }o--|| TEMPLATE : tmpl
    TCP_CON ||--|| COMMAND : cmd
    UDP_CON ||--|| COMMAND : cmd
    TCP_CON }o--o| PORT : "port (subsystem)"
    UDP_CON ||--o{ CONBUFFER : "incoming (max 10)"
    TUPLE ||--o| PORT_ENCAPSULATE : "pending subsystem connect"
    DELAY }o--o| TEMPLATE : tmpl

    TUPLE {
        ip ip_src PK
        ip ip_dst PK
        uint16 sport PK
        uint16 dport PK
        int type "SOCK_STREAM or SOCK_DGRAM"
        uint32 received
        uint32 sent
        event timeout
        int local
    }
    TCP_CON {
        uint8 state "TCP state"
        uint32 snd_una
        uint32 rcv_next
        uint32 last_acked
        ushort mss
        ushort window
        uchar_ptr payload "send buffer"
        uchar_ptr readbuf
        event retrans_timeout
        uint16 flags "TCP_TARPIT"
        uint8 nmap_opt
    }
    UDP_CON {
        int nincoming
        int softerrors "ICMP unreach count"
    }
    CONBUFFER { size_t len }
    DELAY {
        addr src
        addr dst
        ip_hdr_ptr ip
        uint iplen
        struct spoof
        int flags "NEEDFREE EXTERNAL FREEPKT TUNNEL UNREACH ETHERNET"
    }
    PORT_ENCAPSULATE { void_ptr con }
```

TCP and UDP connections live in two splay trees (`tcpcons`, `udpcons`) keyed on the 4-tuple (`conhdr_compare`, util.c:363; trees declared honeyd.c:124–126) plus LRU lists (`struct conlru`) used to evict old state (limit `PHANTOM_MIRAGE_MAX_CONNECTS` = 32000, honeyd.h). Timeouts: SYN/close-wait 60 s, idle 300 s, UDP 60 s (honeyd.h).
