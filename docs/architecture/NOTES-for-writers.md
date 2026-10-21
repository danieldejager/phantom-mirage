# Notes for writers: where things live (master @ a0f3d64)

Line numbers are approximate pointers into `master`; verify before quoting.

## Executables (Makefile.am `bin_PROGRAMS`)
- `phantom-mirage` – the daemon. `main()` honeyd.c:3534.
- `phantom-mirage-ctl` – CLI that connects to the daemon's Unix-domain socket (honeydctl.c:308 `socket(AF_UNIX…)`), served by `ui_init()` ui.c:351 (`ui_file = UI_FIFO`, ui.c:67).
- `phantom-mirage-stats` – separate stats collector (honeydstats_main.c, honeydstats.c, analyze.c); receives tagged stats from phantom-mirage's `stats.c` (`stats_init` stats.c:844).
- `phantom-mirage-sniff` – stand-alone sniffer (hsniff.c).
- `libphantom-mirage.so` – LD_PRELOAD library (honeyd_overload.c) that lets real server programs ("subsystems") use Phantom Mirage's virtual network.
- `smtp`, `proxy` – optional bundled subsystems (subsystems/).

## Startup order (honeyd.c `main`, ~3740–3990)
`event_base_new` → `pool_init` → `hooks_init` → `arp_init` → `interface_initialize(honeyd_recv_cb)` → `config_init` → `router_init` → `plugins_config_init` → (`stats_init`) → `personality_init`, `xprobe_personality_init`, `associations_init` → parse xprobe2.conf, nmap.assoc, nmap-os-db (`personality_parse` personality.c:2349), pf.os (`honeyd_osfp_init` osfp.c:92) → `honeyd_init` → `ip_open` (libdnet raw IP) → `pyextend_init` (if HAVE_PYTHON) → `ethernetcode_init` (nmap-mac-prefixes) → `interface_init` per `-i` (interface.c:310) → `config_read` (config.c:127) → `dhcp_send_discover` → `ui_init` → `plugins_init` (plugins.c:139) → `ip_fragment_init` → PID file → `daemon()` → `cmd_droppriv` → signal events → `event_base_dispatch`.

## Packet path (receive)
1. `honeyd_recv_cb` honeyd.c:3373 – libpcap callback; ARP diverted to `arp_recv_cb` arp.c:320; DHCP replies (udp 67→68) to `dhcp_recv_cb` dhcpclient.c:552.
2. `honeyd_input` honeyd.c:3258 – if no routing topology (`router_used==0`) → `template_find_best` (config.c:254) → `honeyd_delay_packet`. Otherwise GRE decap, entry-router lookup (`network_lookup` router.c:288), `honeyd_route_packet` honeyd.c:3109 (latency/loss/RED/TTL).
3. `honeyd_delay_packet` honeyd.c:899 / `honeyd_delay_cb` honeyd.c:773 – schedules delivery; sends externally, via GRE (`gre_encapsulate` gre.c:135), via Ethernet, or calls…
4. `honeyd_dispatch` honeyd.c:3036 → `tcp_recv_cb` honeyd.c:2118, `udp_recv_cb` 2729 (`handle_udp_packet` 2560), `icmp_recv_cb` 2754; other protocols logged only.
5. Port lookup `honeyd_port` honeyd.c:1326; services started by `generic_connect` honeyd.c:1416 → `cmd_fork` command.c:374 (scripts, env vars PHANTOM_MIRAGE_* command.c:226–259), `proxy_connect` 1349, `cmd_subsystem_schedule_connect`, `cmd_python` command.c:491.

## Packet path (send)
`tcp_send` honeyd.c:1522 / `tcp_senddata` 1655 / `udp_send` 2506 / `icmp_send` 1731 → personality fields (`tcp_personality` personality.c:743, `ip_personality` personality.c:207) → `honeyd_ip_send` honeyd.c:961 → back through `honeyd_delay_packet` (routing) → `ip_send` (libdnet) or `honeyd_send_ethernet` honeyd.c:679 (ARP via `arp_request` arp.c:293).

## Key structs
- `struct template` template.h – virtual host / profile (ports, bcasts, default actions, personality, uid/gid, ethernet_addr, dhcp_req, spoof, dynamic conditions, refcnt).
- `struct port`, `struct action`, `enum status` honeyd.h.
- `struct tuple`, `struct tcp_con`, `struct udp_con`, `struct command`, `struct port_encapsulate`, `struct delay`, `struct spoof` honeyd.h.
- `struct personality`, `struct personate`, `struct xp_fingerprint` personality.h.
- `struct router`, `struct router_entry`, `struct link_entry` router.h; `struct network` network.h.
- `struct subsystem`, `struct template_container`, `struct subsystem_command` subsystem.h.
- `struct interface` interface.h.
- `struct condition` condition.h (dynamic templates).

## Config parsing
- Grammar parse.y (yacc), tokens lex.l. Top-level rules parse.y:156–167.
- `create` → `template_create` config.c:269; `add … port` → `template_add` config.c:650; `bind` → `template_clone` config.c:731; `dynamic`/`add … use … if` → `template_insert_dynamic` config.c:996; `route` → `router_start` router.c:410, `router_add_net` router.c:517; `broadcast` (DataSoft/Nova addition) → `bcast_insert` config.c:585 / `bcast_trigger` config.c:539.

## Extension points
- Hooks: `hooks_dispatch` hooks.c:207 (plugins see packets).
- Plugins: plugins.c (`plugin_hook_up`), plugins_config.c (`option` keyword).
- Python: pyextend.c (`pyextend_init` :769), Python 2 era, optional `--with-python`.
- Logging: `honeyd_log_probe` log.c:307 (`-l` packet log, `-s` service log).
