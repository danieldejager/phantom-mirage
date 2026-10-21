# JSON Lines event log

`--json-log=FILE` makes honeyd also write one JSON object per line for each connection, packet and service event, so a log shipper (Fluent Bit, Vector, Filebeat, ...) can forward them to a SIEM (Sentinel, Splunk, Elastic) without parsing text. It's off by default. The text logs (`-l`, `-s`) and syslog output don't change.

```sh
honeyd -d -f honeyd.conf -i eth0 --json-log=/var/log/honeyd/events.jsonl
honeyd -d -f honeyd.conf -i eth0 --json-log=-     # stdout (containers)
```

In the Docker image, set `HONEYD_JSON_LOG=stdout` (see [docker.md](docker.md)).

## Behaviour

- **One complete line per event.** Each event is built in memory and written in one go, then flushed. The file is opened in append mode.
- **Privileges.** Like the text logs, the file is opened *after* honeyd drops privileges (to `nobody` by default), so the file or directory must be writable by that user. `-` (stdout) avoids this.
- **Rotation.** `SIGUSR1` reopens the JSON log together with the text logs (rename the file, then send `kill -USR1`). stdout isn't reopened.
- **Write errors** (disk full, closed pipe) are reported to syslog once. honeyd keeps running, and logs again when writes succeed.
- **Strings.** Escaped so every line is valid JSON *and pure ASCII*. Quotes, backslashes and control characters are escaped. Bytes ≥ 0x7f are written as `\u00XX` (one code point per byte), because service output is attacker-controlled and needn't be UTF-8.

## Schema (`"v": 1`)

Fields are omitted when they don't apply. Consumers should ignore unknown fields: new optional fields may be added without bumping `v`. Removing or renaming a field bumps `v`.

| Field | Type | Events | Meaning |
|---|---|---|---|
| `ts` | string | all | event time, ISO 8601 UTC with microseconds, e.g. `2026-10-21T11:12:11.913228Z` |
| `v` | int | all | schema version, currently `1` |
| `event` | string | all | `connection.start`, `connection.end`, `packet`, `service` |
| `proto` | string | all | `tcp`, `udp`, `icmp` or the name from `/etc/protocols` |
| `proto_num` | int | all | IP protocol number |
| `src_ip`, `dst_ip` | string | all | source and destination as in the text log (connections: initiator → responder; packets: as sent) |
| `src_port`, `dst_port` | int | tcp, udp | ports |
| `icmp_type`, `icmp_code` | int | icmp packets | ICMP type and code |
| `honeypot_ip` | string | when known | the decoy address involved |
| `template` | string | when known | configured template name (e.g. `linux-srv`), not the bound IP |
| `personality` | string | when known | the template's nmap personality |
| `direction` | string | when known | `inbound` (towards the honeypot) or `outbound` (sent by the honeypot: replies, honeypot-initiated traffic) |
| `bytes` | int | `packet` | IP packet length |
| `tcp_flags` | string | tcp `packet` | flags in `FSRPAUEC` order, e.g. `SA` |
| `os_guess` | string | `packet`, `connection.start` | passive OS fingerprint of the source, if known |
| `comment` | string | `packet` | honeyd's remark for the packet, if any |
| `bytes_in`, `bytes_out` | int | `connection.end` | payload bytes received from / sent to the peer |
| `message` | string | `service` | a line of output from a service script or subsystem (stderr), newline kept |

### Events

- **`connection.start` / `connection.end`:** a TCP connection or UDP flow to a honeypot started or ended. These are the same as the `S` and `E` lines in the text log.
- **`packet`:** a packet logged by honeyd: probes to closed or filtered ports, ICMP, other protocols, and honeyd's own replies. These are the same as the `-` lines in the text log.
- **`service`:** output from a service script or subsystem. These are the same lines as the service log (`-s`).

### Example

```json
{"ts":"2026-10-21T11:12:11.873800Z","v":1,"event":"connection.start","proto":"tcp","proto_num":6,"src_ip":"172.30.0.2","dst_ip":"10.99.0.10","src_port":35458,"dst_port":18080,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"inbound"}
{"ts":"2026-10-21T11:12:11.913228Z","v":1,"event":"packet","proto":"tcp","proto_num":6,"src_ip":"10.99.0.10","dst_ip":"172.30.0.2","src_port":18080,"dst_port":35458,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"outbound","bytes":40,"tcp_flags":"SA"}
{"ts":"2026-10-21T11:12:12.138205Z","v":1,"event":"service","proto":"tcp","proto_num":6,"src_ip":"172.30.0.2","dst_ip":"10.99.0.10","src_port":34384,"dst_port":2323,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"inbound","message":"say \"hi\" \\ \u0001 \u00ff\n"}
{"ts":"2026-10-21T11:12:12.402117Z","v":1,"event":"connection.end","proto":"tcp","proto_num":6,"src_ip":"172.30.0.2","dst_ip":"10.99.0.10","src_port":35458,"dst_port":18080,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"inbound","bytes_in":0,"bytes_out":6}
```

### SIEM mapping hints

| honeyd | Elastic ECS | Splunk CIM | Sentinel ASIM |
|---|---|---|---|
| `ts` | `@timestamp` | `_time` | `TimeGenerated` |
| `src_ip` / `src_port` | `source.ip` / `source.port` | `src_ip` / `src_port` | `SrcIpAddr` / `SrcPortNumber` |
| `dst_ip` / `dst_port` | `destination.ip` / `destination.port` | `dest_ip` / `dest_port` | `DstIpAddr` / `DstPortNumber` |
| `proto` | `network.transport` | `transport` | `NetworkProtocol` |
| `bytes_in` / `bytes_out` | `source.bytes` / `destination.bytes` | `bytes_in` / `bytes_out` | `SrcBytes` / `DstBytes` |

## Not covered yet

- Text log lines that aren't produced by the four log functions (the ~390 `syslog()` calls, the UDP stats feed) aren't in the JSON log.
- No sensor/host identifier field yet. Add it in the shipper, or later with the heartbeat work (#30).
