# JSON Lines event log

`--json-log=FILE` makes phantom-mirage also write one JSON object per line for each connection, packet and service event, so a log shipper (Fluent Bit, Vector, Filebeat, ...) can forward them to a SIEM (Sentinel, Splunk, Elastic) without parsing text. It's off by default. The text logs (`-l`, `-s`) and syslog output don't change.

```sh
phantom-mirage -d -f phantom-mirage.conf -i eth0 --json-log=/var/log/honeyd/events.jsonl
phantom-mirage -d -f phantom-mirage.conf -i eth0 --json-log=-     # stdout (containers)
```

Every event carries a `sensor_id` (`--sensor-id=STR`, default the hostname) so events from several sensors can be told apart. `--heartbeat=SECONDS` (off by default) adds a periodic `heartbeat` event with uptime and packet counters, so the SIEM can alert on a silent sensor (#30).

```sh
phantom-mirage ... --json-log=- --sensor-id=dmz-01 --heartbeat=60
```

In the Docker image, set `PHANTOM_MIRAGE_JSON_LOG=stdout`, `PHANTOM_MIRAGE_SENSOR_ID` and `PHANTOM_MIRAGE_HEARTBEAT` (see [docker.md](docker.md)).

## Behaviour

- **One complete line per event.** Each event is built in memory and written in one go, then flushed. The file is opened in append mode.
- **Privileges.** Like the text logs, the file is opened *after* phantom-mirage drops privileges (to `nobody` by default), so the file or directory must be writable by that user. `-` (stdout) avoids this.
- **Rotation.** `SIGUSR1` reopens the JSON log together with the text logs (rename the file, then send `kill -USR1`). stdout isn't reopened.
- **Write errors** (disk full, closed pipe) are reported to syslog once. phantom-mirage keeps running, and logs again when writes succeed.
- **Strings.** Escaped so every line is valid JSON *and pure ASCII*. Quotes, backslashes and control characters are escaped. Bytes ≥ 0x7f are written as `\u00XX` (one code point per byte), because service output is attacker-controlled and needn't be UTF-8.

## Schema (`"v": 1`, revision 1.1)

Revision 1.1 added `sensor_id` and the `heartbeat` event. Both are additions, so `v` stays `1` (it only changes for breaking changes).

Fields are omitted when they don't apply. Consumers should ignore unknown fields: new optional fields may be added without bumping `v`. Removing or renaming a field bumps `v`.

| Field | Type | Events | Meaning |
|---|---|---|---|
| `ts` | string | all | event time, ISO 8601 UTC with microseconds, e.g. `2026-10-21T11:12:11.913228Z` |
| `v` | int | all | schema version, currently `1` |
| `event` | string | all | `connection.start`, `connection.end`, `packet`, `service`, `heartbeat` |
| `sensor_id` | string | all | sensor identity: `--sensor-id`, default the hostname (1.1) |
| `proto` | string | all but `heartbeat` | `tcp`, `udp`, `icmp` or the name from `/etc/protocols` |
| `proto_num` | int | all but `heartbeat` | IP protocol number |
| `src_ip`, `dst_ip` | string | all but `heartbeat` | source and destination as in the text log (connections: initiator → responder; packets: as sent) |
| `src_port`, `dst_port` | int | tcp, udp | ports |
| `icmp_type`, `icmp_code` | int | icmp packets | ICMP type and code |
| `honeypot_ip` | string | when known | the decoy address involved |
| `template` | string | when known | configured template name (e.g. `linux-srv`), not the bound IP |
| `personality` | string | when known | the template's nmap personality |
| `direction` | string | when known | `inbound` (towards the honeypot) or `outbound` (sent by the honeypot: replies, honeypot-initiated traffic) |
| `bytes` | int | `packet` | IP packet length |
| `tcp_flags` | string | tcp `packet` | flags in `FSRPAUEC` order, e.g. `SA` |
| `os_guess` | string | `packet`, `connection.start` | passive OS fingerprint of the source, if known |
| `comment` | string | `packet` | phantom-mirage's remark for the packet, if any |
| `bytes_in`, `bytes_out` | int | `connection.end` | payload bytes received from / sent to the peer |
| `message` | string | `service` | a line of output from a service script or subsystem (stderr), newline kept |
| `uptime_s` | int | `heartbeat` | seconds since phantom-mirage started serving (1.1) |
| `packets_in` | int | `heartbeat` | IP packets received for processing since start (1.1) |
| `packets_out` | int | `heartbeat` | IP packets sent by phantom-mirage since start (1.1) |
| `connections` | int | `heartbeat` | `connection.start` events since start (1.1) |

### Events

- **`connection.start` / `connection.end`:** a TCP connection or UDP flow to a honeypot started or ended. These are the same as the `S` and `E` lines in the text log.
- **`packet`:** a packet logged by phantom-mirage: probes to closed or filtered ports, ICMP, other protocols, and phantom-mirage's own replies. These are the same as the `-` lines in the text log.
- **`service`:** output from a service script or subsystem. These are the same lines as the service log (`-s`).
- **`heartbeat`:** written every `--heartbeat` seconds (off by default). It has only `ts`, `v`, `event`, `sensor_id` and the counters; there are no protocol or address fields. Counters are cumulative since start and reset on restart.

### Example

```json
{"ts":"2026-10-21T11:12:11.873800Z","v":1,"event":"connection.start","sensor_id":"dmz-01","proto":"tcp","proto_num":6,"src_ip":"172.30.0.2","dst_ip":"10.99.0.10","src_port":35458,"dst_port":18080,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"inbound"}
{"ts":"2026-10-21T11:12:11.913228Z","v":1,"event":"packet","sensor_id":"dmz-01","proto":"tcp","proto_num":6,"src_ip":"10.99.0.10","dst_ip":"172.30.0.2","src_port":18080,"dst_port":35458,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"outbound","bytes":40,"tcp_flags":"SA"}
{"ts":"2026-10-21T11:12:12.138205Z","v":1,"event":"service","sensor_id":"dmz-01","proto":"tcp","proto_num":6,"src_ip":"172.30.0.2","dst_ip":"10.99.0.10","src_port":34384,"dst_port":2323,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"inbound","message":"say \"hi\" \\ \u0001 \u00ff\n"}
{"ts":"2026-10-21T11:12:12.402117Z","v":1,"event":"connection.end","sensor_id":"dmz-01","proto":"tcp","proto_num":6,"src_ip":"172.30.0.2","dst_ip":"10.99.0.10","src_port":35458,"dst_port":18080,"honeypot_ip":"10.99.0.10","template":"linux","personality":"Linux 2.6.32","direction":"inbound","bytes_in":0,"bytes_out":6}
{"ts":"2026-10-21T11:13:00.000412Z","v":1,"event":"heartbeat","sensor_id":"dmz-01","uptime_s":60,"packets_in":41,"packets_out":19,"connections":3}
```

### SIEM mapping hints

| phantom-mirage | Elastic ECS | Splunk CIM | Sentinel ASIM |
|---|---|---|---|
| `ts` | `@timestamp` | `_time` | `TimeGenerated` |
| `src_ip` / `src_port` | `source.ip` / `source.port` | `src_ip` / `src_port` | `SrcIpAddr` / `SrcPortNumber` |
| `dst_ip` / `dst_port` | `destination.ip` / `destination.port` | `dest_ip` / `dest_port` | `DstIpAddr` / `DstPortNumber` |
| `sensor_id` | `observer.name` / `host.name` | `dvc` | `DvcHostname` |
| `proto` | `network.transport` | `transport` | `NetworkProtocol` |
| `bytes_in` / `bytes_out` | `source.bytes` / `destination.bytes` | `bytes_in` / `bytes_out` | `SrcBytes` / `DstBytes` |

## Not covered yet

- Text log lines that aren't produced by the four log functions (the ~390 `syslog()` calls, the UDP stats feed) aren't in the JSON log.
- Central configuration from #30 isn't covered; only the sensor identity and heartbeat parts are done.
