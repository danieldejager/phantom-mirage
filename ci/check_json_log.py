#!/usr/bin/env python3
"""Validate a honeyd --json-log file (issue #24) for the CI subsystem test.

usage: check_json_log.py EVENTS.jsonl [SENSOR_ID]
"""
import json
import re
import sys

TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
REQUIRED = {"ts", "v", "event", "sensor_id"}
FLOW = {"proto", "proto_num"}
EVENTS = {"packet", "connection.start", "connection.end", "service",
          "heartbeat"}
SENSOR = sys.argv[2] if len(sys.argv) > 2 else None

events = []
with open(sys.argv[1], "rb") as f:
    for n, raw in enumerate(f, 1):
        line = raw.decode("ascii")          # output must be pure ASCII
        ev = json.loads(line)               # and one valid object per line
        missing = REQUIRED - ev.keys()
        assert not missing, f"line {n}: missing {missing}"
        assert TS.match(ev["ts"]), f"line {n}: bad ts {ev['ts']}"
        assert ev["v"] == 1 and ev["event"] in EVENTS, f"line {n}: {ev}"
        assert isinstance(ev["sensor_id"], str) and ev["sensor_id"], \
            f"line {n}: bad sensor_id"
        if SENSOR is not None:
            assert ev["sensor_id"] == SENSOR, f"line {n}: {ev['sensor_id']}"
        if ev["event"] != "heartbeat":
            assert not FLOW - ev.keys(), f"line {n}: missing proto"
        events.append(ev)

def pick(kind, **kw):
    return [e for e in events if e["event"] == kind and
            all(e.get(k) == v for k, v in kw.items())]

hp = dict(dst_ip="10.99.0.10", honeypot_ip="10.99.0.10",
          template="linux", personality="Linux 2.6.32", proto="tcp")
starts = pick("connection.start", dst_port=18080, **hp)
ends = pick("connection.end", dst_port=18080, **hp)
# Per-packet events (like the text log) include the honeypot's replies
synacks = pick("packet", src_ip="10.99.0.10", src_port=18080,
               honeypot_ip="10.99.0.10", template="linux",
               direction="outbound", tcp_flags="SA")
assert len(starts) == 3, f"connection.start: {len(starts)}"
assert len(ends) >= 2, f"connection.end: {len(ends)}"
assert all(isinstance(e["bytes_in"], int) and isinstance(e["bytes_out"], int)
           for e in ends)
assert all(e["direction"] == "inbound" and isinstance(e["src_port"], int)
           for e in starts)
assert synacks, "no SYN-ACK packet events from the honeypot"

svc = pick("service", dst_port=2323)
want = 'say "hi" \\ \x01 \xff'
assert any(e["message"].rstrip("\n") == want for e in svc), \
    f"service escaping: {[e['message'] for e in svc]}"

hb = pick("heartbeat")
assert hb, "no heartbeat events"
for e in hb:
    for k in ("uptime_s", "packets_in", "packets_out", "connections"):
        assert isinstance(e[k], int) and e[k] >= 0, f"heartbeat {k}: {e}"
    assert "proto" not in e and "src_ip" not in e, f"heartbeat: {e}"

print(f"OK: {len(events)} events, {len(starts)} connection.start, "
      f"{len(ends)} connection.end, {len(synacks)} SYN-ACK packets, "
      f"{len(svc)} service, {len(hb)} heartbeat")
