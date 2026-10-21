#!/usr/bin/env python3
"""Unit test for webserver/server.py with a stand-in honeyd module (#36)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "webserver"))
import server  # noqa: E402


class FakeHoneyd:
    def config(self):
        return {"version": "0.0-test", "config": "/x<y>.conf", "personality": "p",
                "xprobe": "x", "assoc": "a", "osfp": "o"}

    def interfaces(self):
        return [{"name": "lo", "address": "127.0.0.1/8", "mtu": 65536,
                 "link": None}]

    def stats_network(self):
        return {"Input Bytes": (1.0, 2000.0, 3e6),
                "Output Bytes": (0.0, 0.0, 0.0)}

    def status_connections(self, proto):
        if proto == "tcp":
            return [{"src": "10.0.0.1", "sport": 1, "dst": "10.0.0.2",
                     "dport": 80, "received": 3, "sent": 4}]
        return []

    def config_ips(self):
        return [{"address": "10.99.0.10", "personality": "<script>",
                 "ethernet": None, "tcp_action": "reset",
                 "udp_action": "block", "icmp_action": "open"}]

    def uptime(self):
        return 90061


root = os.path.join(os.path.dirname(__file__), "..", "webserver", "htdocs")
s = server.HoneydServer(root, FakeHoneyd())


def get(req):
    return server.handle_request(s, req, "127.0.0.1")


r = get(b"GET / HTTP/1.0\r\n\r\n")
assert r.startswith(b"HTTP/1.0 200"), r[:80]
assert b"Uptime: 1 days 01:01:01" in r
assert b"10.99.0.10" in r and b"&lt;script&gt;" in r and b"<script>" not in r
assert b"x&lt;y&gt;.conf" in r and b"no active UDP connections" in r
assert b"2.00 KB/s" in r
assert get(b"HEAD /index.py HTTP/1.0\r\n\r\n").endswith(b"\r\n\r\n")
assert get(b"GET /styles/layout.css HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.0 200")
for bad in (b"/../server.py", b"/styles/../../server.py", b"/server.py",
            b"/styles/%2e%2e/%2e%2e/server.py", b"/nope", b"/index.py?delete_ip=1x"):
    r = get(b"GET " + bad + b" HTTP/1.0\r\n\r\n")
    expect = b"HTTP/1.0 200" if bad.startswith(b"/index.py") else b"HTTP/1.0 404"
    assert r.startswith(expect), (bad, r[:60])
assert get(b"POST / HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.0 501")
assert b"Error code: 400" in get(b"garbage\r\n\r\n")
print("webserver unit test OK")
