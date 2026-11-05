"""parse_decoys: Open ports come from `add <tmpl> <proto> port <N> <state>`."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import pmstore  # noqa: E402

CONF = """
create linux-srv
set linux-srv personality "Linux 5.X"
set linux-srv default tcp action reset
add linux-srv tcp port 22 open
add linux-srv tcp port 80 "sh /usr/share/phantom-mirage/web.sh"
add linux-srv udp port 161 open
add linux-srv udp port 53 filtered
add linux-srv tcp port 443
add linux-srv tcp port 23 block
add linux-srv tcp port 25 reset
add linux-srv udp port 69 closed
add linux-srv tcp port
add linux-srv tcp
bind 10.0.0.249 linux-srv
"""


class TestParseDecoys(unittest.TestCase):
    def parse(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(text)
        self.addCleanup(os.unlink, f.name)
        return pmstore.parse_decoys(f.name)

    def test_ports(self):
        d = self.parse(CONF)
        t = d["templates"]["linux-srv"]
        self.assertEqual(t["ports"], ["tcp/22", "tcp/80", "udp/161", "udp/53", "tcp/443"])
        self.assertNotIn("tcp/port", t["ports"])
        self.assertEqual(t["personality"], "Linux 5.X")
        self.assertEqual(t["default"], {"tcp": "reset"})
        self.assertEqual(d["binds"], [{"ip": "10.0.0.249", "template": "linux-srv"}])

    def test_skipped_states(self):
        t = self.parse(CONF)["templates"]["linux-srv"]
        for p in ("tcp/23", "tcp/25", "udp/69"):
            self.assertNotIn(p, t["ports"])

    def test_udp_only(self):
        t = self.parse("add dns udp port 53 open\n")["templates"]["dns"]
        self.assertEqual(t["ports"], ["udp/53"])


if __name__ == "__main__":
    unittest.main()
