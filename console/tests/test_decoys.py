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


FPDB = """# comment
Fingerprint ubuntu2404
Class Linux | Linux | 6.X | general purpose
Fingerprint ws2022-fwoff
Fingerprint ws2019-fwoff
Fingerprint ws2025-fwoff
Fingerprint win11-fwon
Fingerprint win11-fwoff
Fingerprint ubuntu2404
Fingerprint bad name with spaces
Fingerprint evil;rm
"""


class TestPortStates(unittest.TestCase):
    def test_port_states_keep_every_state(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(CONF)
        self.addCleanup(os.unlink, f.name)
        ps = pmstore.parse_decoys(f.name)["templates"]["linux-srv"]["port_states"]
        got = {(p["proto"], p["port"]): p["state"] for p in ps}
        self.assertEqual(got, {("tcp", 22): "open", ("tcp", 80): "script", ("udp", 161): "open",
                               ("udp", 53): "filtered", ("tcp", 443): "open", ("tcp", 23): "block",
                               ("tcp", 25): "reset", ("udp", 69): "closed"})

    def test_script_command_never_exposed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write(CONF)
        self.addCleanup(os.unlink, f.name)
        ps = pmstore.parse_decoys(f.name)["templates"]["linux-srv"]["port_states"]
        self.assertNotIn("web.sh", repr(ps))


class TestPersonalities(unittest.TestCase):
    def test_fingerprint_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".db", delete=False) as f:
            f.write(FPDB)
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(pmstore.personalities(f.name),
                         ["ubuntu2404", "ws2022-fwoff", "ws2019-fwoff", "ws2025-fwoff",
                          "win11-fwon", "win11-fwoff"])

    def test_missing_file(self):
        self.assertEqual(pmstore.personalities("/nonexistent/columbo-v1.db"), [])

    def test_shipped_pinned_db(self):
        db = os.path.join(HERE, "..", "..", "fingerprints", "columbo-v1.db")
        self.assertEqual(len(pmstore.personalities(db)), 6)


if __name__ == "__main__":
    unittest.main()
