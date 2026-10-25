"""Any-touch alerts vs return traffic to decoy-initiated flows (#139).
Synthetic events only; nothing is sent on any network."""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import pmstore  # noqa: E402

D1, D2 = "192.168.1.241", "192.168.1.242"
SCAN = "198.51.100.7"
PUB = "203.0.113.80"          # stands in for a public update/time service


def ts(s):
    return "2026-01-01T00:%02d:%02d.000000Z" % (s // 60, s % 60)


def ev(src, dst, sp, dp, flags="S", proto="tcp", direction="inbound", at=0,
       event="packet", hp=None):
    e = {"ts": ts(at), "event": event, "proto": proto, "src_ip": src, "dst_ip": dst,
         "honeypot_ip": hp or (dst if direction == "inbound" else src),
         "direction": direction}
    if proto in ("tcp", "udp"):
        e["src_port"], e["dst_port"] = sp, dp
    if proto == "tcp":
        e["tcp_flags"] = flags
    return e


class Replies(unittest.TestCase):
    def setUp(self):
        self._sd = pmstore.STATE_DIR
        pmstore.STATE_DIR = tempfile.mkdtemp()
        self.addCleanup(setattr, pmstore, "STATE_DIR", self._sd)
        self.e = pmstore.AlertEngine(event_log=os.path.join(pmstore.STATE_DIR, "none.jsonl"))

    def test_syn_alerts(self):
        self.e.handle(ev(SCAN, D1, 40000, 22, "S"), set())
        self.assertEqual([(a["severity"], a["why"]) for a in self.e.alerts], [("Medium", "Any touch")])

    def test_unsolicited_reply_style_scans_alert(self):
        for name, fl in (("ACK", "A"), ("FIN", "F"), ("NULL", ""), ("Xmas", "FPU")):
            with self.subTest(scan=name):
                e = pmstore.AlertEngine(event_log="/nonexistent")
                e.handle(ev(SCAN, D1, 40000, 80, fl), set())
                self.assertEqual(len(e.alerts), 1)
                self.assertEqual(e.alerts[0]["severity"], "Medium")

    def test_reply_to_decoy_flow_does_not_alert(self):
        self.e.handle(ev(D1, PUB, 51000, 443, "S", direction="outbound", at=0), set())
        self.e.handle(ev(PUB, D1, 443, 51000, "SA", at=1), set())
        self.e.handle(ev(PUB, D1, 443, 51000, "FA", at=2), set())
        self.assertEqual(self.e.alerts, [])
        self.assertTrue(all(r.get("reply") for r in self.e.activity))
        self.assertEqual(len(self.e.activity), 2)

    def test_udp_and_icmp_replies(self):
        self.e.handle(ev(D1, PUB, 123, 123, proto="udp", direction="outbound"), set())
        self.e.handle(ev(D1, PUB, 0, 0, proto="icmp", direction="outbound"), set())
        self.e.handle(ev(PUB, D1, 123, 123, proto="udp", at=1), set())
        self.e.handle(ev(PUB, D1, 0, 0, proto="icmp", at=1), set())
        self.assertEqual(self.e.alerts, [])
        # an unsolicited UDP probe / ICMP echo still alert
        self.e.handle(ev(SCAN, D1, 5000, 161, proto="udp", at=2), set())
        self.e.handle(ev(SCAN, D2, 0, 0, proto="icmp", at=3), set())
        self.assertEqual(len(self.e.alerts), 1)
        self.assertEqual(self.e.alerts[0]["severity"], "High")

    def test_other_port_from_same_peer_still_alerts(self):
        self.e.handle(ev(D1, PUB, 51000, 443, "S", direction="outbound"), set())
        self.e.handle(ev(PUB, D1, 443, 22, "A", at=1), set())
        self.assertEqual(len(self.e.alerts), 1)

    def test_multi_decoy_high_for_each_scan(self):
        for name, fl in (("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("NULL", ""), ("Xmas", "FPU")):
            with self.subTest(scan=name):
                e = pmstore.AlertEngine(event_log="/nonexistent")
                e.handle(ev(SCAN, D1, 40000, 80, fl, at=0), set())
                e.handle(ev(SCAN, D2, 40000, 80, fl, at=5), set())
                self.assertEqual(len(e.alerts), 1)
                self.assertEqual((e.alerts[0]["severity"], e.alerts[0]["why"]), ("High", "Multi-decoy scan"))

    def test_grouping_and_mute_unchanged(self):
        self.e.handle(ev(SCAN, D1, 40000, 22, at=0), set())
        self.e.handle(ev(SCAN, D1, 40001, 23, at=30), set())
        self.assertEqual(self.e.alerts[0]["count"], 2)
        self.e.handle(ev("192.0.2.9", D1, 1, 22), {"192.0.2.9"})
        self.assertEqual(len(self.e.alerts), 1)

    def test_flow_table_expires(self):
        self.e.handle(ev(D1, PUB, 51000, 443, "S", direction="outbound", at=0), set())
        self.e.handle(ev(PUB, D1, 443, 51000, "SA", at=pmstore.FLOW_WINDOW + 1), set())
        self.assertEqual(len(self.e.alerts), 1)
        self.assertEqual(len(self.e.flows), 0)

    def test_flow_table_bounded(self):
        old = pmstore.FLOW_MAX
        pmstore.FLOW_MAX = 10
        self.addCleanup(setattr, pmstore, "FLOW_MAX", old)
        for i in range(50):
            self.e.handle(ev(D1, PUB, 50000 + i, 443, "S", direction="outbound"), set())
        self.assertEqual(len(self.e.flows), 10)
        # oldest flow was evicted: its reply now alerts; newest still suppressed
        self.e.handle(ev(PUB, D1, 443, 50049, "SA"), set())
        self.assertEqual(self.e.alerts, [])
        self.e.handle(ev(PUB, D1, 443, 50000, "SA"), set())
        self.assertEqual(len(self.e.alerts), 1)

    def test_old_state_files_load(self):
        old_alert = {"id": 3, "severity": "Medium", "why": "Any touch", "src": SCAN,
                     "decoys": [D1], "first": ts(0), "last": ts(0),
                     "last_t": pmstore._parse_ts(ts(0)), "count": 1, "status": "Open", "note": ""}
        with open(pmstore.path("alerts.json"), "w") as f:
            json.dump({"alerts": [old_alert], "next_id": 4}, f)
        with open(pmstore.path("ingest.json"), "w") as f:
            json.dump({"ino": 1, "off": 0}, f)
        e = pmstore.AlertEngine(event_log="/nonexistent")
        self.assertEqual((e.next_id, e.ino, e.off, len(e.alerts)), (4, 1, 0, 1))
        e.handle(ev(SCAN, D1, 40000, 22, at=10), set())
        self.assertEqual(e.alerts[0]["count"], 2)
        e.save()
        with open(pmstore.path("ingest.json")) as f:
            self.assertEqual(set(json.load(f)), {"ino", "off"})

    def _probe_answer_follow(self, proto, ans_flags, sp=40000, dp=80):
        self.e.handle(ev(SCAN, D1, sp, dp, "S", proto=proto, at=0), set())
        self.e.handle(ev(D1, SCAN, dp, sp, ans_flags, proto=proto,
                         direction="outbound", at=1), set())
        self.e.handle(ev(SCAN, D1, sp, dp, "A", proto=proto, at=20), set())
        self.assertEqual(len(self.e.alerts), 1)
        self.assertEqual(self.e.alerts[0]["count"], 2)
        self.assertFalse(any(r.get("reply") for r in self.e.activity))
        self.assertEqual(len(self.e.flows), 0)

    def test_follow_up_after_decoy_synack_alerts(self):
        self._probe_answer_follow("tcp", "SA")

    def test_follow_up_after_decoy_rst_alerts(self):
        self._probe_answer_follow("tcp", "RA")

    def test_follow_up_after_decoy_udp_answer_alerts(self):
        self._probe_answer_follow("udp", "", sp=5353, dp=161)

    def test_follow_up_after_decoy_icmp_answer_alerts(self):
        self._probe_answer_follow("icmp", "")

    def test_scanner_data_after_synack_alerts(self):
        # review on #140: SYN, decoy SYN-ACK, then 5 data packets on the same flow
        self.e.handle(ev(SCAN, D1, 40000, 80, "S", at=0), set())
        self.e.handle(ev(D1, SCAN, 80, 40000, "SA", direction="outbound", at=0), set())
        for i in range(5):
            self.e.handle(ev(SCAN, D1, 40000, 80, "PA", at=1 + i), set())
        self.assertEqual(len(self.e.alerts), 1)
        self.assertEqual(self.e.alerts[0]["count"], 6)
        self.assertFalse(any(r.get("reply") for r in self.e.activity))

    def test_late_synack_still_starts_no_tcp_flow(self):
        # SYN-only rule holds even outside the answer window
        self.e.handle(ev(D1, SCAN, 80, 40000, "SA", direction="outbound", at=0), set())
        self.e.handle(ev(D1, SCAN, 80, 40001, "R", direction="outbound", at=0), set())
        self.e.handle(ev(SCAN, D1, 40000, 80, "A", at=1), set())
        self.assertEqual(len(self.e.flows), 0)
        self.assertEqual(len(self.e.alerts), 1)

    def test_icmp_unreachable_for_udp_probe_starts_no_flow(self):
        self.e.handle(ev(SCAN, D1, 5000, 161, proto="udp", at=0), set())
        self.e.handle(ev(D1, SCAN, 0, 0, proto="icmp", direction="outbound", at=1), set())
        self.e.handle(ev(SCAN, D1, 0, 0, proto="icmp", at=20), set())
        self.assertEqual(self.e.alerts[0]["count"], 2)

    def test_decoy_started_flow_still_suppresses_reply(self):
        self.e.handle(ev(D1, PUB, 51000, 443, "S", direction="outbound", at=0), set())
        self.e.handle(ev(PUB, D1, 443, 51000, "SA", at=1), set())
        self.e.handle(ev(D1, PUB, 51000, 443, "A", direction="outbound", at=1), set())
        self.e.handle(ev(PUB, D1, 443, 51000, "PA", at=2), set())
        self.assertEqual(self.e.alerts, [])

    def test_answer_window_expires(self):
        self.e.handle(ev(SCAN, D1, 5000, 53, proto="udp", at=0), set())
        self.e.handle(ev(D1, SCAN, 53, 5000, proto="udp", direction="outbound",
                         at=pmstore.ANSWER_WINDOW + 5), set())
        self.assertEqual(len(self.e.flows), 1)
        self.assertEqual(len(self.e.inbound), 0)

    def test_inbound_table_bounded(self):
        old = pmstore.INBOUND_MAX
        pmstore.INBOUND_MAX = 10
        self.addCleanup(setattr, pmstore, "INBOUND_MAX", old)
        for i in range(50):
            self.e.handle(ev(SCAN, D1, 5000 + i, 53, proto="udp"), set())
        self.assertLessEqual(len(self.e.inbound), 10)
        self.e.handle(ev(D1, SCAN, 53, 5049, proto="udp", direction="outbound"), set())
        self.assertEqual(len(self.e.flows), 0)      # newest remembered: answer
        self.e.handle(ev(D1, SCAN, 53, 5000, proto="udp", direction="outbound"), set())
        self.assertEqual(len(self.e.flows), 1)      # oldest evicted


if __name__ == "__main__":
    unittest.main()
