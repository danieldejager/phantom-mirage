"""Tests for the time source ops of pm-decoyd (timeinfo, set_time) with a
fake systemctl, chronyc and timedatectl, for both the chrony and the
systemd-timesyncd paths: validation, the file written, restart of only the
time service, verify, rollback, keep anyway, the crash journal and the
systemctl allowlist. No real chronyd is run here."""
import json
import os
import unittest

from test_decoyd import Base, D

ORIG_OWN = D.own_addresses

FAKE_SYSTEMCTL = r"""#!/bin/sh
D=@D@
echo "$*" >> "$D/calls"
case "$1" in
is-active) cat "$D/tactive" ;;
show) echo loaded ;;
restart)
	cp "@SRC@" "$D/at_restart" 2>/dev/null || echo none > "$D/at_restart"
	n=$(cat "$D/trestart"); [ -n "$n" ] || n=ok
	case "$n" in ok) echo active > "$D/tactive" ;; fail) echo failed > "$D/tactive"; exit 1 ;;
	failonce) echo active > "$D/tactive"; echo ok > "$D/trestart"; echo failed > "$D/tactive"; exit 1 ;; esac ;;
esac
exit 0
"""

FAKE_CHRONYC = r"""#!/bin/sh
D=@D@
echo "$*" >> "$D/chronyc_calls"
case "$*" in
*sources*) if [ -s "$D/reach" ]; then sed "s/@R@/$(cat "$D/reach")/" "$D/sources"; fi ;;
*tracking*) cat "$D/tracking" ;;
esac
"""

FAKE_TIMEDATECTL = r"""#!/bin/sh
D=@D@
case "$1" in
timesync-status) cat "$D/tss" ;;
show) cat "$D/ntpsync" ;;
esac
"""

CHRONY_CONF = ("confdir /etc/chrony/conf.d\n#pm-disabled pool ntp.ubuntu.com iburst\n"
               "sourcedir /run/chrony-dhcp\nsourcedir @SD@\n")
TRACKING = """Reference ID    : C0A80105 (192.168.1.5)
Stratum         : 3
Ref time (UTC)  : Thu Nov 05 08:20:11 2026
System time     : 0.000123000 seconds slow of NTP time
Last offset     : -0.000000100 seconds
RMS offset      : 0.000000100 seconds
Frequency       : 1.200 ppm fast
Residual freq   : +0.010 ppm
Skew            : 0.100 ppm
Root delay      : 0.002000000 seconds
Root dispersion : 0.001000000 seconds
Update interval : 64.0 seconds
Leap status     : Normal
"""
# What chronyc tracking printed on an Ubuntu 26.04 arm64 VM before setup,
# with chrony on its default NTS pools (the regression this pins down).
TRACKING_UBUNTU = """Reference ID    : 5BBD5B70 (ntp-nts-2.ps6.canonical.com)
Stratum         : 3
Ref time (UTC)  : Thu Nov 05 08:29:41 2026
System time     : 0.000747161 seconds fast of NTP time
Last offset     : -0.000000672 seconds
RMS offset      : 0.000000672 seconds
Frequency       : 9.873 ppm fast
Residual freq   : -0.000 ppm
Skew            : 0.032 ppm
Root delay      : 0.369115323 seconds
Root dispersion : 0.003040781 seconds
Update interval : 1036.9 seconds
Leap status     : Normal
"""
TRACKING_UNSYNC = """Reference ID    : 00000000 ()
Stratum         : 0
Ref time (UTC)  : Thu Jan 01 00:00:00 1970
System time     : 0.000000000 seconds fast of NTP time
Last offset     : +0.000000000 seconds
RMS offset      : 0.000000000 seconds
Frequency       : 9.873 ppm fast
Residual freq   : +0.000 ppm
Skew            : 0.000 ppm
Root delay      : 1.000000000 seconds
Root dispersion : 1.000000000 seconds
Update interval : 0.0 seconds
Leap status     : Not synchronised
"""
TSS = ("       Server: 192.168.1.5 (192.168.1.5)\nPoll interval: 32s (min: 32s; max 34min 8s)\n"
       "         Leap: normal\n      Stratum: 3\n    Reference: C0A80101\n       Offset: -1.234ms\n"
       " Packet count: 2\n")


class TimeBase(Base):
    kind = "chrony"

    def setUp(self):
        super().setUp()
        sd = self.p("chrony/sources.d")
        os.makedirs(sd)
        os.makedirs(self.p("timesyncd.conf.d"))
        src = os.path.join(sd, "phantom-mirage.sources")
        drop = self.p("timesyncd.conf.d/phantom-mirage.conf")
        for name, body in (("systemctl", FAKE_SYSTEMCTL), ("chronyc", FAKE_CHRONYC), ("timedatectl", FAKE_TIMEDATECTL)):
            self.w(name, body.replace("@D@", self.d).replace("@SRC@", src if self.kind == "chrony" else drop))
            os.chmod(self.p(name), 0o755)
        self.w("chrony/chrony.conf", CHRONY_CONF.replace("@SD@", sd))
        self.w("chrony/sources.d/phantom-mirage.sources", "server 192.168.1.5 iburst\n")
        self.w("timesyncd.conf.d/phantom-mirage.conf", "[Time]\nNTP=192.168.1.5\nFallbackNTP=\n")
        self.w("sources", "^,*,192.168.1.5,3,6,@R@,10,0.0001,0.0001,0.001\n")
        for k, v in (("tactive", "active"), ("trestart", "ok"), ("reach", "377"), ("tracking", TRACKING),
                     ("tss", TSS), ("ntpsync", "yes"), ("calls", "")):
            self.w(k, v + ("\n" if v and not v.endswith("\n") else ""))
        D.P.update({"chrony_conf": self.p("chrony/chrony.conf"), "chrony_src": src,
                    "timesyncd_dropin": drop, "chronyc": self.p("chronyc"),
                    "timedatectl": self.p("timedatectl"), "time_service": self.kind,
                    "time_journal": self.p("run/timechange.journal"),
                    "time_outcome": self.p("run/timechange.last")})
        D.T.update(time_wait=0.3)
        self.src = src if self.kind == "chrony" else drop

    def set(self, servers, expect=("192.168.1.5",), **kw):
        a = {"servers": servers, "expect": list(expect)}
        a.update(kw)
        return self.req("set_time", a)

    def tcalls(self):
        return [l.strip() for l in self.r("calls").splitlines()]


class TestCheckServers(unittest.TestCase):
    def code(self, v, nets=(), own=()):
        with self.assertRaises(D.Err) as c:
            D.check_servers(v, list(nets), own)
        return c.exception.message

    def test_good(self):
        self.assertEqual(D.check_servers(["192.168.1.5", "NTP.lan", "time-1.corp.example"], []),
                         ["192.168.1.5", "ntp.lan", "time-1.corp.example"])

    def test_bad(self):
        net = [D.ipaddress.IPv4Network("10.9.0.8/29")]
        self.assertIn("1 to 3", self.code([]))
        self.assertIn("1 to 3", self.code(["a", "b", "c", "d"]))
        self.assertIn("1 to 3", self.code("192.168.1.5"))
        self.assertIn("decoy block", self.code(["10.9.0.9"], net))
        self.assertIn("twice", self.code(["ntp.lan", "NTP.lan"]))
        for bad in ("127.0.0.1", "127.1.2.3"):
            self.assertIn("loopback address, so the sensor would ask itself", self.code([bad]))
        for bad in ("224.0.0.1", "0.0.0.0", "169.254.1.1", "255.255.255.255"):
            self.assertIn("cannot be", self.code([bad]))
        for bad in ("localhost", "ntp.localhost"):
            self.assertIn("this sensor itself", self.code([bad]))
        own = {D.ipaddress.IPv4Address("192.168.1.20")}
        self.assertIn("an address of this sensor", self.code(["192.168.1.20"], own=own))
        self.assertEqual(D.check_servers(["192.168.1.21"], [], own), ["192.168.1.21"])
        for bad in ("1.2.3", "300.1.1.1", "01.2.3.4"):
            self.assertIn("not a valid", self.code([bad]))
        for bad in ("ntp.lan; reboot", "a b", "-x", "ntp..lan", "$(id)", "x\nserver 1.1.1.1",
                    "a" * 64 + ".lan", "nts://ntp.lan", "ntp.lan:123"):
            self.assertIn("host name", self.code([bad]), bad)
        self.assertIn("not a server", self.code([5]))


class TestChrony(TimeBase):
    def test_timeinfo(self):
        r = self.req("timeinfo")
        self.assertTrue(r["ok"], r)
        t = r["result"]
        self.assertEqual((t["service"], t["unit"], t["active"], t["servers"]),
                         ("chrony", "chrony.service", True, ["192.168.1.5"]))
        self.assertEqual((t["synced"], t["reference"], t["stratum"], t["offset_s"], t["ready"]),
                         (True, "192.168.1.5", 3, -0.000123, None))
        for c in self.r("chronyc_calls").splitlines():
            self.assertTrue(c.startswith("-h 127.0.0.1 "), c)
        self.assertEqual(t["sources"][0]["reach"], "377")

    def test_set_time_refuses_own_and_loopback(self):
        D.own_addresses = lambda: {D.ipaddress.IPv4Address("192.168.1.20"), D.ipaddress.IPv4Address("127.0.0.1")}
        try:
            for addr, msg in (("192.168.1.20", "an address of this sensor"), ("127.0.0.1", "loopback")):
                r = self.set([addr])
                self.assertFalse(r["ok"], r)
                self.assertEqual(r["error"]["code"], "E_INVALID")
                self.assertIn(msg, r["error"]["message"])
            self.assertEqual(self.r("chrony/sources.d/phantom-mirage.sources"), "server 192.168.1.5 iburst\n")
            self.assertNotIn("restart", self.r("calls"))
        finally:
            D.own_addresses = ORIG_OWN

    def test_not_synced(self):
        self.w("tracking", TRACKING_UNSYNC)
        t = self.req("timeinfo")["result"]
        self.assertEqual((t["synced"], t["reference"], t["stratum"], t["offset_s"]), (False, None, 0, 0.0))

    def test_ubuntu_default_pools_before_setup(self):
        # setup not run: no Mirage server file, Ubuntu NTS pools active
        os.unlink(self.src)
        self.w("chrony/sources.d/ubuntu-ntp-pools.sources", "pool 1.ntp.ubuntu.com iburst nts\n")
        self.w("tracking", TRACKING_UBUNTU)
        self.w("sources", "^,*,91.189.91.112,2,10,@R@,40,0.0001,0.0001,0.02\n")
        t = self.req("timeinfo")["result"]
        self.assertEqual((t["synced"], t["reference"], t["stratum"], t["servers"]),
                         (True, "ntp-nts-2.ps6.canonical.com", 3, []))
        self.assertAlmostEqual(t["offset_s"], 0.000747161)
        self.assertEqual([x["name"] for x in t["sources"]], ["91.189.91.112"])
        self.assertIn("ubuntu-ntp-pools.sources", t["ready"])

    def test_tracking_parse(self):
        self.assertAlmostEqual(D.parse_tracking(TRACKING_UBUNTU)["offset_s"], 0.000747161)
        slow = TRACKING_UBUNTU.replace("seconds fast of NTP", "seconds slow of NTP")
        self.assertAlmostEqual(D.parse_tracking(slow)["offset_s"], -0.000747161)
        self.assertTrue(D.parse_tracking(slow)["synced"])
        noname = TRACKING_UBUNTU.replace("5BBD5B70 (ntp-nts-2.ps6.canonical.com)", "5BBD5B70 ()")
        self.assertEqual(D.parse_tracking(noname)["reference"], "5BBD5B70")
        self.assertIsNone(D.parse_tracking(""))
        self.assertIsNone(D.parse_tracking("506 Cannot talk to daemon\n"))

    def test_chronyc_fails(self):
        self.w("chronyc", "#!/bin/sh\necho '506 Cannot talk to daemon' >&2\nexit 1\n")
        t = self.req("timeinfo")["result"]
        self.assertEqual((t["synced"], t["stratum"], t["sources"]), (False, None, []))

    def test_apply(self):
        r = self.set(["192.168.1.6", "ntp.lan"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["result"], {"service": "chrony", "unit": "chrony.service",
                                       "servers": ["192.168.1.6", "ntp.lan"], "reached": True})
        text = self.r("chrony/sources.d/phantom-mirage.sources")
        self.assertIn("server 192.168.1.6 iburst\nserver ntp.lan iburst\n", text)
        self.assertNotIn("nts", text)
        self.assertEqual(self.r("at_restart"), text)
        self.assertIn("restart chrony.service", self.tcalls())
        self.assertFalse([c for c in self.tcalls() if "phantom-mirage" in c])
        self.assertFalse(os.path.exists(D.P["time_journal"]))
        o = self.req("timeinfo")["result"]["last_change"]
        self.assertEqual((o["result"], o["servers"], o["previous"]), ("applied", ["192.168.1.6", "ntp.lan"], ["192.168.1.5"]))

    def test_unreachable_rolls_back(self):
        self.w("reach", "0\n")
        r = self.set(["192.168.1.6"])
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], "E_TIME_UNREACHABLE_ROLLED_BACK")
        self.assertTrue(r["rolled_back"])
        self.assertEqual(self.r("chrony/sources.d/phantom-mirage.sources"), "server 192.168.1.5 iburst\n")
        self.assertEqual([c for c in self.tcalls() if c.startswith("restart")], ["restart chrony.service"] * 2)
        self.assertEqual(D.time_outcome()["result"], "rolled_back")

    def test_keep_anyway(self):
        self.w("reach", "0\n")
        r = self.set(["192.168.1.6"], keep=True)
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["result"]["reached"])
        self.assertIn("kept as asked", r["result"]["warnings"][0])
        self.assertIn("192.168.1.6", self.r("chrony/sources.d/phantom-mirage.sources"))
        self.assertEqual(D.time_outcome()["result"], "applied_unverified")

    def test_restart_fails(self):
        self.w("trestart", "failonce\n")
        r = self.set(["192.168.1.6"], keep=True)
        self.assertEqual(r["error"]["code"], "E_RESTART_FAILED_ROLLED_BACK", r)
        self.assertIn("192.168.1.5", self.r("chrony/sources.d/phantom-mirage.sources"))

    def test_rollback_fails(self):
        self.w("trestart", "fail\n")
        r = self.set(["192.168.1.6"])
        self.assertEqual(r["error"]["code"], "E_ROLLBACK_FAILED")
        self.assertEqual(D.time_outcome()["result"], "rollback_failed")

    def test_refusals(self):
        self.assertEqual(self.set(["192.168.1.6"], expect=["1.1.1.1"])["error"]["code"], "E_CONFLICT")
        self.assertEqual(self.set(["192.168.1.5"])["error"]["code"], "E_UNCHANGED")
        self.assertEqual(self.set(["10.9.0.9"])["error"]["code"], "E_INVALID")
        self.assertEqual(self.set(["192.168.1.6"], keep="yes")["error"]["code"], "E_INVALID")
        self.assertEqual(self.req("set_time", {"servers": ["1.2.3.4"], "expect": [], "nts": True})["error"]["code"],
                         "E_UNKNOWN_FIELD")
        self.assertEqual(self.tcalls(), [])

    def test_setup_needed(self):
        for extra, why in (("pool ntp.ubuntu.com iburst\n", "pool or server"), ("", "no 'sourcedir")):
            conf = CHRONY_CONF.replace("@SD@", os.path.dirname(D.P["chrony_src"]))
            self.w("chrony/chrony.conf", conf + extra if extra else conf.replace("sourcedir " + os.path.dirname(D.P["chrony_src"]), ""))
            r = self.set(["192.168.1.6"])
            self.assertEqual(r["error"]["code"], "E_SETUP_NEEDED")
            self.assertIn(why, r["error"]["message"])
        self.w("chrony/chrony.conf", CHRONY_CONF.replace("@SD@", os.path.dirname(D.P["chrony_src"])))
        self.w("chrony/sources.d/ubuntu-ntp-pools.sources", "pool 1.ntp.ubuntu.com iburst nts\n")
        r = self.set(["192.168.1.6"])
        self.assertIn("ubuntu-ntp-pools.sources", r["error"]["message"])
        self.assertIsNotNone(self.req("timeinfo")["result"]["ready"])

    def test_journal_recovery(self):
        # a cut off swap: new file in place, journal and .prev left behind
        self.w("chrony/sources.d/phantom-mirage.sources.prev", "server 192.168.1.5 iburst\n")
        self.w("chrony/sources.d/phantom-mirage.sources", "server 192.168.1.9 iburst\n")
        with open(D.P["time_journal"], "w") as f:
            json.dump({"id": "x", "path": D.P["chrony_src"], "had": True, "unit": "chrony.service",
                       "previous": ["192.168.1.5"]}, f)
        r = self.set(["192.168.1.6"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.tcalls().count("restart chrony.service"), 2)
        self.assertFalse(os.path.exists(D.P["time_journal"]))

    def test_journal_bad_path(self):
        with open(D.P["time_journal"], "w") as f:
            json.dump({"id": "x", "path": "/etc/passwd", "had": True, "unit": "chrony.service"}, f)
        self.assertEqual(self.set(["192.168.1.6"])["error"]["code"], "E_INTERNAL")
        with open(D.P["time_journal"], "w") as f:
            json.dump({"id": "x", "path": D.P["chrony_src"], "had": True, "unit": "ssh.service"}, f)
        self.assertEqual(self.set(["192.168.1.6"])["error"]["code"], "E_INTERNAL")


class TestTimesyncd(TimeBase):
    kind = "timesyncd"

    def test_timeinfo(self):
        t = self.req("timeinfo")["result"]
        self.assertEqual((t["service"], t["unit"], t["servers"], t["synced"], t["stratum"]),
                         ("timesyncd", "systemd-timesyncd.service", ["192.168.1.5"], True, 3))
        self.assertAlmostEqual(t["offset_s"], -0.001234)
        self.assertEqual(t["reference"], "192.168.1.5 (192.168.1.5)")

    def test_apply(self):
        r = self.set(["192.168.1.6", "ntp.lan", "192.168.1.7"])
        self.assertTrue(r["ok"], r)
        text = self.r("timesyncd.conf.d/phantom-mirage.conf")
        self.assertIn("[Time]\nNTP=192.168.1.6 ntp.lan 192.168.1.7\nFallbackNTP=\n", text)
        self.assertEqual(D.read_servers("timesyncd"), ["192.168.1.6", "ntp.lan", "192.168.1.7"])
        self.assertEqual([c for c in self.tcalls() if c.startswith("restart")], ["restart systemd-timesyncd.service"])

    def test_unreachable(self):
        self.w("tss", "       Server: n/a\n")
        r = self.set(["192.168.1.6"])
        self.assertEqual(r["error"]["code"], "E_TIME_UNREACHABLE_ROLLED_BACK")
        self.assertIn("NTP=192.168.1.5\n", self.r("timesyncd.conf.d/phantom-mirage.conf"))

    def test_no_file_yet(self):
        os.unlink(D.P["timesyncd_dropin"])
        self.assertEqual(self.req("timeinfo")["result"]["servers"], [])
        self.w("reach", "")
        self.w("tss", "")
        r = self.set(["192.168.1.6"], expect=[])
        self.assertEqual(r["error"]["code"], "E_TIME_UNREACHABLE_ROLLED_BACK")
        self.assertFalse(os.path.exists(D.P["timesyncd_dropin"]))


class TestAllowlist(unittest.TestCase):
    def test_refused(self):
        for args in (("stop", "chrony.service"), ("restart", "ssh.service"), ("enable", "chrony.service"),
                     ("restart", "chrony.service", "ssh.service"), ("daemon-reload", "x"), ()):
            self.assertEqual(D.systemctl(*args), (-1, "refused"), args)


if __name__ == "__main__":
    unittest.main()


class TestUnitFile(unittest.TestCase):
    def test_chronyc_can_reach_loopback(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "debian", "pm-decoyd.service")) as f:
            u = f.read()
        lines = [l.strip() for l in u.splitlines() if not l.startswith("#")]
        self.assertIn("IPAddressDeny=any", lines)
        self.assertIn("IPAddressAllow=localhost", lines)
        self.assertEqual([l for l in lines if l.startswith("IPAddressAllow=")], ["IPAddressAllow=localhost"])
