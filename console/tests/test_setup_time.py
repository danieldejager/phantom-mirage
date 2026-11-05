"""Setup points the time service the machine actually runs (chrony or
systemd-timesyncd) at one local NTP server, with no internet fallback."""
import importlib.util
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
UBUNTU_CONF = """confdir /etc/chrony/conf.d
sourcedir /run/chrony-dhcp
sourcedir {d}/sources.d
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
makestep 1 3
"""
POOLS = "pool 1.ntp.ubuntu.com iburst maxsources 1 nts prefer\npool 2.ntp.ubuntu.com iburst maxsources 1 nts\n"
DEBIAN_CONF = "# Debian default\npool 2.debian.pool.ntp.org iburst\nserver ntp.example.com\ndriftfile /var/lib/chrony/chrony.drift\n"


class SetupTime(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.chrony = os.path.join(self.d, "chrony")
        os.makedirs(os.path.join(self.chrony, "sources.d"))
        self.dropin = os.path.join(self.d, "timesyncd.conf.d", "phantom-mirage.conf")
        self.env = dict(os.environ)
        os.environ.update(PM_CHRONY_DIR=self.chrony, PM_TIMESYNCD_DROPIN=self.dropin,
                          PM_CONSOLE_STATE=os.path.join(self.d, "st"))
        sys.path.insert(0, ROOT)
        spec = importlib.util.spec_from_file_location("pmsetup_t", os.path.join(ROOT, "pm-console-setup.py"))
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.euid = mock.patch.object(os, "geteuid", lambda: 1000)  # never run systemctl/timedatectl here
        self.euid.start()

    def tearDown(self):
        self.euid.stop()
        os.environ.clear()
        os.environ.update(self.env)
        shutil.rmtree(self.d)

    def p(self, *a):
        return os.path.join(self.chrony, *a)

    def apply(self, svc, src="ntp", server="192.168.1.10"):
        os.environ["PM_TIME_SERVICE"] = svc
        out = io.StringIO()
        with redirect_stdout(out):
            got = self.m.apply_time({"time_source": src, "ntp_server": server if src == "ntp" else "",
                                     "timezone": "UTC"}, False)
        return got, out.getvalue()

    def test_chrony_ubuntu_pools_set_aside(self):
        open(self.p("chrony.conf"), "w").write(UBUNTU_CONF.format(d=self.chrony))
        open(self.p("sources.d", "ubuntu-ntp-pools.sources"), "w").write(POOLS)
        svc, out = self.apply("chrony")
        self.assertEqual(svc, "chrony")
        self.assertIn("chrony configured with server 192.168.1.10; no internet fallback", out)
        self.assertIn("set aside ubuntu-ntp-pools.sources", out)
        names = sorted(os.listdir(self.p("sources.d")))
        self.assertEqual(names, ["phantom-mirage.sources", "ubuntu-ntp-pools.sources.pm-disabled"])
        self.assertEqual(open(self.p("sources.d", "ubuntu-ntp-pools.sources.pm-disabled")).read(), POOLS)
        ours = open(self.p("sources.d", "phantom-mirage.sources")).read()
        self.assertIn("server 192.168.1.10 iburst\n", ours)
        self.assertNotIn("nts", ours)
        # chrony.conf already reads sources.d and has no pool lines: untouched, no backup
        self.assertEqual(open(self.p("chrony.conf")).read(), UBUNTU_CONF.format(d=self.chrony))
        self.assertFalse(os.path.exists(self.p("chrony.conf.pm-backup")))
        self.assertFalse(os.path.exists(self.dropin))

    def test_chrony_idempotent_and_restore(self):
        open(self.p("chrony.conf"), "w").write(DEBIAN_CONF)
        self.apply("chrony")
        first = {n: open(self.p("sources.d", n)).read() for n in os.listdir(self.p("sources.d"))}
        conf1 = open(self.p("chrony.conf")).read()
        self.assertIn("#pm-disabled pool 2.debian.pool.ntp.org iburst", conf1)
        self.assertIn("#pm-disabled server ntp.example.com", conf1)
        self.assertIn("sourcedir %s/sources.d" % self.chrony, conf1)
        self.assertEqual(open(self.p("chrony.conf.pm-backup")).read(), DEBIAN_CONF)
        _, out = self.apply("chrony")
        self.assertEqual(open(self.p("chrony.conf")).read(), conf1)
        self.assertEqual({n: open(self.p("sources.d", n)).read() for n in os.listdir(self.p("sources.d"))}, first)
        self.assertEqual(open(self.p("chrony.conf.pm-backup")).read(), DEBIAN_CONF)
        self.assertNotIn("set aside", out)
        with redirect_stdout(io.StringIO()):
            self.m.restore_time([])
        self.assertEqual(open(self.p("chrony.conf")).read(), DEBIAN_CONF)
        self.assertEqual(os.listdir(self.p("sources.d")), [])

    def test_chrony_restore_brings_back_pools(self):
        open(self.p("chrony.conf"), "w").write(UBUNTU_CONF.format(d=self.chrony))
        open(self.p("sources.d", "ubuntu-ntp-pools.sources"), "w").write(POOLS)
        self.apply("chrony")
        with redirect_stdout(io.StringIO()):
            self.m.restore_time([])
        self.assertEqual(os.listdir(self.p("sources.d")), ["ubuntu-ntp-pools.sources"])

    def test_chrony_browser_mode_has_no_servers(self):
        open(self.p("chrony.conf"), "w").write(UBUNTU_CONF.format(d=self.chrony))
        open(self.p("sources.d", "ubuntu-ntp-pools.sources"), "w").write(POOLS)
        self.apply("chrony")
        _, out = self.apply("chrony", src="browser")
        self.assertEqual(os.listdir(self.p("sources.d")), ["ubuntu-ntp-pools.sources.pm-disabled"])
        self.assertIn("no servers", out)

    def test_timesyncd(self):
        open(self.p("chrony.conf"), "w").write(DEBIAN_CONF)
        svc, out = self.apply("timesyncd", server="ntp.lan")
        self.assertEqual(svc, "timesyncd")
        self.assertEqual(open(self.dropin).read(), "# written by phantom-mirage-setup\n[Time]\nNTP=ntp.lan\nFallbackNTP=\n")
        self.assertIn("systemd-timesyncd configured with server ntp.lan", out)
        self.assertEqual(open(self.p("chrony.conf")).read(), DEBIAN_CONF)  # chrony left alone

    def test_no_time_service(self):
        svc, out = self.apply("none")
        self.assertEqual(svc, "none")
        self.assertIn("no time service found", out)
        self.assertFalse(os.path.exists(self.dropin))
        self.assertEqual(os.listdir(self.p("sources.d")), [])

    def test_dry_run_writes_nothing(self):
        open(self.p("chrony.conf"), "w").write(DEBIAN_CONF)
        os.environ["PM_TIME_SERVICE"] = "chrony"
        out = io.StringIO()
        with redirect_stdout(out):
            self.m.apply_time({"time_source": "ntp", "ntp_server": "10.0.0.5", "timezone": "UTC"}, True)
        self.assertIn("dry run: time service chrony", out.getvalue())
        self.assertEqual(open(self.p("chrony.conf")).read(), DEBIAN_CONF)

    def test_chk_ntp_local_only(self):
        for ok in ("192.168.1.10", "10.1.2.3", "ntp.lan", "timehost", "clock.home.arpa"):
            self.assertIsNone(self.m.chk_ntp(ok), ok)
        own = set()
        for ok in ("192.168.1.10", "10.1.2.3", "ntp.lan", "timehost", "clock.home.arpa", "fd00::5"):
            self.assertIsNone(self.m.chk_ntp(ok, own), ok)
        for bad in ("8.8.8.8", "pool.ntp.org", "a;rm -rf /", "time.google.com"):
            self.assertIsNotNone(self.m.chk_ntp(bad, own), bad)
        for bad in ("127.0.0.1", "127.9.9.9", "::1"):
            self.assertIn("loopback address, so the sensor would ask itself", self.m.chk_ntp(bad, own), bad)
        for bad in ("localhost", "LOCALHOST"):
            self.assertIn("this sensor itself", self.m.chk_ntp(bad, own), bad)
        for bad in ("169.254.1.1", "fe80::1", "0.0.0.0", "::", "224.0.0.1", "ff02::101", "255.255.255.255"):
            self.assertIn("cannot be an NTP server", self.m.chk_ntp(bad, own), bad)
        own = {self.m.ipaddress.ip_address("192.168.1.20"), self.m.ipaddress.ip_address("fd00::20")}
        for bad in ("192.168.1.20", "fd00::20"):
            self.assertIn("an address of this sensor", self.m.chk_ntp(bad, own), bad)
        self.assertIn("no default", self.m.chk_ntp("", own))


class SetupNtpPrompt(unittest.TestCase):
    """The reconfigure prompt has no NTP default and re-asks on bad answers."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = dict(os.environ)
        os.environ.update(PM_CONSOLE_STATE=os.path.join(self.d, "st"), PM_CHRONY_DIR=os.path.join(self.d, "chrony"),
                          PM_TIMESYNCD_DROPIN=os.path.join(self.d, "ts.conf"), PM_TEST_STDIN="1",
                          PM_OWN_ADDRS="192.168.1.20 127.0.0.1 ::1")
        sys.path.insert(0, ROOT)
        spec = importlib.util.spec_from_file_location("pmsetup_p", os.path.join(ROOT, "pm-console-setup.py"))
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.euid = mock.patch.object(os, "geteuid", lambda: 1000)
        self.euid.start()
        importlib.reload(self.m.pmstore)   # STATE_DIR is read from the environment at import
        os.makedirs(self.m.pmstore.STATE_DIR, exist_ok=True)
        # a stale loopback value from an earlier install must not be offered
        self.m.pmstore.save_config(dict(self.m.pmstore.DEFAULTS, sensor_name="s1", ntp_server="127.0.0.1",
                                        time_source="ntp"))

    def tearDown(self):
        self.euid.stop()
        os.environ.clear()
        os.environ.update(self.env)
        shutil.rmtree(self.d)

    def run_setup(self, answers, argv=("--reconfigure", "--dry-run"), tty=True):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(answers)), redirect_stdout(out), \
                mock.patch.object(sys, "stderr", err), mock.patch.object(self.m, "interactive", lambda: tty):
            try:
                rc = self.m.first_run(list(argv))
            except SystemExit as e:
                rc = e.code
        return rc, out.getvalue(), err.getvalue()

    def test_reprompts_until_a_real_server(self):
        pw = "Correct-Horse-9"
        ans = "\n".join(["s1", "admin", "8443", "ntp", "", "127.0.0.1", "::1",
                         "192.168.1.20", "192.168.1.10", "UTC", "90", pw, pw]) + "\n"
        rc, out, err = self.run_setup(ans)
        self.assertEqual(rc, 0, err)
        self.assertIn("there is no default", out)
        self.assertIn("127.0.0.1 is a loopback address, so the sensor would ask itself", out)
        self.assertIn("::1 is a loopback address", out)
        self.assertIn("192.168.1.20 is an address of this sensor", out)
        self.assertIn("server 192.168.1.10", out)

    def test_empty_input_never_picks_a_value(self):
        rc, out, err = self.run_setup("s1\nadmin\n8443\nntp\n\n")
        self.assertNotEqual(rc, 0)
        self.assertIn("there is no default", out)
        self.assertNotIn("server 127.0.0.1", out)

    def test_non_interactive_fails_clearly(self):
        rc, out, err = self.run_setup("", ("--reconfigure", "--time-source", "ntp"), tty=False)
        self.assertEqual(rc, 2)
        self.assertIn("needs --ntp-server ADDRESS", err)
        self.assertIn("there is no default", err)
        rc, out, err = self.run_setup("", ("--reconfigure", "--time-source", "ntp", "--ntp-server", "127.0.0.1"), tty=False)
        self.assertEqual(rc, 2)
        self.assertIn("ntp-server: 127.0.0.1 is a loopback address", err)
        rc, out, err = self.run_setup("", ("--reconfigure", "--ntp-server", "192.168.1.20"), tty=False)
        self.assertEqual(rc, 2)
        self.assertIn("an address of this sensor", err)


if __name__ == "__main__":
    unittest.main()
