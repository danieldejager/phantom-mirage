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
        for bad in ("8.8.8.8", "pool.ntp.org", "127.0.0.1", "a;rm -rf /", "time.google.com"):
            self.assertIsNotNone(self.m.chk_ntp(bad), bad)


if __name__ == "__main__":
    unittest.main()
