"""Clock-set cap, clock-jump guard and retention cleanup (#120)."""
import importlib.util
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
TMP = tempfile.mkdtemp()
sys.path.insert(0, ROOT)
import pmstore  # noqa: E402

spec = importlib.util.spec_from_file_location("pmconsole_c", os.path.join(ROOT, "pm-console.py"))
pmc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pmc)
DAY = 86400


class Clk:
    def __init__(self):
        self.w, self.m = 2_000_000_000.0, 1000.0

    def wall(self):
        return self.w

    def mono(self):
        return self.m

    def tick(self, s):
        self.w += s
        self.m += s


def mk(c, ages_days):
    e = pmstore.AlertEngine(event_log=os.path.join(TMP, "none.jsonl"), wall=c.wall, mono=c.mono)
    e.prune_paused, e.pause_reason = False, ""
    e.alerts = [{"id": i, "src": "x", "last_t": c.w - d * DAY, "status": "Open"}
                for i, d in enumerate(ages_days)]
    return e


class Guard(unittest.TestCase):
    def setUp(self):
        self._sd = pmstore.STATE_DIR
        pmstore.STATE_DIR = tempfile.mkdtemp(dir=TMP)
        self.addCleanup(setattr, pmstore, "STATE_DIR", self._sd)
        self.c = Clk()
        self.cfg = {"alert_retention_days": 90}

    def test_normal_prune_every_10_min(self):
        e = mk(self.c, [1, 100])
        e.poll(self.cfg)
        self.assertEqual(len(e.alerts), 1, "old alert pruned")
        e.alerts.append({"id": 9, "src": "y", "last_t": self.c.w - 200 * DAY, "status": "Open"})
        self.c.tick(2)
        e.poll(self.cfg)
        self.assertEqual(len(e.alerts), 2, "not pruned again within 10 min")
        self.c.tick(pmstore.PRUNE_EVERY)
        e.poll(self.cfg)
        self.assertEqual(len(e.alerts), 1)

    def test_jump_pauses_cleanup(self):
        e = mk(self.c, [1, 10, 60])
        self.c.w += 100 * DAY          # wall jumps, monotonic does not
        self.c.m += 2
        e.poll(self.cfg)
        self.assertTrue(e.prune_paused)
        self.assertEqual(len(e.alerts), 3, "nothing wiped after a jump")
        self.c.tick(pmstore.PRUNE_EVERY * 10)
        e.poll(self.cfg)
        self.assertEqual(len(e.alerts), 3, "still paused")

    def test_resume_after_admin_or_24h(self):
        e = mk(self.c, [1])
        e.note_clock_set(3600)
        self.assertTrue(e.prune_paused)
        self.assertTrue(e.resume_pruning("admin"))
        self.assertFalse(e.prune_paused)
        e.note_clock_set(-3600)
        self.c.tick(pmstore.STABLE_RESUME + 1)
        e.poll(self.cfg)
        self.assertFalse(e.prune_paused, "24 h of stable clock resumes cleanup")

    def test_small_step_does_not_pause(self):
        e = mk(self.c, [1])
        e.note_clock_set(30)
        self.assertFalse(e.prune_paused)

    def test_future_clock_never_wipes_recent(self):
        e = mk(self.c, [0, 5, 30])
        self.c.w += 200 * DAY          # even without jump detection
        self.assertEqual(e.prune(self.cfg), 0)
        self.assertEqual(len(e.alerts), 3)


class FakeHandler:
    clock_from_browser = pmc.Handler.clock_from_browser

    def __init__(self, engine):
        class A:
            pass
        self.app = A()
        self.app.cfg = {"time_source": "browser"}
        self.app.alerts = engine
        self.app.clock_refused = ""


class BrowserClock(unittest.TestCase):
    def setUp(self):
        self._sd = pmstore.STATE_DIR
        pmstore.STATE_DIR = tempfile.mkdtemp(dir=TMP)
        self.addCleanup(setattr, pmstore, "STATE_DIR", self._sd)
        self.sets = []
        self.orig = time.clock_settime
        time.clock_settime = lambda clk, t: self.sets.append(t)

    def tearDown(self):
        time.clock_settime = self.orig

    def test_refuses_over_24h_and_audits(self):
        e = mk(Clk(), [1])
        h = FakeHandler(e)
        w = h.clock_from_browser("admin", (time.time() + 100 * DAY) * 1000)
        self.assertIn("not applied", w)
        self.assertEqual(self.sets, [])
        self.assertTrue(h.app.clock_refused)
        last = pmstore.read_audit()[0]
        self.assertEqual((last["action"], last["ok"]), ("clock-set", False))
        self.assertIn("refused", last["detail"])
        self.assertIn("browser", last["detail"])

    def test_applies_within_24h_and_pauses(self):
        e = mk(Clk(), [1])
        h = FakeHandler(e)
        self.assertIsNone(h.clock_from_browser("admin", (time.time() + 7200) * 1000))
        self.assertEqual(len(self.sets), 1)
        self.assertTrue(e.prune_paused, "a 2 h step pauses cleanup")
        rec = [r for r in pmstore.read_audit() if r["action"] == "clock-set"][0]
        self.assertIn("->", rec["detail"])
        self.assertIn("delta +7200s", rec["detail"])


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
