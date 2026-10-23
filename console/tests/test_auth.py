"""Unit tests for the console's auth, CSRF, lockout and hashing (#118).

Run: python3 -m unittest discover -s console/tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import pmauth  # noqa: E402


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class Hashing(unittest.TestCase):
    def test_scrypt_roundtrip_and_salt(self):
        h1 = pmauth.hash_password("correct horse battery", prefer_argon2=False)
        h2 = pmauth.hash_password("correct horse battery", prefer_argon2=False)
        self.assertTrue(h1.startswith("$scrypt$"))
        self.assertNotEqual(h1, h2, "hashes must be salted")
        self.assertNotIn("correct horse", h1)
        self.assertTrue(pmauth.verify_password("correct horse battery", h1))
        self.assertFalse(pmauth.verify_password("correct horse batterY", h1))
        self.assertEqual(pmauth.hash_scheme(h1), "scrypt")

    def test_default_scheme(self):
        h = pmauth.hash_password("correct horse battery")
        want = "argon2id" if pmauth._ARGON2 is not None else "scrypt"
        self.assertEqual(pmauth.hash_scheme(h), want)
        self.assertTrue(pmauth.verify_password("correct horse battery", h))

    def test_garbage_and_types(self):
        for bad in ("", "plain", "$scrypt$n=x$a$b", "$scrypt$n=1048576,r=8,p=1$AAAA$AAAA",
                    "$argon2id$v=19$m=1,t=1,p=1$x$y", None):
            self.assertFalse(pmauth.verify_password("x" * 12, bad or ""))
        h = pmauth.hash_password("correct horse battery", prefer_argon2=False)
        self.assertFalse(pmauth.verify_password(None, h))
        self.assertFalse(pmauth.verify_password(12345, h))

    def test_password_policy(self):
        self.assertIsNotNone(pmauth.password_problem("short", "admin"))
        self.assertIsNotNone(pmauth.password_problem("aaaaaaaaaaaaaaa", "admin"))
        self.assertIsNotNone(pmauth.password_problem("administrator", "administrator"))
        self.assertIsNone(pmauth.password_problem("Correct-Horse-9", "admin"))

    def test_dummy_verify_runs(self):
        pmauth.dummy_verify("whatever")


class Lockouts(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "lockout.json")
        self.c = Clock()

    def lk(self, **kw):
        return pmauth.Lockout(self.path, clock=self.c, **kw)

    def test_per_source_buckets(self):
        lk = self.lk(max_failures=2, lock_for=600)
        lk.failure("admin", "uid:1001")
        self.assertGreater(lk.failure("admin", "uid:1001"), 0)
        self.assertTrue(lk.locked_until("admin", "uid:1001"))
        self.assertFalse(lk.locked_until("admin", "uid:1000"), "other local user unaffected")

    def test_exponential_backoff_capped(self):
        lk = self.lk(max_failures=1, lock_for=600, lock_base=60)
        waits = []
        for _ in range(6):
            until = lk.failure("admin", "s")
            waits.append(until - self.c.t)
            self.c.t = until + 1
        self.assertEqual(waits, [60, 120, 240, 480, 600, 600])
        lk.success("admin", "s")
        self.assertEqual(lk.failure("admin", "s") - self.c.t, 60)

    def test_rate_limit_per_source(self):
        lk = self.lk(rate=2, rate_window=60)
        self.assertEqual([lk.rate_limited("uid:1001") for _ in range(3)], [False, False, True])
        self.assertFalse(lk.rate_limited("uid:1000"), "admin's bucket is separate")

    def test_peer_uid_from_proc(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "tcp"), "w") as f:
            f.write("  sl  local_address rem_address   st tx:rx tr:tm retrnsmt   uid\n")
            f.write("   0: 0100007F:20FB 0100007F:D431 01 0:0 0:0 0 998 0 1\n")
            f.write("   1: 0100007F:D431 0100007F:20FB 01 0:0 0:0 0 1001 0 2\n")
        self.assertEqual(pmauth.peer_uid(("127.0.0.1", 0xD431), ("127.0.0.1", 8443), d), 1001)
        self.assertIsNone(pmauth.peer_uid(("127.0.0.1", 1), ("127.0.0.1", 8443), d))

    def test_origin_requires_console_port(self):
        ok = lambda o: pmauth.same_origin_ok({"Origin": o} if o else {}, 8443)
        self.assertTrue(ok("https://localhost:8443"))
        self.assertTrue(ok("https://[::1]:8443"))
        self.assertFalse(ok("https://localhost:9999"))
        self.assertFalse(ok("https://localhost"))
        self.assertFalse(ok("http://localhost:8443"))
        self.assertFalse(ok("https://evil.example:8443"))
        self.assertFalse(ok(None))

    def test_locks_after_max_failures(self):
        lk = self.lk(max_failures=3, lock_for=600, lock_base=600)
        self.assertEqual(lk.failure("admin"), 0)
        self.assertEqual(lk.failure("admin"), 0)
        self.assertGreater(lk.failure("admin"), 0)
        self.assertTrue(lk.locked_until("admin"))
        self.assertFalse(lk.locked_until("other"))
        self.c.t += 601
        self.assertFalse(lk.locked_until("admin"))

    def test_window_expiry(self):
        lk = self.lk(max_failures=3, window=100)
        lk.failure("admin")
        lk.failure("admin")
        self.c.t += 101
        self.assertEqual(lk.failure("admin"), 0)

    def test_persisted_across_restart(self):
        lk = self.lk(max_failures=2)
        lk.failure("admin")
        lk.failure("admin")
        self.assertTrue(self.lk(max_failures=2).locked_until("admin"))

    def test_success_and_reset_clear(self):
        lk = self.lk(max_failures=2)
        lk.failure("admin")
        lk.success("admin")
        self.assertEqual(lk.failure("admin"), 0)
        lk.failure("admin")
        lk.reset()
        self.assertFalse(self.lk().locked_until("admin"))

    def test_rate_limit(self):
        lk = self.lk(rate=3, rate_window=60)
        self.assertEqual([lk.rate_limited() for _ in range(4)], [False, False, False, True])
        self.c.t += 61
        self.assertFalse(lk.rate_limited())

    def test_memory_bounded(self):
        lk = self.lk(window=10)
        for i in range(1200):
            lk.failure("u%d" % i)
            self.c.t += 0.1
        self.assertLess(len(lk._fail), 1100)


class SessionsCsrf(unittest.TestCase):
    def setUp(self):
        self.c = Clock()
        self.s = pmauth.Sessions(idle=100, absolute=1000, clock=self.c)

    def test_create_get_and_csrf(self):
        sid = self.s.create("admin")
        s = self.s.get(sid)
        self.assertEqual(s["user"], "admin")
        self.assertTrue(self.s.check_csrf(sid, s["csrf"]))
        self.assertFalse(self.s.check_csrf(sid, ""))
        self.assertFalse(self.s.check_csrf(sid, s["csrf"] + "x"))
        self.assertFalse(self.s.check_csrf("nope", s["csrf"]))
        other = self.s.create("admin")
        self.assertFalse(self.s.check_csrf(other, s["csrf"]), "CSRF token is per session")

    def test_session_id_not_stored_in_clear(self):
        sid = self.s.create("admin")
        self.assertNotIn(sid, repr(self.s.__dict__))

    def test_idle_timeout(self):
        sid = self.s.create("admin")
        self.c.t += 50
        self.assertIsNotNone(self.s.get(sid))
        self.c.t += 101
        self.assertIsNone(self.s.get(sid))

    def test_absolute_timeout(self):
        sid = self.s.create("admin")
        for _ in range(12):
            self.c.t += 90
            self.s.get(sid)
        self.assertIsNone(self.s.get(sid))

    def test_destroy(self):
        a, b = self.s.create("admin"), self.s.create("admin")
        self.s.destroy(a)
        self.assertIsNone(self.s.get(a))
        self.assertIsNotNone(self.s.get(b))
        self.s.destroy_user("admin")
        self.assertIsNone(self.s.get(b))
        self.assertIsNone(self.s.get(None))


class SameOrigin(unittest.TestCase):
    def ok(self, **h):
        return pmauth.same_origin_ok({k.replace("_", "-"): v for k, v in h.items()}, 8443)

    def test_origin(self):
        self.assertTrue(self.ok(Origin="https://localhost:8443"))
        self.assertFalse(self.ok(Origin="https://127.0.0.1:9443"))  # must be the console port (#120)
        self.assertFalse(self.ok())
        self.assertFalse(self.ok(Origin="https://evil.example"))
        self.assertFalse(self.ok(Origin="http://localhost:8443"))
        self.assertFalse(self.ok(Origin="null"))

    def test_fetch_site(self):
        self.assertFalse(self.ok(Origin="https://localhost:8443", Sec_Fetch_Site="cross-site"))
        self.assertFalse(self.ok(Origin="https://localhost:8443", Sec_Fetch_Site="same-site"))
        self.assertTrue(self.ok(Origin="https://localhost:8443", Sec_Fetch_Site="same-origin"))


if __name__ == "__main__":
    unittest.main()
