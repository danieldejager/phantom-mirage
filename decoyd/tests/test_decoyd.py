"""Tests for decoyd/pm-decoyd.py: validation, rendering (golden files),
the change pipeline with a fake daemon and a fake systemctl (verify,
swap, reload, rollback order), rate limit and queue, and the socket
protocol including the SO_PEERCRED check.

A real --verify-config run is in TestRealVerify; it needs root and
PM_REAL_DAEMON=/path/to/phantom-mirage (CI builds one), else it skips.
"""
import fcntl
import importlib.util
import json
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "pm-decoyd.py")
GOLDEN = os.path.join(HERE, "golden")
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

spec = importlib.util.spec_from_file_location("pmdecoyd", SRC)
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)

NETS = [D.ipaddress.IPv4Network("10.9.0.8/29")]
BINDS = {"10.9.0.14"}
PERS = ["ws2022-fwoff", "linux-6", "cisco-ios"]
D.P["services"] = os.path.join(REPO, "decoyd", "decoy-services.json")
SVCS = D.services()

MAIN = ("create default\nset default default tcp action reset\n"
        "bind 10.9.0.14 default\ninclude /etc/phantom-mirage/decoys.conf\n")

FAKE_SYSTEMCTL = r"""#!/bin/sh
D=@D@
echo "$*" >> "$D/calls"
case "$1" in
is-active) cat "$D/active" ;;
show) case "$*" in *NeedDaemonReload*) cat "$D/ndr" 2>/dev/null || echo no ;; *) cat "$D/pid" ;; esac ;;
reload)
	case "$(cat "$D/mode")" in
	ok) exit 0 ;;
	die) echo failed > "$D/active"; echo 0 > "$D/pid"; exit 0 ;;
	newpid) echo 4242 > "$D/pid"; exit 0 ;;
	fail) exit 1 ;;
	esac ;;
restart)
	cp "$D/etc/decoys.conf" "$D/at_restart"
	if [ "$(cat "$D/restart")" = ok ]; then echo active > "$D/active"; echo 999 > "$D/pid"
	else echo failed > "$D/active"; fi ;;
esac
exit 0
"""

FAKE_DAEMON = r"""#!/bin/sh
D=@D@
echo "$*" > "$D/verify_argv"
while [ $# -gt 0 ]; do
	if [ "$1" = -f ]; then cp "$2" "$D/verify_main"; fi
	shift
done
inc=$(sed -n 's/^include //p' "$D/verify_main")
cp "$inc" "$D/verify_cand"
rc=$(cat "$D/verify_rc")
if [ "$rc" != 0 ]; then
	echo "/x.conf:3: Unknown personality \"nosuch\""
	echo "config_read: parsing configuration file failed"
fi
exit "$rc"
"""


def decoy(ip="10.9.0.9", **kw):
    d = {"ip": ip, "personality": "ws2022-fwoff",
         "defaults": {"tcp": "reset", "udp": "closed", "icmp": "open"},
         "ports": [{"proto": "tcp", "port": 22, "service": "ssh"},
                   {"proto": "udp", "port": 53, "state": "filtered"}]}
    d.update(kw)
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self._p, self._t = dict(D.P), dict(D.T)
        self.d = tempfile.mkdtemp()
        etc = os.path.join(self.d, "etc")
        os.mkdir(etc)
        os.mkdir(os.path.join(self.d, "run"))
        self.w("etc/default", "NETWORK=10.9.0.8/29\nINTERFACE=lo\n")
        self.w("etc/phantom-mirage.conf", MAIN)
        fp = "Fingerprint ws2022-fwoff\nFingerprint linux-6\nFingerprint cisco-ios\n"
        self.w("etc/columbo-v1.db", fp)
        self.w("etc/columbo-v1.db.sha256", D.hashlib.sha256(fp.encode()).hexdigest() + "  columbo-v1.db\n")
        for name, body in (("systemctl", FAKE_SYSTEMCTL), ("daemon", FAKE_DAEMON)):
            self.w(name, body.replace("@D@", self.d))
            os.chmod(self.p(name), 0o755)
        for k, v in (("active", "active"), ("pid", "100"), ("mode", "ok"),
                     ("restart", "ok"), ("verify_rc", "0"), ("calls", "")):
            self.w(k, v + ("\n" if v else ""))
        D.P.update({
            "default": self.p("etc/default"), "main_conf": self.p("etc/phantom-mirage.conf"),
            "decoys_conf": self.p("etc/decoys.conf"), "store": self.p("etc/decoys.json"),
            "fpdb": self.p("etc/columbo-v1.db"), "fpdb_sha": self.p("etc/columbo-v1.db.sha256"),
            "rundir": self.p("run"), "daemon": self.p("daemon"), "systemctl": self.p("systemctl"),
            "data": {k: self.p("etc/x" + k) for k in ("-a", "-0", "-x", "-m")},
            "console_uid": os.getuid(),
        })
        D.T.update(settle=0, restart_wait=0.5, min_interval=0, queue_wait=0.5, check_owner=False)
        self.h = D.Helper()
        self.n = 0

    def tearDown(self):
        D.P.clear(); D.P.update(self._p)
        D.T.clear(); D.T.update(self._t)
        shutil.rmtree(self.d)

    def p(self, rel):
        return os.path.join(self.d, rel)

    def w(self, rel, text):
        with open(self.p(rel), "w") as f:
            f.write(text)

    def r(self, rel):
        with open(self.p(rel)) as f:
            return f.read()

    def req(self, _op, args=None, **kw):
        self.n += 1
        q = {"v": 1, "id": "t-%d-%d" % (os.getpid(), self.n), "ts": int(time.time()),
             "actor": "admin", "op": _op, "args": args if args is not None else {}}
        q.update(kw)
        return self.h.handle(q)

    def calls(self):
        return [l.split()[0] for l in self.r("calls").splitlines()]


class TestValidation(unittest.TestCase):
    def code(self, d):
        with self.assertRaises(D.Err) as c:
            D.check_decoy(d, NETS, BINDS, PERS, SVCS)
        return c.exception.code

    def test_good(self):
        ip, d = D.check_decoy(decoy(), NETS, BINDS, PERS, SVCS)
        self.assertEqual(ip, "10.9.0.9")
        self.assertEqual([p["port"] for p in d["ports"]], [22, 53])

    def test_null_personality(self):
        D.check_decoy(decoy(personality=None), NETS, BINDS, PERS, SVCS)

    def test_table(self):
        many = [{"proto": "tcp", "port": i, "state": "open"} for i in range(1, 66)]
        cases = [
            (decoy(ip="198.51.100.7"), "E_ADDRESS_OUTSIDE_NETWORK"),
            (decoy(ip="203.0.113.9"), "E_ADDRESS_OUTSIDE_NETWORK"),
            (decoy(ip="10.9.0.8"), "E_ADDRESS_RESERVED"),
            (decoy(ip="10.9.0.15"), "E_ADDRESS_RESERVED"),
            (decoy(ip="10.9.0.14"), "E_ADDRESS_IN_MAIN_CONF"),
            (decoy(ip="010.9.0.9"), "E_INVALID_ADDRESS"),
            (decoy(ip="10.9.0.9 "), "E_INVALID_ADDRESS"),
            (decoy(ip="10.9.0.9\nbind"), "E_TYPE"),
            (decoy(ip=167772169), "E_TYPE"),
            (decoy(personality='x" \nbind 10.9.0.9 default'), "E_TYPE"),
            (decoy(personality="linux#6"), "E_TYPE"),
            (decoy(personality="nosuch"), "E_INVALID_PERSONALITY"),
            (decoy(personality="a" * 65), "E_TYPE"),
            (decoy(defaults={"tcp": "reset", "udp": "closed"}), "E_MISSING_FIELD"),
            (decoy(defaults={"tcp": "tarpit", "udp": "closed", "icmp": "open"}), "E_INVALID_STATE"),
            (decoy(defaults={"tcp": "reset", "udp": "closed", "icmp": "open", "x": "open"}), "E_UNKNOWN_FIELD"),
            (decoy(ports=many), "E_TOO_MANY_PORTS"),
            (decoy(ports={}), "E_TYPE"),
            (decoy(ports=[{"proto": "tcp", "port": 0, "state": "open"}]), "E_INVALID_PORT"),
            (decoy(ports=[{"proto": "tcp", "port": 65536, "state": "open"}]), "E_INVALID_PORT"),
            (decoy(ports=[{"proto": "tcp", "port": True, "state": "open"}]), "E_INVALID_PORT"),
            (decoy(ports=[{"proto": "tcp", "port": "22", "state": "open"}]), "E_INVALID_PORT"),
            (decoy(ports=[{"proto": "icmp", "port": 1, "state": "open"}]), "E_INVALID_PORT"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "state": "proxy 1.2.3.4:22"}]), "E_INVALID_STATE"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "state": 'open"'}]), "E_INVALID_STATE"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "service": "nosuch"}]), "E_INVALID_SERVICE"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "service": "../../bin/sh"}]), "E_INVALID_SERVICE"),
            (decoy(ports=[{"proto": "udp", "port": 22, "service": "ssh"}]), "E_INVALID_SERVICE"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "state": "open", "service": "ssh"}]), "E_MISSING_FIELD"),
            (decoy(ports=[{"proto": "tcp", "port": 22}]), "E_MISSING_FIELD"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "state": "open", "script": "x"}]), "E_UNKNOWN_FIELD"),
            (decoy(ports=[{"proto": "tcp", "port": 22, "state": "open"},
                          {"proto": "tcp", "port": 22, "state": "closed"}]), "E_INVALID_PORT"),
            (dict(decoy(), extra=1), "E_UNKNOWN_FIELD"),
            ({"ip": "10.9.0.9"}, "E_MISSING_FIELD"),
            ("10.9.0.9", "E_TYPE"),
        ]
        for d, want in cases:
            with self.subTest(d=str(d)[:80]):
                self.assertEqual(self.code(d), want)

    def test_service_list_has_no_scripts_or_backdoors(self):
        with open(D.P["services"]) as f:
            raw = json.load(f)
        for s in raw["services"]:
            self.assertEqual(set(s), {"id", "label", "proto", "port", "action"})
            self.assertEqual(s["action"], "open")
            self.assertNotIn("backdoor", (s["id"] + s["label"]).lower())

    def test_network_slash31_no_reserved(self):
        n = [D.ipaddress.IPv4Network("10.9.0.8/31")]
        self.assertEqual(D.check_ip("10.9.0.8", "ip", n, set()), "10.9.0.8")


class TestEnvelope(Base):
    def test_codes(self):
        now = int(time.time())
        cases = [
            ({"v": 2}, "E_VERSION"),
            ({"v": True}, "E_VERSION"),
            ({"extra": 1}, "E_UNKNOWN_FIELD"),
            ({"ts": now - 61}, "E_REPLAY"),
            ({"ts": "now"}, "E_TYPE"),
            ({"op": "exec"}, "E_UNKNOWN_OP"),
            ({"op": ["list"]}, "E_UNKNOWN_OP"),
            ({"id": "a b"}, "E_TYPE"),
            ({"actor": "admin\n"}, "E_TYPE"),
            ({"args": []}, "E_TYPE"),
        ]
        for extra, want in cases:
            with self.subTest(extra=extra):
                r = self.req("list", **extra)
                self.assertFalse(r["ok"])
                self.assertEqual(r["error"]["code"], want)

    def test_missing(self):
        r = self.h.handle({"v": 1, "id": "x", "ts": int(time.time()), "actor": "a", "op": "list"})
        self.assertEqual(r["error"]["code"], "E_MISSING_FIELD")

    def test_replay_survives_restart(self):
        q = {"v": 1, "id": "same-id", "ts": int(time.time()), "actor": "a", "op": "list", "args": {}}
        self.assertTrue(self.h.handle(dict(q))["ok"])
        self.assertEqual(self.h.handle(dict(q))["error"]["code"], "E_REPLAY")
        self.assertEqual(D.Helper().handle(dict(q))["error"]["code"], "E_REPLAY")

    def test_parse(self):
        for raw, want in ((b'{"v":1,"v":1}', "E_BAD_JSON"), (b"\xff\xfe", "E_BAD_JSON"),
                          (b"[1]", "E_BAD_JSON"), (b"{", "E_BAD_JSON"),
                          (b" " * (D.MAX_REQ + 1), "E_BAD_JSON")):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(D.Err) as c:
                    D.parse_request(raw)
                self.assertEqual(c.exception.code, want)

    def test_list_and_options(self):
        r = self.req("list")
        self.assertTrue(r["ok"], r)
        ips = {d["ip"]: d["source"] for d in r["result"]["decoys"]}
        self.assertEqual(ips["10.9.0.14"], "main_conf")
        self.assertEqual(ips["10.9.0.9"], "default")
        o = self.req("options")["result"]
        self.assertEqual(o["personalities"], PERS)
        self.assertIn("ssh", [s["id"] for s in o["services"]])
        self.assertEqual(self.req("list", {"x": 1})["error"]["code"], "E_UNKNOWN_FIELD")

    def test_pinned_db(self):
        self.w("etc/columbo-v1.db", "Fingerprint evil\n")
        self.assertEqual(self.req("options")["error"]["code"], "E_INTERNAL")

    def test_no_include_line(self):
        self.w("etc/phantom-mirage.conf", "create default\n")
        self.assertEqual(self.req("list")["error"]["code"], "E_INTERNAL")


class TestRender(unittest.TestCase):
    def store(self):
        _, d9 = D.check_decoy(decoy(), NETS, BINDS, PERS, SVCS)
        _, d10 = D.check_decoy(decoy(ip="10.9.0.10", personality=None, ports=[]), NETS, BINDS, PERS, SVCS)
        return {"v": 1, "conf_sha256": None, "overrides": {
            "10.9.0.11": {"rev": 1, "state": "stopped", "decoy": None},
            "10.9.0.9": {"rev": 3, "state": "running", "decoy": d9},
            "10.9.0.10": {"rev": 2, "state": "stopped", "decoy": d10},
            "10.9.0.12": {"rev": 1, "state": "running", "decoy": d10},
        }}

    def golden(self, name, text):
        path = os.path.join(GOLDEN, name)
        if os.environ.get("PM_REGEN_GOLDEN"):
            with open(path, "w") as f:
                f.write(text)
        with open(path) as f:
            self.assertEqual(text, f.read())

    def test_mixed(self):
        self.golden("mixed.conf", D.render(self.store(), SVCS))

    def test_empty(self):
        self.golden("empty.conf", D.render(D.empty_store(), SVCS))

    def test_bad_store_refused(self):
        s = self.store()
        s["overrides"]["10.9.0.9"]["decoy"]["personality"] = 'x"\nbind'
        with self.assertRaises(D.Err):
            D.render(s, SVCS)
        s = self.store()
        s["overrides"]["10.9.0.9 x"] = s["overrides"].pop("10.9.0.9")
        with self.assertRaises(ValueError):
            D.render(s, SVCS)

    def test_ops(self):
        s = D.empty_store()
        a = lambda op, args: D.apply_op(op, args, s, NETS, BINDS, PERS, SVCS)
        s, r = a("stop", {"ip": "10.9.0.9"})
        self.assertEqual(r["arp"], "still_answered")
        self.assertEqual(s["overrides"]["10.9.0.9"], {"rev": 1, "state": "stopped", "decoy": None})
        with self.assertRaises(D.Err) as c:
            a("start", {"ip": "10.9.0.9", "expect_rev": 0})
        self.assertEqual(c.exception.code, "E_CONFLICT")
        s, r = a("start", {"ip": "10.9.0.9", "expect_rev": 1})
        self.assertEqual(s["overrides"], {})
        s, _ = a("add", {"decoy": decoy()})
        with self.assertRaises(D.Err) as c:
            a("add", {"decoy": decoy()})
        self.assertEqual(c.exception.code, "E_EXISTS")
        s, r = a("edit", {"decoy": decoy(personality="linux-6"), "expect_rev": 1})
        self.assertEqual(r["rev"], 2)
        s, r = a("stop", {"ip": "10.9.0.9", "expect_rev": 2})
        self.assertEqual(s["overrides"]["10.9.0.9"]["decoy"]["personality"], "linux-6")
        with self.assertRaises(D.Err) as c:
            a("stop", {"ip": "10.9.0.9", "expect_rev": 3})
        self.assertEqual(c.exception.code, "E_NOT_RUNNING")
        s, _ = a("start", {"ip": "10.9.0.9", "expect_rev": 3})
        self.assertEqual(s["overrides"]["10.9.0.9"]["state"], "running")
        with self.assertRaises(D.Err) as c:
            a("reset", {"ip": "10.9.0.10"})
        self.assertEqual(c.exception.code, "E_NOT_FOUND")
        with self.assertRaises(D.Err) as c:
            a("stop", {"ip": "10.9.0.14"})
        self.assertEqual(c.exception.code, "E_ADDRESS_IN_MAIN_CONF")
        with self.assertRaises(D.Err) as c:
            a("reset_all", {"confirm": "yes"})
        s, _ = a("reset_all", {"confirm": "reset-all"})
        self.assertEqual(s["overrides"], {})


class TestPipeline(Base):
    def test_add_reload(self):
        r = self.req("add", {"decoy": decoy()})
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["reloaded"])
        self.assertFalse(r["rolled_back"])
        live = self.r("etc/decoys.conf")
        self.assertIn("bind 10.9.0.9 pm_d_10_9_0_9", live)
        self.assertEqual(self.r("verify_cand"), live)
        self.assertFalse(os.path.exists(self.p("etc/decoys.conf.new")))
        self.assertFalse(os.path.exists(self.p("etc/.pm-decoyd-verify.conf")))
        store = json.loads(self.r("etc/decoys.json"))
        self.assertEqual(store["conf_sha256"], D.sha(live))
        self.assertEqual(os.stat(self.p("etc/decoys.json")).st_mode & 0o777, 0o600)
        self.assertEqual(self.calls(), ["is-active", "show", "reload", "is-active", "show"])
        # the temp main config is the real one with only the include rewritten
        vm = self.r("verify_main").splitlines()
        self.assertEqual(vm[:3], MAIN.splitlines()[:3])
        self.assertEqual(vm[3], "include " + self.p("etc/decoys.conf.new"))
        argv = self.r("verify_argv").split()
        self.assertEqual(argv[0], "--verify-config")
        self.assertIn("-p", argv)
        self.assertEqual(argv[-3:], ["-i", "lo", "10.9.0.8/29"])
        # second change keeps the previous file
        r = self.req("stop", {"ip": "10.9.0.9", "expect_rev": 1})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.r("etc/decoys.conf.prev"), live)
        self.assertIn("pm_s_10_9_0_9", self.r("etc/decoys.conf"))

    def test_sensor_not_running(self):
        self.w("active", "inactive\n")
        r = self.req("add", {"decoy": decoy()})
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["reloaded"])
        self.assertEqual(self.calls(), ["is-active"])
        self.assertTrue(os.path.exists(self.p("etc/decoys.json")))

    def test_verify_failed(self):
        self.w("etc/decoys.conf", D.HEADER)
        self.w("verify_rc", "1\n")
        r = self.req("add", {"decoy": decoy()})
        self.assertEqual(r["error"]["code"], "E_VERIFY_FAILED")
        self.assertIn("Unknown personality", r["error"]["message"])
        self.assertFalse(r["reloaded"])
        self.assertEqual(self.r("etc/decoys.conf"), D.HEADER)
        self.assertFalse(os.path.exists(self.p("etc/decoys.conf.new")))
        self.assertFalse(os.path.exists(self.p("etc/decoys.json")))
        self.assertEqual(self.calls(), [])

    def _rollback(self, mode, restart):
        self.w("etc/decoys.conf", D.HEADER)
        self.w("mode", mode + "\n")
        self.w("restart", restart + "\n")
        r = self.req("add", {"decoy": decoy()})
        self.assertFalse(r["ok"])
        self.assertTrue(r["reloaded"])
        self.assertTrue(r["rolled_back"])
        # restored BEFORE the restart (RestartPreventExitStatus=78)
        self.assertEqual(self.r("at_restart"), D.HEADER)
        self.assertEqual(self.r("etc/decoys.conf"), D.HEADER)
        self.assertFalse(os.path.exists(self.p("etc/decoys.json")))
        self.assertIn("restart", self.calls())
        return r["error"]["code"]

    def test_rollback_daemon_died(self):
        self.assertEqual(self._rollback("die", "ok"), "E_RELOAD_FAILED_ROLLED_BACK")

    def test_rollback_new_pid(self):
        self.assertEqual(self._rollback("newpid", "ok"), "E_RELOAD_FAILED_ROLLED_BACK")

    def test_rollback_reload_rc(self):
        self.assertEqual(self._rollback("fail", "ok"), "E_RELOAD_FAILED_ROLLED_BACK")

    def test_rollback_failed(self):
        self.assertEqual(self._rollback("die", "fail"), "E_ROLLBACK_FAILED")

    def test_rollback_with_no_previous_file(self):
        self.w("mode", "die\n")
        r = self.req("add", {"decoy": decoy()})
        self.assertEqual(r["error"]["code"], "E_RELOAD_FAILED_ROLLED_BACK")
        self.assertEqual(self.r("etc/decoys.conf"), D.HEADER)

    def test_hand_edit_conflict(self):
        self.assertTrue(self.req("add", {"decoy": decoy()})["ok"])
        with open(self.p("etc/decoys.conf"), "a") as f:
            f.write("bind 10.9.0.10 default\n")
        r = self.req("reset", {"ip": "10.9.0.9", "expect_rev": 1})
        self.assertEqual(r["error"]["code"], "E_CONFLICT")
        self.assertIn("sudo rm /var/lib/phantom-mirage/decoys.json", r["error"]["message"])
        r = self.req("reset_all", {"confirm": "reset-all"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(self.r("etc/decoys.conf"), D.HEADER)

    def test_rate_limit_and_queue(self):
        D.T.update(min_interval=0.6, queue_wait=1.0)
        self.assertTrue(self.req("add", {"decoy": decoy()})["ok"])
        t0 = time.monotonic()
        self.assertTrue(self.req("stop", {"ip": "10.9.0.9", "expect_rev": 1})["ok"])
        self.assertGreater(time.monotonic() - t0, 0.4)   # queued, not refused
        # a last reload stamp in the future (clock moved back) still waits
        # at most min_interval, then applies: there is no rate limit refusal
        self.w("run/last_reload", "%f" % (time.time() + 1000))
        t0 = time.monotonic()
        self.assertTrue(self.req("start", {"ip": "10.9.0.9", "expect_rev": 2})["ok"])
        self.assertLess(time.monotonic() - t0, 2.0)
        with open(SRC) as f:
            self.assertNotIn("E_RATE_LIMIT", f.read())

    def test_busy(self):
        D.T.update(queue_wait=0.3)
        fd = os.open(self.p("run/lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            r = self.req("add", {"decoy": decoy()})
        finally:
            os.close(fd)
        self.assertEqual(r["error"]["code"], "E_BUSY")
        self.assertTrue(self.req("add", {"decoy": decoy()})["ok"])

    def test_symlinked_candidate_not_followed(self):
        os.symlink(self.p("victim"), self.p("etc/decoys.conf.new"))
        self.assertTrue(self.req("add", {"decoy": decoy()})["ok"])
        self.assertFalse(os.path.exists(self.p("victim")))

    def test_check_paths(self):
        D.T["check_owner"] = True
        r = self.req("add", {"decoy": decoy()})
        if os.getuid() != 0:
            self.assertEqual(r["error"]["code"], "E_INTERNAL")


def ifc(*a):
    return [D.ipaddress.IPv4Interface(x) for x in a]


INFO = {"ifaces": {"eth0": {"addrs": ifc("10.9.0.2/24"), "up": True, "lo": False},
                   "eth1": {"addrs": ifc("10.9.0.3/24"), "up": True, "lo": False},
                   "eth2": {"addrs": [], "up": True, "lo": False},
                   "lo": {"addrs": ifc("127.0.0.1/8"), "up": True, "lo": True}},
        "gateways": [D.ipaddress.IPv4Address("10.9.0.1")]}


def golden(name):
    with open(os.path.join(GOLDEN, name)) as f:
        return f.read()


class TestNetworkValidation(unittest.TestCase):
    def setUp(self):
        self._p = dict(D.P)
        self.sys = tempfile.mkdtemp()
        for n in INFO["ifaces"]:
            os.mkdir(os.path.join(self.sys, n))
        D.P["sysfs_net"] = self.sys

    def tearDown(self):
        D.P.clear(); D.P.update(self._p)
        shutil.rmtree(self.sys)

    def code(self, net, iface="eth0", info=INFO):
        with self.assertRaises(D.Err) as c:
            D.check_network(net, iface, info)
        return c.exception.code, c.exception.message

    def test_good(self):
        for n in ("10.9.0.8/29", "10.9.0.64/26", "10.9.0.200/32", "10.9.0.32/28"):
            self.assertEqual(str(D.check_network(n, "eth0", INFO)[0]), n)

    def test_format(self):
        for n in ("10.9.0.8", "10.9.0.8/29 10.9.0.16/29", "10.9.0.8/29;reboot", "x", "10.9.0.256/29",
                  "10.9.0.8/33", "::1/128", "$(id)", ""):
            self.assertIn(self.code(n)[0], ("E_INVALID_NETWORK", "E_TYPE", "E_INVALID_VALUE", "E_TOO_LONG"), n)

    def test_host_bits_suggests(self):
        c, m = self.code("10.9.0.9/29")
        self.assertEqual(c, "E_INVALID_NETWORK")
        self.assertIn("10.9.0.8/29", m)

    def test_too_wide(self):
        self.assertEqual(self.code("10.9.0.0/23")[0], "E_NETWORK_TOO_WIDE")
        self.assertEqual(self.code("10.0.0.0/8")[0], "E_NETWORK_TOO_WIDE")

    def test_not_private(self):
        info = {"ifaces": {"eth0": {"addrs": ifc("8.8.8.2/24"), "up": True, "lo": False}}, "gateways": []}
        self.assertEqual(self.code("8.8.8.8/29", info=info)[0], "E_NOT_PRIVATE")
        self.assertEqual(self.code("172.32.0.8/29", info=info)[0], "E_NOT_PRIVATE")

    def test_interface(self):
        self.assertEqual(self.code("10.9.0.8/29", "eth9")[0], "E_INVALID_INTERFACE")
        self.assertEqual(self.code("10.9.0.8/29", "lo")[0], "E_INVALID_INTERFACE")
        self.assertEqual(self.code("10.9.0.8/29", "eth2")[0], "E_INVALID_INTERFACE")
        self.assertIn(self.code("10.9.0.8/29", "eth0;x")[0], ("E_INVALID_VALUE", "E_TYPE"))

    def test_not_on_lan(self):
        self.assertEqual(self.code("192.168.7.8/29")[0], "E_NOT_ON_LAN")

    def test_own_address_and_gateway(self):
        c, m = self.code("10.9.0.0/30")
        self.assertIn(c, ("E_HOST_ADDRESS", "E_GATEWAY"))
        self.assertEqual(self.code("10.9.0.0/31")[0], "E_GATEWAY")   # 10.9.0.0 and .1, .1 is the gateway
        self.assertEqual(self.code("10.9.0.2/32")[0], "E_HOST_ADDRESS")
        self.assertEqual(self.code("10.9.0.3/32")[0], "E_HOST_ADDRESS")   # other interface's address
        self.assertEqual(self.code("10.9.0.0/24")[0], "E_HOST_ADDRESS")

    def test_lan_edge(self):
        self.assertEqual(self.code("10.9.0.255/32")[0], "E_LAN_EDGE")
        self.assertEqual(self.code("10.9.0.248/29")[0], "E_LAN_EDGE")

    def test_retarget(self):
        st = {"v": 1, "conf_sha256": None, "overrides": {
            "10.9.0.33": {"stopped": True}, "10.9.0.9": {"stopped": True},
            "10.9.0.32": {"stopped": True}, "10.9.0.47": {"stopped": True}, "10.9.0.40": {"stopped": True}}}
        new, dropped = D.retarget_store(st, D.ipaddress.IPv4Network("10.9.0.32/28"))
        self.assertEqual(dropped, ["10.9.0.9", "10.9.0.32", "10.9.0.47"])
        self.assertEqual(sorted(new["overrides"]), ["10.9.0.33", "10.9.0.40"])
        self.assertEqual(len(st["overrides"]), 5)   # input untouched

    def test_rewrite_golden(self):
        self.assertEqual(D.rewrite_default(golden("default-before.txt"), "10.9.0.32/28", "eth1"),
                         golden("default-after.txt"))
        self.assertEqual(D.rewrite_default(golden("farpd-before.txt"), "10.9.0.32/28", "eth1"),
                         golden("farpd-after.txt"))

    def test_rewrite_needs_one_each(self):
        for t in ("INTERFACE=eth0\n", "NETWORK=a\nNETWORK=b\nINTERFACE=eth0\n", ""):
            with self.assertRaises(D.Err):
                D.rewrite_default(t, "10.9.0.32/28", "eth1")

    def test_host_info_parses_ip_json(self):
        d = tempfile.mkdtemp()
        try:
            ip = os.path.join(d, "ip")
            with open(ip, "w") as f:
                f.write("#!/bin/sh\ncase \"$3\" in\naddr) cat <<'X'\n"
                        '[{"ifname":"lo","flags":["LOOPBACK","UP"],"addr_info":[{"local":"127.0.0.1","prefixlen":8}]},'
                        '{"ifname":"eth0","flags":["UP"],"addr_info":[{"local":"10.9.0.2","prefixlen":24}]},'
                        '{"ifname":"bad name","flags":[],"addr_info":[]}]\nX\n;;\n'
                        "route) echo '[{\"dst\":\"default\",\"gateway\":\"10.9.0.1\"}]' ;;\nesac\n")
            os.chmod(ip, 0o755)
            D.P["ip"] = ip
            info = D.host_info()
            self.assertEqual(sorted(info["ifaces"]), ["eth0", "lo"])
            self.assertTrue(info["ifaces"]["lo"]["lo"])
            self.assertEqual([str(a) for a in info["ifaces"]["eth0"]["addrs"]], ["10.9.0.2/24"])
            self.assertEqual([str(g) for g in info["gateways"]], ["10.9.0.1"])
            D.P["ip"] = os.path.join(d, "missing")
            self.assertEqual(D.host_info(), {"ifaces": {}, "gateways": []})
        finally:
            shutil.rmtree(d)


class TestSetNetwork(Base):
    def setUp(self):
        super().setUp()
        self.w("etc/default", golden("default-before.txt"))
        self.w("etc/farpd", golden("farpd-before.txt"))
        os.mkdir(self.p("sys"))
        for n in INFO["ifaces"]:
            os.mkdir(self.p("sys/" + n))
        D.P.update(farpd_default=self.p("etc/farpd"), sysfs_net=self.p("sys"), journal=self.p("etc/netchange.journal"),
                   outcome=self.p("etc/netchange.last"))
        self._hi = D.host_info
        D.host_info = lambda: INFO
        # a stopped override that stays and one that is dropped
        for ip in ("10.9.0.9", "10.9.0.10"):
            self.assertTrue(self.req("stop", {"ip": ip, "expect_rev": 0})["ok"])
        self.w("calls", "")

    def tearDown(self):
        D.host_info = self._hi
        super().tearDown()

    def setnet(self, net="10.9.0.32/28", iface="eth1", expect=("10.9.0.8/29", "eth0")):
        return self.req("set_network", {"network": net, "interface": iface,
                                        "expect": {"network": expect[0], "interface": expect[1]}})

    def test_netinfo(self):
        r = self.req("netinfo")
        self.assertTrue(r["ok"])
        res = r["result"]
        self.assertEqual((res["network"], res["interface"]), ("10.9.0.8/29", "eth0"))
        self.assertEqual([i["name"] for i in res["interfaces"]], ["eth0", "eth1"])
        self.assertEqual(res["gateways"], ["10.9.0.1"])

    def test_success(self):
        self.w("etc/decoys.json", self.r("etc/decoys.json").replace('"10.9.0.10"', '"10.9.0.10"'))
        st = json.loads(self.r("etc/decoys.json"))
        st["overrides"]["10.9.0.33"] = st["overrides"].pop("10.9.0.9")
        st["overrides"]["10.9.0.33"]["ip"] = "10.9.0.33" if "ip" in st["overrides"]["10.9.0.33"] else None
        if st["overrides"]["10.9.0.33"]["ip"] is None:
            del st["overrides"]["10.9.0.33"]["ip"]
        txt = D.render(st, SVCS)
        st["conf_sha256"] = D.sha(txt)
        self.w("etc/decoys.json", json.dumps(st))
        self.w("etc/decoys.conf", txt)
        r = self.setnet()
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["reloaded"])
        self.assertEqual(r["result"]["dropped"], ["10.9.0.10"])
        self.assertTrue(r["result"]["farpd"])
        self.assertEqual(self.r("etc/default"), golden("default-after.txt"))
        self.assertEqual(self.r("etc/farpd"), golden("farpd-after.txt"))
        self.assertEqual(self.r("etc/default.prev"), golden("default-before.txt"))
        self.assertEqual(sorted(json.loads(self.r("etc/decoys.json"))["overrides"]), ["10.9.0.33"])
        self.assertNotIn("10.9.0.10", self.r("etc/decoys.conf"))
        self.assertIn("10.9.0.33", self.r("at_restart"))
        argv = self.r("verify_argv")
        self.assertIn("-i eth1", argv)
        self.assertIn("10.9.0.32/28", argv)
        calls = self.r("calls").splitlines()
        self.assertIn("restart phantom-mirage.service", calls)
        i = calls.index("restart phantom-mirage.service")
        self.assertIn("reload phantom-mirage-firewall.service", calls[i:])
        self.assertIn("restart farpd.service", calls[i:])
        # follow up list sees the new block
        self.assertTrue(self.req("list")["ok"])

    def test_handwritten_farpd_untouched(self):
        self.w("etc/farpd", "INTERFACE=eth0\nNETWORK=10.9.0.8/29\n")
        r = self.setnet()
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["result"]["farpd"])
        self.assertEqual(self.r("etc/farpd"), "INTERFACE=eth0\nNETWORK=10.9.0.8/29\n")
        self.assertNotIn("restart farpd.service", self.r("calls"))

    def snapshot(self):
        return {f: self.r("etc/" + f) for f in ("default", "farpd", "decoys.conf", "decoys.json")}

    def test_restart_fails_rolls_back_before_restart(self):
        before = self.snapshot()
        # first restart fails, the restart after restore succeeds
        self.w("systemctl", self.r("systemctl").replace(
            'if [ "$(cat "$D/restart")" = ok ]',
            '[ "$2" = phantom-mirage.service ] && cp "$D/etc/default" "$D/default_at_restart_$(wc -l < "$D/calls")"\n\tif [ "$(cat "$D/restart")" = ok ]'))
        self.w("restart", "once\n")
        self.w("systemctl", self.r("systemctl").replace(
            'else echo failed > "$D/active"; fi ;;',
            'else echo failed > "$D/active"; echo ok > "$D/restart"; fi ;;'))
        r = self.setnet()
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"]["code"], "E_RESTART_FAILED_ROLLED_BACK")
        self.assertTrue(r["rolled_back"])
        self.assertEqual(self.snapshot(), before)
        snaps = sorted(f for f in os.listdir(self.d) if f.startswith("default_at_restart_"))
        self.assertEqual(len(snaps), 2)
        with open(self.p(snaps[-1])) as f:
            self.assertEqual(f.read(), before["default"])   # old block was back before the second restart

    def test_rollback_failed(self):
        before = self.snapshot()
        self.w("restart", "no\n")
        r = self.setnet()
        self.assertEqual(r["error"]["code"], "E_ROLLBACK_FAILED")
        self.assertEqual(self.snapshot(), before)

    def test_outcome_recorded_and_in_netinfo(self):
        self.assertIsNone(self.req("netinfo")["result"]["last_change"])
        r = self.setnet()
        self.assertTrue(r["ok"], r)
        lc = self.req("netinfo")["result"]["last_change"]
        self.assertEqual((lc["result"], lc["network"], lc["interface"]), ("applied", "10.9.0.32/28", "eth1"))
        self.assertEqual(lc["previous"], {"network": "10.9.0.8/29", "interface": "eth0"})
        self.assertEqual(lc["dropped"], ["10.9.0.9", "10.9.0.10"])

    def test_outcome_rolled_back_and_failed(self):
        self.w("restart", "no\n")
        self.setnet()
        lc = self.req("netinfo")["result"]["last_change"]
        self.assertEqual((lc["result"], lc["network"]), ("rollback_failed", "10.9.0.8/29"))

    def test_outcome_not_written_on_refusal(self):
        self.setnet(net="10.9.0.8/29", iface="eth0")
        self.assertIsNone(self.req("netinfo")["result"]["last_change"])

    def test_daemon_reload_only_when_stale(self):
        self.assertTrue(self.setnet()["ok"])
        self.assertNotIn("daemon-reload", self.r("calls").splitlines())
        self.w("ndr", "yes\n")
        self.w("calls", "")
        self.assertTrue(self.setnet("10.9.0.64/28", "eth1", ("10.9.0.32/28", "eth1"))["ok"])
        calls = self.r("calls").splitlines()
        self.assertLess(calls.index("daemon-reload"), calls.index("restart phantom-mirage.service"))

    def test_gateways_deduped(self):
        info = dict(INFO, gateways=[D.ipaddress.IPv4Address("10.9.0.1")] * 2)
        D.host_info = lambda: info
        self.assertEqual(self.req("netinfo")["result"]["gateways"], ["10.9.0.1"])

    def test_verify_fails_nothing_written(self):
        before = self.snapshot()
        self.w("verify_rc", "1\n")
        r = self.setnet()
        self.assertFalse(r["ok"])
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("restart", self.r("calls"))

    def test_inactive_sensor_not_started(self):
        self.w("active", "inactive\n")
        r = self.setnet()
        self.assertTrue(r["ok"], r)
        self.assertFalse(r["reloaded"])
        self.assertFalse(r["result"]["restarted"])
        self.assertEqual(self.r("etc/default"), golden("default-after.txt"))
        self.assertNotIn("restart phantom-mirage.service", self.r("calls"))

    def test_refusals(self):
        before = self.snapshot()
        self.assertEqual(self.setnet(expect=("10.9.0.16/29", "eth0"))["error"]["code"], "E_CONFLICT")
        self.assertEqual(self.setnet("10.9.0.8/29", "eth0")["error"]["code"], "E_UNCHANGED")
        self.assertEqual(self.setnet("10.9.0.0/29")["error"]["code"], "E_HOST_ADDRESS")
        self.assertEqual(self.setnet("10.9.0.0/22")["error"]["code"], "E_NETWORK_TOO_WIDE")
        r = self.req("set_network", {"network": "10.9.0.32/28", "interface": "eth1"})
        self.assertEqual(r["error"]["code"], "E_MISSING_FIELD")
        r = self.req("set_network", {"network": "10.9.0.32/28", "interface": "eth1", "cmd": "x",
                                     "expect": {"network": "10.9.0.8/29", "interface": "eth0"}})
        self.assertEqual(r["error"]["code"], "E_UNKNOWN_FIELD")
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("restart", self.r("calls"))

    def test_queued_behind_interval(self):
        D.T.update(min_interval=0.6, queue_wait=1)
        self.w("run/last_reload", "0")
        self.assertTrue(self.setnet()["ok"])
        t0 = time.monotonic()
        r = self.setnet("10.9.0.64/28", "eth1", ("10.9.0.32/28", "eth1"))
        self.assertTrue(r["ok"], r)
        self.assertGreater(time.monotonic() - t0, 0.4)

    def test_restart_order_firewall_then_farpd(self):
        # firewall reloaded, never restarted: a restart would restart the console (Requires=)
        self.assertTrue(self.setnet()["ok"])
        calls = [l for l in self.r("calls").splitlines() if l.startswith(("restart", "reload"))]
        self.assertEqual(calls, ["restart phantom-mirage.service", "reload phantom-mirage-firewall.service",
                                 "restart farpd.service"])

    def test_crash_mid_swap_recovered_on_next_change(self):
        before = self.snapshot()
        real, n = D.replace_file, [0]
        swaps = {self.p("etc/default"), self.p("etc/decoys.conf"), self.p("etc/decoys.json"), self.p("etc/farpd")}

        def crashing(path, data, mode):
            if path in swaps:
                n[0] += 1
                if n[0] == 3:
                    raise KeyboardInterrupt("simulated crash")
            return real(path, data, mode)
        D.replace_file = crashing
        try:
            with self.assertRaises(KeyboardInterrupt):
                self.setnet()
        finally:
            D.replace_file = real
        self.assertNotEqual(self.snapshot(), before)        # mixed files left behind
        self.assertTrue(os.path.exists(D.P["journal"]))
        self.w("calls", "")
        self.h = D.Helper()                                 # a fresh helper process
        r = self.req("stop", {"ip": "10.9.0.11"})
        self.assertTrue(r["ok"], r)
        self.assertFalse(os.path.exists(D.P["journal"]))
        after = self.snapshot()
        self.assertEqual(after["default"], before["default"])
        self.assertEqual(after["farpd"], before["farpd"])
        self.assertEqual(json.loads(after["decoys.json"])["overrides"].keys(),
                         set(json.loads(before["decoys.json"])["overrides"]) | {"10.9.0.11"})
        self.assertEqual(self.r("calls").splitlines()[1], "restart phantom-mirage.service")

    def test_recover_journal_refuses_foreign_paths(self):
        with open(D.P["journal"], "w") as f:
            json.dump({"id": "x", "files": [["/etc/passwd", True, 420]]}, f)
        with self.assertRaises(D.Err):
            D.recover_journal()
        self.assertTrue(os.path.exists(D.P["journal"]))

    def test_no_journal_after_success_or_rollback(self):
        self.assertTrue(self.setnet()["ok"])
        self.assertFalse(os.path.exists(D.P["journal"]))
        self.w("restart", "no\n")
        self.w("run/last_reload", "0")
        self.setnet("10.9.0.64/28", "eth1", ("10.9.0.32/28", "eth1"))
        self.assertFalse(os.path.exists(D.P["journal"]))


class TestSocket(Base):
    def serve(self):
        path = self.p("s.sock")
        ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        ls.bind(path)
        ls.listen(4)
        D.T["idle"] = 1.0
        out = {}
        th = threading.Thread(target=lambda: out.setdefault("rc", D.serve(ls, self.h)))
        th.start()
        return path, th, out, ls

    def send(self, path, raw):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(path)
        c.sendall(raw)
        data = b""
        while not data.endswith(b"\n"):
            chunk = c.recv(65536)
            if not chunk:
                break
            data += chunk
        c.close()
        return json.loads(data)

    def env(self, op, args=None, rid="s1"):
        return (json.dumps({"v": 1, "id": rid, "ts": int(time.time()), "actor": "admin",
                            "op": op, "args": args or {}}) + "\n").encode()

    def test_protocol(self):
        path, th, out, ls = self.serve()
        try:
            r = self.send(path, self.env("list"))
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["id"], "s1")
            r = self.send(path, self.env("add", {"decoy": decoy()}, "s2"))
            self.assertTrue(r["ok"], r)
            self.assertEqual(self.send(path, b"not json\n")["error"]["code"], "E_BAD_JSON")
            self.assertEqual(self.send(path, b'{"v":1,"v":1}\n')["error"]["code"], "E_BAD_JSON")
            self.assertEqual(self.send(path, b"x" * (D.MAX_REQ + 10) + b"\n")["error"]["code"], "E_BAD_JSON")
            D.P["console_uid"] = os.getuid() + 1
            self.assertEqual(self.send(path, self.env("list", rid="s3"))["error"]["code"], "E_PEER")
        finally:
            th.join(5)
            ls.close()
        self.assertEqual(out.get("rc"), 0)   # idle exit

    def test_main_refuses_without_socket_activation(self):
        os.environ.pop("LISTEN_PID", None)
        self.assertEqual(D.main(), 2)


@unittest.skipUnless(os.environ.get("PM_REAL_DAEMON") and os.geteuid() == 0,
                     "needs root and PM_REAL_DAEMON=/path/to/phantom-mirage")
class TestRealVerify(Base):
    """Run the built daemon's --verify-config through verify()."""

    def setUp(self):
        super().setUp()
        D.P["daemon"] = os.environ["PM_REAL_DAEMON"]
        D.P["fpdb"] = os.path.join(REPO, "fingerprints", "columbo-v1.db")
        D.P["data"] = {"-a": os.path.join(REPO, "nmap.assoc"), "-0": os.path.join(REPO, "pf.os"),
                       "-x": os.path.join(REPO, "xprobe2.conf"), "-m": os.path.join(REPO, "nmap-mac-prefixes")}
        # the Debian main config, as shipped (debian/mkconf.sh), plus the include
        out = self.p("main.conf")
        D.subprocess.run(["sh", os.path.join(REPO, "debian", "mkconf.sh"),
                          os.path.join(REPO, "config.sample"), out], check=True)
        with open(out) as f:
            self.main = f.read() + "\ninclude /etc/phantom-mirage/decoys.conf\n"

    def check(self, text):
        cand = self.p("etc/decoys.conf.new")
        with open(cand, "w") as f:
            f.write(text)
        D.verify(cand, self.main, "lo", NETS)

    def test_goldens_pass(self):
        for name in ("mixed.conf", "empty.conf"):
            with self.subTest(name=name):
                with open(os.path.join(GOLDEN, name)) as f:
                    text = f.read()
                self.check(text.replace('"ws2022-fwoff"', '"%s"' % REAL_PERSONALITY))

    def test_bad_personality_fails(self):
        with self.assertRaises(D.Err) as c:
            self.check(D.HEADER + 'create pm_d_10_9_0_9\nset pm_d_10_9_0_9 personality "nosuch"\nbind 10.9.0.9 pm_d_10_9_0_9\n')
        self.assertEqual(c.exception.code, "E_VERIFY_FAILED")

    def test_duplicate_bind_fails(self):
        self.main = self.main.replace("include /etc", "bind 10.9.0.9 default\ninclude /etc")
        with self.assertRaises(D.Err):
            with open(os.path.join(GOLDEN, "mixed.conf")) as f:
                self.check(f.read().replace('"ws2022-fwoff"', '"%s"' % REAL_PERSONALITY))


def _real_personality():
    try:
        with open(os.path.join(REPO, "fingerprints", "columbo-v1.db"), errors="replace") as f:
            for line in f:
                m = D.FP_RE.match(line)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return "unknown"


REAL_PERSONALITY = _real_personality()

if __name__ == "__main__":
    unittest.main()
