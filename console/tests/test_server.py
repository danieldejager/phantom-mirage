"""Integration test: the console daemon on a random loopback port with a
temporary state dir and certificate (no root, no systemd)."""
import http.client
import importlib.util
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
TMP = tempfile.mkdtemp()
os.environ.update(PM_CONSOLE_STATE=os.path.join(TMP, "st"), PM_DEFAULT=os.path.join(TMP, "default"),
                  PM_SENSOR_CONF=os.path.join(TMP, "pm.conf"), PM_EVENT_LOG=os.path.join(TMP, "ev.jsonl"))
sys.path.insert(0, ROOT)
import pmauth  # noqa: E402
import pmstore  # noqa: E402

# another test module may have imported pmstore first: point it here
pmstore.STATE_DIR, pmstore.SENSOR_DEFAULT = os.environ["PM_CONSOLE_STATE"], os.environ["PM_DEFAULT"]
pmstore.SENSOR_CONF, pmstore.EVENT_LOG = os.environ["PM_SENSOR_CONF"], os.environ["PM_EVENT_LOG"]

spec = importlib.util.spec_from_file_location("pmconsole", os.path.join(ROOT, "pm-console.py"))
pmc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pmc)
PW = "Correct-Horse-9"


def setUpModule():
    global httpd, PORT
    os.makedirs(pmstore.STATE_DIR)
    with open(os.environ["PM_DEFAULT"], "w") as f:
        f.write('INTERFACE=eth9\nNETWORK="10.9.0.8/29"\n')
    with open(os.environ["PM_SENSOR_CONF"], "w") as f:
        f.write('create default\nset default personality "Linux 2.6"\nadd default tcp port 22 open\n')
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-days", "2", "-subj", "/CN=test", "-keyout", pmstore.path("key.pem"),
                    "-out", pmstore.path("cert.pem")], check=True, capture_output=True)
    cfg = dict(pmstore.DEFAULTS, sensor_name="t1")
    pmstore.save_config(cfg)
    pmstore.save_admin("admin", pmauth.hash_password(PW, prefer_argon2=False))
    httpd = pmc.make_server(pmstore.load_config(), port=0)
    PORT = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


def tearDownModule():
    httpd.shutdown()
    shutil.rmtree(TMP, ignore_errors=True)


class Client:
    def __init__(self):
        self.cookies = {}
        self.ctx = ssl._create_unverified_context()

    def req(self, method, path, body=None, csrf=None, origin="https://localhost:8443", host=None):
        c = http.client.HTTPSConnection("127.0.0.1", PORT, context=self.ctx, timeout=10)
        h = {"Host": host or "localhost:%d" % PORT}
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if origin and method == "POST":
            h["Origin"] = origin
        if csrf:
            h["X-CSRF-Token"] = csrf
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, val = v.split(";", 1)[0].split("=", 1)
                if "Max-Age=0" in v:
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = val
        self.last = r
        try:
            return r.status, json.loads(raw or b"{}")
        except ValueError:
            return r.status, raw

    def login(self, user="admin", pw=PW):
        _, s = self.req("GET", "/api/session")
        st, j = self.req("POST", "/api/login", {"username": user, "password": pw}, s["csrf"])
        return st, j


class Server(unittest.TestCase):
    def setUp(self):
        pmc.Handler.app.lockout.reset()
        pmc.Handler.app.lockout._attempts = {}

    def test_binds_loopback_only(self):
        self.assertEqual(httpd.server_address[0], "127.0.0.1")

    def test_headers_and_cookie_flags(self):
        c = Client()
        st, _ = c.req("GET", "/")
        self.assertEqual(st, 200)
        csp = c.last.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(c.last.getheader("X-Frame-Options"), "DENY")
        c.req("GET", "/api/session")
        st, _ = c.login()
        self.assertEqual(st, 200)
        sc = [v for k, v in c.last.getheaders() if k.lower() == "set-cookie" and "pm_session=" in v][0]
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, sc)
        self.assertTrue(sc.startswith("__Host-"))

    def test_dns_rebinding_host_refused(self):
        st, _ = Client().req("GET", "/api/health", host="evil.example:%d" % PORT)
        self.assertEqual(st, 421)

    def test_api_needs_session(self):
        for p in ("/api/status", "/api/alerts", "/api/audit", "/api/settings", "/api/decoys",
                  "/api/personalities"):
            self.assertEqual(Client().req("GET", p)[0], 401, p)

    def test_login_needs_pre_token(self):
        c = Client()
        self.assertEqual(c.req("POST", "/api/login", {"username": "admin", "password": PW})[0], 403)
        _, s = c.req("GET", "/api/session")
        self.assertEqual(c.req("POST", "/api/login", {"username": "admin", "password": PW}, "x" + s["csrf"])[0], 403)

    def test_csrf_and_origin_on_state_change(self):
        c = Client()
        st, j = c.login()
        self.assertEqual(st, 200)
        tok = j["csrf"]
        self.assertEqual(c.req("POST", "/api/mute", {"src": "192.0.2.9"})[0], 403)
        self.assertEqual(c.req("POST", "/api/mute", {"src": "192.0.2.9"}, "bad")[0], 403)
        self.assertEqual(c.req("POST", "/api/mute", {"src": "192.0.2.9"}, tok, origin="https://evil.example")[0], 403)
        self.assertEqual(c.req("POST", "/api/mute", {"src": "192.0.2.9"}, tok, origin=None)[0], 403)
        self.assertEqual(c.req("POST", "/api/mute", {"src": "192.0.2.9"}, tok)[0], 200)
        self.assertIn("192.0.2.9", pmstore.load_config()["muted"])
        self.assertEqual(c.req("POST", "/api/unmute", {"src": "192.0.2.9"}, tok)[0], 200)
        st, a = c.req("GET", "/api/audit")
        acts = [x["action"] for x in a["audit"]]
        self.assertIn("csrf-reject", acts)
        self.assertIn("mute", acts)

    def test_lockout_over_http(self):
        c = Client()
        for _ in range(5):
            self.assertEqual(c.login(pw="wrong-password-x")[0], 401)
        self.assertEqual(c.login()[0], 423, "locked even with the right password")
        _, a = Client().req("GET", "/api/health")

    def test_rate_limit_over_http(self):
        codes = [Client().login(user="nobody%d" % i, pw="x")[0] for i in range(12)]
        self.assertIn(429, codes)

    def test_wrong_user_same_answer(self):
        self.assertEqual(Client().login(user="root")[0], 401)

    def test_body_limits(self):
        c = Client()
        _, j = c.login()
        st, _ = c.req("POST", "/api/mute", {"src": "1" * 20000}, j["csrf"])
        self.assertEqual(st, 400)

    def test_logout_and_password_change(self):
        c = Client()
        _, j = c.login()
        c2 = Client()
        _, j2 = c2.login()
        self.assertEqual(c.req("POST", "/api/password", {"current": "nope", "new": "x"}, j["csrf"])[0], 403)
        self.assertEqual(c.req("POST", "/api/password", {"current": PW, "new": "short"}, j["csrf"])[0], 400)
        self.assertEqual(c.req("POST", "/api/password", {"current": PW, "new": "Another-Horse-7"}, j["csrf"])[0], 200)
        self.assertEqual(c2.req("GET", "/api/status")[0], 401, "other sessions signed out")
        self.assertEqual(Client().login(pw="Another-Horse-7")[0], 200)
        pmstore.save_admin("admin", pmauth.hash_password(PW, prefer_argon2=False))
        c3 = Client()
        _, j3 = c3.login()
        self.assertEqual(c3.req("POST", "/api/logout", {}, j3["csrf"])[0], 200)
        self.assertEqual(c3.req("GET", "/api/status")[0], 401)

    def test_alerts_from_event_log(self):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(os.environ["PM_EVENT_LOG"], "a") as f:
            for d, direction in (("10.9.0.9", "inbound"), ("10.9.0.10", "inbound"), ("10.9.0.11", "outbound")):
                f.write(json.dumps({"ts": now, "event": "connection.start", "proto": "tcp", "src_ip": "198.51.100.7",
                                    "dst_ip": d, "honeypot_ip": d, "dst_port": 22, "direction": direction}) + "\n")
            f.write("not json\n")
        app = pmc.Handler.app
        app.alerts.poll(app.cfg)
        c = Client()
        _, j = c.login()
        _, a = c.req("GET", "/api/alerts")
        mine = [x for x in a["alerts"] if x["src"] == "198.51.100.7"]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["severity"], "High")
        self.assertEqual(sorted(mine[0]["decoys"]), ["10.9.0.10", "10.9.0.9"])
        st, _ = c.req("POST", "/api/alerts/%d/close" % mine[0]["id"], {"note": "<b>test</b>"}, j["csrf"])
        self.assertEqual(st, 200)
        _, d = c.req("GET", "/api/decoys")
        self.assertEqual(len(d["decoys"]), 8)
        self.assertTrue(any(x["last"] for x in d["decoys"] if x["ip"] == "10.9.0.9"))

    def test_decoy_detail_and_personalities(self):
        c = Client()
        c.login()
        _, d = c.req("GET", "/api/decoys")
        x = [r for r in d["decoys"] if r["ip"] == "10.9.0.12"][0]
        self.assertEqual(x["port_states"], [{"proto": "tcp", "port": 22, "state": "open"}])
        self.assertIn("default", x)
        db = os.path.join(TMP, "fp.db")
        with open(db, "w") as f:
            f.write("Fingerprint ubuntu2404\nFingerprint ws2022-fwoff\n")
        old, pmstore.FPDB = pmstore.FPDB, db
        try:
            st, j = c.req("GET", "/api/personalities")
        finally:
            pmstore.FPDB = old
        self.assertEqual(st, 200)
        self.assertEqual(j["personalities"], ["ubuntu2404", "ws2022-fwoff"])

    def test_failed_login_keyed_by_local_uid(self):
        self.assertEqual(Client().login(pw="wrong-password-1")[0], 401)
        rec = [r for r in pmstore.read_audit() if r["action"] == "login"][0]
        self.assertIn("uid:%d" % os.getuid(), rec["detail"])

    def test_static_traversal(self):
        for p in ("/static/../pmauth.py", "/static/.hidden", "/static/%2e%2e%2fpmauth.py", "/static/x.py"):
            self.assertEqual(Client().req("GET", p)[0], 404, p)

    def raw(self, path):
        c = http.client.HTTPSConnection("127.0.0.1", PORT, context=ssl._create_unverified_context(), timeout=10)
        c.request("GET", path, headers={"Host": "localhost:%d" % PORT})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, r, body

    def test_font_and_licence_served_from_allowlist(self):
        for path, ctype in (("/static/fonts/Aldrich-Regular.woff2", "font/woff2"),
                            ("/static/fonts/Aldrich-OFL.txt", "text/plain; charset=utf-8")):
            st, r, body = self.raw(path)
            self.assertEqual(st, 200, path)
            self.assertEqual(r.getheader("Content-Type"), ctype)
            self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
            self.assertIn("font-src 'self'", r.getheader("Content-Security-Policy"))
            self.assertTrue(body)
        self.assertEqual(self.raw("/static/fonts/Aldrich-Regular.woff2")[2][:4], b"wOF2")

    def test_profile_menu(self):
        """The profile row sits at the bottom of the menu pane and opens a
        menu with the theme switch and Sign out; the old header controls are gone."""
        st, r, page = self.raw("/")
        page = page.decode() if isinstance(page, bytes) else page
        header = page[page.index("<header>"):page.index("</header>")]
        self.assertNotIn("Sign out", header)
        self.assertNotIn("data-theme-toggle", header)
        self.assertNotIn("hsensor", page)
        nav = page[page.index('<nav id="dock"'):page.index("</nav>")]
        self.assertLess(nav.index('id="nav"'), nav.index('id="prof"'))
        for k in ('id="pbtn" aria-haspopup="menu" aria-expanded="false" aria-controls="pmenu"', 'id="pmenu" role="menu"', 'role="menuitem" class="pmi" data-act="logout"', 'role="menuitemcheckbox" class="pmi" data-theme-toggle'):
            self.assertIn(k, nav)
        self.assertNotIn("style=", nav)
        d = os.path.join(os.path.dirname(__file__), "..", "static")
        js = open(os.path.join(d, "console.js")).read()
        prof = js[js.index("function profSet"):js.index('const DK = "mirage.dock"')]
        for k in ('e.key === "Escape"', '"ArrowDown"', '"ArrowUp"', '"Tab"', 'btn.setAttribute("aria-expanded"', 'close(true)', '!e.target.closest("#prof")'):
            self.assertIn(k, prof)
        self.assertNotIn("innerHTML", prof)
        self.assertNotIn("prof", js[js.index("function render()"):js.index("function card(")])
        css = open(os.path.join(d, "console.css")).read()
        self.assertIn(".prof{position:sticky;bottom:0;margin-top:auto", css)
        self.assertIn('"menuitemcheckbox" ? "aria-checked" : "aria-pressed"', open(os.path.join(d, "theme.js")).read())

    def test_theme_toggle_served_csp_unchanged(self):
        csp = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
               "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        st, r, page = self.raw("/")
        self.assertEqual(st, 200)
        self.assertEqual(r.getheader("Content-Security-Policy"), csp)
        page = page.decode()
        head = page[:page.index("</head>")]
        # theme.js runs from <head>, before the stylesheet, so there is no flash
        self.assertLess(head.index('<script src="/static/theme.js"></script>'), head.index("/static/console.css"))
        self.assertNotRegex(page, r'<script(?![^>]*\bsrc=)')
        # one toggle button in the header and one on the sign-in splash, no radio group
        # sign-in page button, plus the item in the profile menu
        self.assertEqual(page.count('class="themetg" data-theme-toggle aria-pressed="false" aria-label="Dark theme"'), 1)
        self.assertEqual(page.count('role="menuitemcheckbox" class="pmi" data-theme-toggle aria-checked="false" aria-label="Dark theme"'), 1)
        self.assertNotIn("data-theme-pick", page)
        self.assertNotIn('role="radiogroup"', page)
        st, r, js = self.raw("/static/theme.js")
        self.assertEqual(st, 200)
        self.assertEqual(r.getheader("Content-Type"), "text/javascript; charset=utf-8")
        self.assertEqual(r.getheader("Content-Security-Policy"), csp)
        js = js.decode()
        self.assertIn("localStorage", js)
        self.assertNotIn("cookie", js.lower())
        # toggle logic: same key, OS preference until a choice is stored, then explicit light/dark
        self.assertIn('KEY = "pm_theme"', js)
        self.assertIn("prefers-color-scheme: light", js)
        self.assertIn("[data-theme-toggle]", js)
        self.assertIn('aria-pressed', js)
        self.assertIn('current() === "dark" ? "light" : "dark"', js)
        self.assertIn("localStorage.setItem(KEY, mem)", js)
        self.assertNotIn("removeItem", js)
        st, r, css = self.raw("/static/console.css")
        self.assertEqual(st, 200)
        css = css.decode()
        self.assertIn(":root[data-theme=light]{", css)
        self.assertIn("@media(prefers-color-scheme:light){:root:not([data-theme=dark]){", css)
        self.assertIn(".themetg{", css)
        self.assertIn("--b1:#6C56E0;", css)       # dark primary button: white text 5.2:1
        self.assertNotIn("#A58BFF;", css)

    def test_static_only_exact_names(self):
        for p in ("/static/fonts/../pmauth.py", "/static/fonts/", "/static/fonts", "/static/fonts/x.woff2",
                  "/static/fonts/%2e%2e/console.css", "/static/fonts//Aldrich-OFL.txt",
                  "/static/./console.css", "/static/fonts/Aldrich-OFL.TXT", "/static/Aldrich-OFL.txt",
                  "/static//etc/passwd", "/static/README.md"):
            self.assertEqual(self.raw(p)[0], 404, p)
        self.assertEqual(sorted(pmc.STATIC_FILES), sorted([
            "index.html", "console.css", "console.js", "theme.js", "phantom-mirage-mark.svg", "mirage-wordmark.svg", "phantom-technologies-wordmark.svg", "phantom-mirage-mark-dark.png", "phantom-mirage-mark.png",
            "phantom-mirage-logo-light.png", "phantom-mirage-logo-dark.png",
            "fonts/Aldrich-Regular.woff2", "fonts/Aldrich-OFL.txt"]))


class FakeHelper:
    """A unix socket standing in for pm-decoyd: records requests, replies
    with self.reply (or the id echoed back with ok)."""

    def __init__(self, path):
        import socket as so
        self.path, self.reqs, self.reply = path, [], None
        self.ls = so.socket(so.AF_UNIX, so.SOCK_STREAM)
        self.ls.bind(path)
        self.ls.listen(4)
        self.ls.settimeout(0.2)
        self.stop = False
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        import socket as so
        while not self.stop:
            try:
                c, _ = self.ls.accept()
            except so.timeout:
                continue
            with c:
                buf = b""
                while not buf.endswith(b"\n"):
                    ch = c.recv(65536)
                    if not ch:
                        break
                    buf += ch
                q = json.loads(buf)
                self.reqs.append(q)
                r = dict(self.reply or {"ok": True, "result": {"echo": q["op"]},
                                        "reloaded": True, "rolled_back": False})
                r.update(v=1, id=q["id"])
                c.sendall((json.dumps(r) + "\n").encode())

    def close(self):
        self.stop = True
        self.t.join(2)
        self.ls.close()


class DecoydApi(unittest.TestCase):
    def setUp(self):
        pmc.Handler.app.lockout.reset()
        pmc.Handler.app.lockout._attempts = {}
        self.sock = os.path.join(TMP, "decoyd.sock")
        os.environ["PM_DECOYD_SOCK"] = self.sock
        self.h = FakeHelper(self.sock)
        self.c = Client()
        st, j = self.c.login()
        self.assertEqual(st, 200)
        self.csrf = j["csrf"]

    def tearDown(self):
        self.h.close()
        os.unlink(self.sock)
        os.environ.pop("PM_DECOYD_SOCK", None)

    def change(self, body, csrf=True):
        return self.c.req("POST", "/api/decoyd/change", body, self.csrf if csrf else None)

    def audit(self):
        return [a for a in pmstore.read_audit()[::-1] if a["action"].startswith("decoy-")]

    def test_reads(self):
        st, j = self.c.req("GET", "/api/decoyd/options")
        self.assertEqual((st, j["result"]["echo"]), (200, "options"))
        st, j = self.c.req("GET", "/api/decoyd/list")
        self.assertEqual((st, j["result"]["echo"]), (200, "list"))
        q = self.h.reqs[-1]
        self.assertEqual((q["v"], q["actor"], q["args"]), (1, "admin", {}))
        self.assertEqual(Client().req("GET", "/api/decoyd/list")[0], 401)

    def test_change_needs_password_csrf_and_known_op(self):
        args = {"ip": "10.9.0.9"}
        self.assertEqual(self.change({"op": "stop", "args": args, "password": PW}, csrf=False)[0], 403)
        self.assertEqual(self.change({"op": "stop", "args": args})[0], 403)
        self.assertEqual(self.change({"op": "stop", "args": args, "password": "nope"})[0], 403)
        self.assertEqual(self.change({"op": "list", "args": {}, "password": PW})[0], 400)
        self.assertEqual(self.change({"op": "set_interface", "args": {}, "password": PW})[0], 400)
        self.assertEqual(self.change({"op": "stop", "args": args, "password": PW, "network": "1.2.3.0/24"})[0], 400)
        self.assertEqual(self.h.reqs, [])
        st, j = self.change({"op": "stop", "args": args, "password": PW})
        self.assertEqual(st, 200)
        self.assertTrue(j["ok"])
        q = self.h.reqs[-1]
        self.assertEqual((q["op"], q["args"]), ("stop", args))
        self.assertNotIn("password", json.dumps(q))
        a = self.audit()
        self.assertEqual([x["ok"] for x in a[-3:]], [False, True, True])
        self.assertIn("requested 10.9.0.9", a[-2]["detail"])
        self.assertIn("sensor reloaded", a[-1]["detail"])
        self.assertNotIn(PW, json.dumps(pmstore.read_audit()))

    def test_netinfo_read(self):
        st, j = self.c.req("GET", "/api/decoyd/netinfo")
        self.assertEqual((st, j["result"]["echo"]), (200, "netinfo"))
        self.assertEqual(self.h.reqs[-1]["args"], {})
        self.assertEqual(Client().req("GET", "/api/decoyd/netinfo")[0], 401)

    def test_set_network(self):
        args = {"network": "10.9.0.32/28", "interface": "eth1",
                "expect": {"network": "10.9.0.8/29", "interface": "eth0"}}
        body = {"op": "set_network", "args": args, "password": PW}
        self.assertEqual(self.change(body, csrf=False)[0], 403)
        self.assertEqual(self.change(dict(body, password="nope"))[0], 403)
        self.assertEqual(self.h.reqs, [])
        self.h.reply = {"ok": True, "reloaded": True, "rolled_back": False,
                        "result": {"network": "10.9.0.32/28", "interface": "eth1",
                                   "dropped": ["10.9.0.10"], "farpd": True, "restarted": True}}
        st, j = self.change(body)
        self.assertEqual(st, 200, j)
        q = self.h.reqs[-1]
        self.assertEqual((q["op"], q["args"]), ("set_network", args))
        a = self.audit()
        self.assertIn("requested 10.9.0.32/28 on eth1", a[-2]["detail"])
        self.assertIn("dropped settings for 10.9.0.10", a[-1]["detail"])
        for code, want in (("E_NOT_PRIVATE", 400), ("E_HOST_ADDRESS", 400), ("E_UNCHANGED", 409),
                           ("E_RESTART_FAILED_ROLLED_BACK", 500), ("E_ROLLBACK_FAILED", 500)):
            self.h.reply = {"ok": False, "reloaded": False, "rolled_back": False,
                            "error": {"code": code, "field": "args.network", "message": "x"}}
            self.assertEqual(self.change(body)[0], want, code)

    def test_set_network_timeout_longer(self):
        import decoyclient
        self.assertGreater(decoyclient.NET_TIMEOUT, decoyclient.TIMEOUT)

    def test_wrong_password_backs_off(self):
        codes = [self.change({"op": "stop", "args": {"ip": "10.9.0.9"}, "password": "bad"})[0]
                 for _ in range(8)]
        self.assertIn(423, codes)
        self.assertEqual(self.change({"op": "stop", "args": {"ip": "10.9.0.9"}, "password": PW})[0], 423)
        self.assertEqual(self.h.reqs, [])

    def test_helper_errors_mapped(self):
        for code, want in (("E_INVALID_PERSONALITY", 400), ("E_CONFLICT", 409), ("E_BUSY", 429),
                           ("E_RELOAD_FAILED_ROLLED_BACK", 500)):
            with self.subTest(code=code):
                self.h.reply = {"ok": False, "reloaded": code.startswith("E_RELOAD"),
                                "rolled_back": code.startswith("E_RELOAD"),
                                "error": {"code": code, "field": None, "message": "x"}}
                st, j = self.change({"op": "add", "args": {"decoy": {"ip": "10.9.0.9"}}, "password": PW})
                self.assertEqual(st, want)
                self.assertEqual(j["error"]["code"], code)
        self.assertIn("rolled back", self.audit()[-1]["detail"])

    def test_helper_down(self):
        self.h.close()
        os.unlink(self.sock)
        st, j = self.c.req("GET", "/api/decoyd/list")
        self.assertEqual((st, j["error"]["code"]), (503, "E_UNAVAILABLE"))
        st, j = self.change({"op": "reset_all", "args": {"confirm": "reset-all"}, "password": PW})
        self.assertEqual((st, j["error"]["code"]), (503, "E_UNAVAILABLE"))
        self.h = FakeHelper(self.sock)


class DecoyStopStart(unittest.TestCase):
    """Stop and Start through the console with the helper's own operation
    and render code behind the socket (sim_decoyd)."""

    def setUp(self):
        import sim_decoyd
        pmc.Handler.app.lockout._attempts = {}
        with open(os.environ["PM_SENSOR_CONF"]) as f:
            self.main = f.read()
        with open(os.environ["PM_SENSOR_CONF"], "w") as f:
            f.write(self.main + "bind 10.9.0.14 default\ninclude /etc/phantom-mirage/decoys.conf\n")
        self.conf = os.path.join(TMP, "decoys.conf")
        self.old_conf, pmstore.DECOYS_CONF = pmstore.DECOYS_CONF, self.conf
        self.sock = os.path.join(TMP, "sim.sock")
        os.environ["PM_DECOYD_SOCK"] = self.sock
        self.h = sim_decoyd.SimHelper(self.sock, self.conf, "10.9.0.8/29", binds={"10.9.0.14"})
        self.c = Client()
        st, j = self.c.login()
        self.csrf = j["csrf"]

    def tearDown(self):
        self.h.close()
        pmstore.DECOYS_CONF = self.old_conf
        os.environ.pop("PM_DECOYD_SOCK", None)
        with open(os.environ["PM_SENSOR_CONF"], "w") as f:
            f.write(self.main)

    def change(self, op, args, pw=PW):
        return self.c.req("POST", "/api/decoyd/change", {"op": op, "args": args, "password": pw}, self.csrf)

    def row(self, ip):
        st, j = self.c.req("GET", "/api/decoys")
        return [r for r in j["decoys"] if r["ip"] == ip][0]

    def hrow(self, ip):
        st, j = self.c.req("GET", "/api/decoyd/list")
        return [r for r in j["result"]["decoys"] if r["ip"] == ip][0]

    def test_stop_then_start_default_decoy(self):
        self.assertEqual(self.row("10.9.0.10")["template"], "default")
        self.assertEqual(self.hrow("10.9.0.10")["source"], "default")
        st, j = self.change("stop", {"ip": "10.9.0.10"})
        self.assertEqual(st, 200, j)
        self.assertEqual((j["result"]["state"], j["result"]["arp"]), ("stopped", "still_answered"))
        r = self.row("10.9.0.10")
        self.assertEqual(r["template"], "pm_s_10_9_0_10")
        self.assertEqual(r["ports"], [])
        self.assertEqual(r["default"], {"tcp": "block", "udp": "block", "icmp": "block"})
        self.assertEqual(self.row("10.9.0.11")["template"], "default")
        h = self.hrow("10.9.0.10")
        self.assertEqual((h["state"], h["rev"]), ("stopped", 1))
        st, j = self.change("stop", {"ip": "10.9.0.10", "expect_rev": 1})
        self.assertEqual((st, j["error"]["code"]), (409, "E_NOT_RUNNING"))
        st, j = self.change("start", {"ip": "10.9.0.10", "expect_rev": 0})
        self.assertEqual((st, j["error"]["code"]), (409, "E_CONFLICT"))
        st, j = self.change("start", {"ip": "10.9.0.10", "expect_rev": 1})
        self.assertEqual(st, 200, j)
        self.assertEqual(self.row("10.9.0.10")["template"], "default")
        self.assertEqual(self.hrow("10.9.0.10")["source"], "default")
        with open(self.conf) as f:
            self.assertNotIn("bind", f.read())

    def test_dashboard_drilldown(self):
        """Dashboard chart parts open Activity with matching filters; they are
        keyboard reachable and the time window shows as a clearable chip."""
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "console.js")) as f:
            js = f.read()
        for k in ('data-drill="proto"', 'data-drill="win"', 'data-drill="${id === "dbd" ? "decoy" : "src"}"', 'data-drill="${id}"'):
            self.assertIn(k, js)
        self.assertIn("Show ${p} events in Activity", js)
        d = js[js.index("function drill("):js.index("function topN")]
        for k in ("F.proto = v", "F.decoy = v", "F.src = v", "F.from = +el.dataset.from", 'go("Alerts")', 'go("Decoys")', 'go("Activity")'):
            self.assertIn(k, d)
        self.assertIn('(e.key === "Enter" || e.key === " ") && e.target.closest && e.target.closest("[data-drill]")', js)
        self.assertIn("(!F.from || inWin(e.ts))", js)
        self.assertIn('data-act="winclear"', js)
        self.assertIn('case "winclear": F.from = F.to = 0; $("fwinrow").innerHTML = ""; rt();', js)
        self.assertIn('data-act="fclear"', js)
        self.assertNotIn("style=", js[js.index("function winChip"):js.index("function Activity")])
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "console.css")) as f:
            css = f.read()
        self.assertIn("[data-drill]{cursor:pointer}", css)
        self.assertIn("[data-drill]:focus-visible", css)

    def test_dashboard_page(self):
        """Dashboard is the landing page: SVG metrics that a live refresh
        updates in place, then the system status cards under their own heading."""
        d = os.path.join(os.path.dirname(__file__), "..", "static")
        with open(os.path.join(d, "console.js")) as f:
            js = f.read()
        with open(os.path.join(d, "console.css")) as f:
            css = f.read()
        self.assertIn('cur = "Dashboard"', js)
        self.assertIn("const pages = {Dashboard, Decoys, Alerts, Activity, Settings}", js)
        self.assertNotIn('"Status"', js)
        self.assertIn('else if (cur === "Dashboard" && $("dash")) dashUpdate();', js)
        for i in ('id="dline"', 'id="donut"', 'barSlots("dbd"', 'barSlots("dbs"', 'kpi("kev"', 'kpi("kal"', 'kpi("kdc"', 'kpi("ksrc"', 'class="pulse"', '<h2 id="sysh">System status</h2>'):
            self.assertIn(i, js)
        dash = js[js.index("function dashMetrics"):js.index("function Decoys")]
        self.assertNotIn("style=", dash)
        self.assertNotIn(".style", dash)
        self.assertIn('role="img"', dash)
        self.assertIn("aria-label", dash)
        self.assertIn("No connections in the last hour", dash)
        upd = js[js.index("function dashUpdate"):js.index("function Decoys")]
        self.assertNotIn("innerHTML = dashMetrics", upd)
        self.assertIn("prefers-reduced-motion: reduce", js)
        self.assertIn("@media(prefers-reduced-motion:reduce)", css)
        for card in ("Sensor clock", "Console firewall", "Decoy address block", "Last activity"):
            self.assertIn(card, js)

    def test_activity_filter_live_safe(self):
        """The live refresh must not re-render the Activity filter controls
        (that dropped focus and keystrokes); typing is debounced and Enter applies."""
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "console.js")) as f:
            js = f.read()
        self.assertIn('if (cur === "Activity" && $("fsrc")) actUpdate();', js)
        upd = js[js.index("function actUpdate"):js.index("const ACT_MAX")]
        self.assertNotIn("fsrc", upd)
        self.assertNotIn('$("main")', upd)
        self.assertIn("setTimeout(() => { F.src = v; rt(); }, 200)", js)
        self.assertIn('e.target.id === "fsrc" && e.key === "Enter"', js)
        for s in ('id="fcount"', 'id="fempty"', "No events match the filter."):
            self.assertIn(s, js)

    def test_activity_event_filter(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "console.js")) as f:
            js = f.read()
        self.assertIn('<select id="fev" aria-label="Filter by event">', js)
        self.assertIn("(!F.event || e.event === F.event)", js)
        self.assertIn('if (e.target.id === "fev") { F.event = e.target.value; rt(); }', js)
        upd = js[js.index("function actUpdate"):js.index("const ACT_MAX")]
        self.assertIn('"fev", present("event", F.event)', upd)   # rebuilt live, choice kept
        self.assertNotIn("fsrc", upd)

    def test_refusals(self):
        self.assertEqual(self.hrow("10.9.0.14")["source"], "main_conf")
        st, j = self.change("stop", {"ip": "10.9.0.14"})
        self.assertEqual((st, j["error"]["code"]), (400, "E_ADDRESS_IN_MAIN_CONF"))
        st, j = self.change("stop", {"ip": "10.9.1.1"})
        self.assertEqual((st, j["error"]["code"]), (400, "E_ADDRESS_OUTSIDE_NETWORK"))
        self.h.force = "E_BUSY"
        st, j = self.change("stop", {"ip": "10.9.0.10"})
        self.assertEqual((st, j["error"]["code"]), (429, "E_BUSY"))
        self.assertEqual(self.row("10.9.0.10")["template"], "default")

    def test_ui_stop_start(self):
        with open(os.path.join(os.path.dirname(pmstore.__file__), "static", "console.js")) as f:
            js = f.read()
        for want in ('data-act="ss"', "farpd still answers ARP", "Connections already open to this decoy are cut off",
                     '"/api/decoyd/change"', "E_BUSY:", "E_UNAVAILABLE:", "E_RELOAD_FAILED_ROLLED_BACK:",
                     "expect_rev", 'id="dpw"', 'h.source === "main_conf"', 'id="dunavail"'):
            self.assertIn(want, js)
        self.assertNotIn("Editing decoys from the console is not in this version", js)


class DecoySettings(DecoyStopStart):
    """The gear settings panel's save path: add, edit, reset."""

    def decoy(self, **kw):
        d = {"ip": "10.9.0.11", "personality": "linux-6",
             "defaults": {"tcp": "block", "udp": "closed", "icmp": "open"},
             "ports": [{"proto": "tcp", "port": 22, "service": "ssh"},
                       {"proto": "tcp", "port": 80, "state": "reset"}]}
        d.update(kw)
        return d

    def test_add_edit_reset(self):
        st, j = self.c.req("GET", "/api/decoyd/options")
        self.assertIn("linux-6", j["result"]["personalities"])
        self.assertIn("ssh", [v["id"] for v in j["result"]["services"]])
        st, j = self.change("add", {"decoy": self.decoy()})
        self.assertEqual(st, 200, j)
        r = self.row("10.9.0.11")
        self.assertEqual((r["template"], r["personality"]), ("pm_d_10_9_0_11", "linux-6"))
        self.assertEqual(r["ports"], ["tcp/22"])
        self.assertEqual(r["default"], {"tcp": "block", "udp": "closed", "icmp": "open"})
        h = self.hrow("10.9.0.11")
        self.assertEqual((h["source"], h["rev"], h["personality"]), ("override", 1, "linux-6"))
        st, j = self.change("add", {"decoy": self.decoy()})
        self.assertEqual((st, j["error"]["code"]), (409, "E_EXISTS"))
        st, j = self.change("edit", {"decoy": self.decoy(personality=None), "expect_rev": 0})
        self.assertEqual((st, j["error"]["code"]), (409, "E_CONFLICT"))
        st, j = self.change("edit", {"decoy": self.decoy(personality=None, ports=[]), "expect_rev": 1})
        self.assertEqual(st, 200, j)
        r = self.row("10.9.0.11")
        self.assertEqual((r["personality"], r["ports"]), ("", []))
        st, j = self.change("stop", {"ip": "10.9.0.11", "expect_rev": 2})
        self.assertEqual(st, 200)
        st, j = self.change("start", {"ip": "10.9.0.11", "expect_rev": 3})
        self.assertEqual(self.row("10.9.0.11")["template"], "pm_d_10_9_0_11")
        st, j = self.change("reset", {"ip": "10.9.0.11", "expect_rev": 4})
        self.assertEqual(st, 200, j)
        self.assertEqual(self.row("10.9.0.11")["template"], "default")

    def test_bad_settings_refused(self):
        for d, code in ((self.decoy(personality="nope"), "E_INVALID_PERSONALITY"),
                        (self.decoy(ports=[{"proto": "tcp", "port": 22, "service": "rootshell"}]), "E_INVALID_SERVICE"),
                        (self.decoy(ports=[{"proto": "udp", "port": 22, "service": "ssh"}]), "E_INVALID_SERVICE"),
                        (self.decoy(ports=[{"proto": "tcp", "port": 22, "state": "proxy 1.2.3.4:22"}]), "E_INVALID_STATE"),
                        (self.decoy(defaults={"tcp": "open", "udp": "open"}), "E_MISSING_FIELD"),
                        (self.decoy(ip="10.9.0.14"), "E_ADDRESS_IN_MAIN_CONF"),
                        (self.decoy(network="0.0.0.0/0"), "E_UNKNOWN_FIELD")):
            with self.subTest(code=code):
                st, j = self.change("add", {"decoy": d})
                self.assertEqual((st, j["error"]["code"]), (400, code), j)
        with open(self.conf) as f:
            self.assertNotIn("bind", f.read())

    def test_ui_settings_panel(self):
        with open(os.path.join(os.path.dirname(pmstore.__file__), "static", "console.js")) as f:
            js = f.read()
        for want in ('id="epers"', 'data-ed="def"', 'data-ed="svc"', 'data-ed="st"', 'data-act="edsave"',
                     'data-act="edreset"', "/api/decoyd/options", "max_ports", "fixed list of named services",
                     "is listed twice", "args.expect_rev = e.rev", "E_VERIFY_FAILED:", 'id="dro"'):
            self.assertIn(want, js)
        self.assertNotIn("innerHTML = e", js)


class DecoyNetwork(DecoyStopStart):
    """The Network section end to end with the helper's own validation and
    store retarget code behind the socket: the table follows the new block
    and settings outside it are dropped and named."""

    def setUp(self):
        super().setUp()
        import sim_decoyd
        D = sim_decoyd.D
        self.h.close()
        with open(os.environ["PM_DEFAULT"]) as f:
            self.old_default = f.read()
        with open(os.environ["PM_DEFAULT"], "w") as f:
            f.write('INTERFACE=eth0\nNETWORK="10.9.0.8/29"\n')
        info = {"ifaces": {"eth0": {"addrs": [D.ipaddress.IPv4Interface("10.9.0.2/24")], "up": True, "lo": False}},
                "gateways": [D.ipaddress.IPv4Address("10.9.0.1")]}
        self.h = sim_decoyd.SimHelper(self.sock, self.conf, "10.9.0.8/29", binds={"10.9.0.14"},
                                      info=info, default_path=os.environ["PM_DEFAULT"])

    def tearDown(self):
        super().tearDown()
        with open(os.environ["PM_DEFAULT"], "w") as f:
            f.write(self.old_default)

    def setnet(self, net, expect="10.9.0.8/29"):
        return self.change("set_network", {"network": net, "interface": "eth0",
                                           "expect": {"network": expect, "interface": "eth0"}})

    def test_netinfo(self):
        st, j = self.c.req("GET", "/api/decoyd/netinfo")
        self.assertEqual(st, 200)
        self.assertEqual((j["result"]["network"], j["result"]["gateways"]), ("10.9.0.8/29", ["10.9.0.1"]))

    def test_change_follows_block_and_drops(self):
        for ip in ("10.9.0.9", "10.9.0.12"):
            self.assertEqual(self.change("stop", {"ip": ip})[0], 200)
        st, j = self.setnet("10.9.0.12/30")
        self.assertEqual(st, 200, j)
        self.assertEqual(j["result"]["dropped"], ["10.9.0.9", "10.9.0.12"])   # .12 is the new network address
        st, j = self.c.req("GET", "/api/decoys")
        got = {r["ip"]: r["reserved"] for r in j["decoys"] if r["ip"].startswith("10.9.0.")}
        self.assertEqual(got, {"10.9.0.12": "network", "10.9.0.13": None, "10.9.0.14": None,
                               "10.9.0.15": "broadcast"})
        self.assertEqual(self.change("stop", {"ip": "10.9.0.12"})[1]["error"]["code"], "E_ADDRESS_RESERVED")
        self.assertEqual(self.change("stop", {"ip": "10.9.0.13"})[0], 200)

    def test_last_change_readable_after_change(self):
        """A browser whose request was cut off reads the outcome back."""
        self.assertIsNone(self.c.req("GET", "/api/decoyd/netinfo")[1]["result"]["last_change"])
        self.assertEqual(self.setnet("10.9.0.16/29")[0], 200)
        lc = self.c.req("GET", "/api/decoyd/netinfo")[1]["result"]["last_change"]
        self.assertEqual((lc["result"], lc["network"], lc["previous"]["network"]), ("applied", "10.9.0.16/29", "10.9.0.8/29"))

    def test_ui_reads_outcome_after_lost_connection(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "console.js")) as f:
            js = f.read()
        for s in ("function netWait", "last_change", "mirage.netpending", "new Set(ni.gateways"):
            self.assertIn(s, js)

    def test_refusals(self):
        for net, code in (("10.9.0.0/29", "E_HOST_ADDRESS"), ("8.8.8.0/29", "E_NOT_PRIVATE"),
                          ("10.9.1.8/29", "E_NOT_ON_LAN"), ("10.9.0.0/23", "E_NETWORK_TOO_WIDE"),
                          ("10.9.0.9/29", "E_INVALID_NETWORK"), ("10.9.0.8/29", "E_UNCHANGED")):
            with self.subTest(net=net):
                st, j = self.setnet(net)
                self.assertEqual(j["error"]["code"], code, j)
        self.assertEqual(self.setnet("10.9.0.32/28", expect="10.9.0.16/29")[1]["error"]["code"], "E_CONFLICT")
        with open(os.environ["PM_DEFAULT"]) as f:
            self.assertIn('NETWORK="10.9.0.8/29"', f.read())


class DecoyReserved(DecoyStopStart):
    """Network and broadcast addresses of the block: listed, flagged, no
    controls, and refused by the console before the helper is asked."""

    def test_rows_flagged(self):
        st, j = self.c.req("GET", "/api/decoys")
        got = {r["ip"]: r["reserved"] for r in j["decoys"]}
        self.assertEqual(got["10.9.0.8"], "network")
        self.assertEqual(got["10.9.0.15"], "broadcast")
        self.assertEqual([ip for ip, v in got.items() if v], ["10.9.0.8", "10.9.0.15"])
        self.assertEqual(len([ip for ip in got if ip.startswith("10.9.0.")]), 8)

    def test_direct_call_refused(self):
        for op, args in (("stop", {"ip": "10.9.0.8"}), ("start", {"ip": "10.9.0.15"}),
                         ("reset", {"ip": "10.9.0.8"}),
                         ("add", {"decoy": {"ip": "10.9.0.15", "personality": None,
                                            "defaults": {"tcp": "reset", "udp": "closed", "icmp": "open"},
                                            "ports": []}})):
            with self.subTest(op=op):
                n = len(self.h.reqs)
                st, j = self.change(op, args)
                self.assertEqual((st, j["error"]["code"]), (400, "E_ADDRESS_RESERVED"), j)
                self.assertIn("address of the decoy block", j["error"]["message"])
                self.assertEqual(len(self.h.reqs), n)

    def test_rule_matches_helper(self):
        import importlib.machinery, importlib.util, ipaddress
        path = os.path.join(os.path.dirname(pmstore.__file__), "..", "decoyd", "pm-decoyd.py")
        ld = importlib.machinery.SourceFileLoader("pm_decoyd_rule", path)
        spec = importlib.util.spec_from_loader(ld.name, ld)
        hm = importlib.util.module_from_spec(spec)
        ld.exec_module(hm)
        for block in ("10.211.55.240/29", "10.0.0.0/30", "10.0.0.0/31", "10.0.0.5/32", "10.0.0.0/24"):
            nets = pmstore.parse_networks(block)
            for a in list(nets[0])[:6] + list(nets[0])[-2:]:
                ip = str(a)
                try:
                    hm.check_ip(ip, "f", nets, set())
                    helper = False
                except hm.Err as e:
                    helper = e.code == "E_ADDRESS_RESERVED"
                with self.subTest(block=block, ip=ip):
                    self.assertEqual(bool(pmstore.reserved_address(ip, nets)), helper)
        self.assertEqual(pmstore.reserved_address("10.211.55.240", pmstore.parse_networks("10.211.55.240/29")), "network")
        self.assertEqual(pmstore.reserved_address("10.211.55.247", pmstore.parse_networks("10.211.55.240/29")), "broadcast")
        self.assertIsNone(pmstore.reserved_address("10.0.0.1", pmstore.parse_networks("10.0.0.0/31")))

    def test_ui_reserved_and_icons(self):
        with open(os.path.join(os.path.dirname(pmstore.__file__), "static", "console.js")) as f:
            js = f.read()
        for want in ('network: "network address"', 'broadcast: "broadcast address"', "x.reserved ?",
                     'aria-label="Stop decoy ${ex}"', 'aria-label="Start decoy ${ex}"', "ssi stop", "ssi start",
                     "if (resv || !h"):
            self.assertIn(want, js)


if __name__ == "__main__":
    unittest.main()
