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
        for p in ("/api/status", "/api/alerts", "/api/audit", "/api/settings", "/api/decoys"):
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
        self.assertEqual(page.count('class="themetg" data-theme-toggle aria-pressed="false" aria-label="Dark theme"'), 2)
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
            "index.html", "console.css", "console.js", "theme.js", "phantom-mirage-mark.svg", "mirage-wordmark.svg", "phantom-mirage-mark-dark.png", "phantom-mirage-mark.png",
            "phantom-mirage-logo-light.png", "phantom-mirage-logo-dark.png",
            "fonts/Aldrich-Regular.woff2", "fonts/Aldrich-OFL.txt"]))


if __name__ == "__main__":
    unittest.main()
