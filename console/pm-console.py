#!/usr/bin/python3
"""Phantom Mirage I console daemon (phantom-mirage-console.service).

HTTPS on 127.0.0.1 only (reach it with: ssh -L 8443:127.0.0.1:8443 user@sensor).
Python 3 standard library only; no outbound connections.
"""
import http.server
import json
import os
import re
import html
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import branding  # noqa: E402
import decoyclient  # noqa: E402
import pmauth  # noqa: E402
import pmstore  # noqa: E402

BIND = "127.0.0.1"           # never configurable: loopback only (#118)
STATIC = os.environ.get("PM_CONSOLE_STATIC",
                        os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))
VERSION = "1.7.0"
COOKIE = "__Host-pm_session"
PRE = "__Host-pm_pre"
MAX_BODY = 16384
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8", ".png": "image/png",
         ".svg": "image/svg+xml", ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8"}
# exact-name allowlist for /static/ (#141): URL name -> file under STATIC.
# Nothing from the request is ever joined onto a path.
STATIC_FILES = {n: n for n in (
    "index.html", "console.css", "console.js", "theme.js", "phantom-mirage-mark.svg", "mirage-wordmark.svg", "phantom-technologies-wordmark.svg", "phantom-mirage-mark-dark.png",
    "phantom-mirage-mark.png", "phantom-mirage-logo-light.png",
    "phantom-mirage-logo-dark.png")}
STATIC_FILES.update({"fonts/Aldrich-Regular.woff2": os.path.join("fonts", "Aldrich-Regular.woff2"),
                     "fonts/Aldrich-OFL.txt": os.path.join("fonts", "Aldrich-OFL.txt")})
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
CLOCK_MAX_STEP = 86400       # browser may move the clock by at most 24 h (#120)
# index.html placeholders, filled from branding.conf (#141, single source)
BRAND = {"{{PRODUCT}}": branding.PRODUCT, "{{LEGAL_NAME}}": branding.LEGAL_NAME,
         "{{COPYRIGHT}}": branding.COPYRIGHT}
HOST_RE = re.compile(r'^(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$')


def brand_html(data):
    t = data.decode("utf-8")
    for k, v in BRAND.items():
        t = t.replace(k, html.escape(v))
    return t.encode("utf-8")


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = pmauth.Sessions()
        self.lockout = pmauth.Lockout(pmstore.path("lockout.json"))
        self.alerts = pmstore.AlertEngine()
        self.alerts.preload_activity()
        self.pre = {}                 # pre-login CSRF tokens -> expiry
        self.lock = threading.Lock()
        self.clock_refused = ""       # last refused browser clock set, for the UI

    def reload_cfg(self):
        self.cfg = pmstore.load_config()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "PhantomMirageConsole"
    sys_version = ""
    timeout = 30
    protocol_version = "HTTP/1.1"
    app = None  # type: App

    # never log bodies, cookies or headers: method, path, status only
    def log_message(self, fmt, *args):
        sys.stderr.write("console: %s\n" % (fmt % args))

    def log_request(self, code="-", size="-"):
        p = urllib.parse.urlsplit(self.path).path
        self.log_message('%s %s %s', self.command, p[:100], str(code))

    # ---- helpers
    def headers_common(self, ctype, length, api=True):
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Cache-Control", "no-store" if api else "private, max-age=300")

    def send_json(self, code, obj, cookies=()):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.headers_common("application/json", len(body))
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, msg):
        self.send_json(code, {"error": msg})

    def cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def session(self):
        sid = self.cookie(COOKIE)
        return sid, self.app.sessions.get(sid)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return None
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            return None
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
            return d if isinstance(d, dict) else None
        except ValueError:
            return None

    def host_ok(self):
        return bool(HOST_RE.match(self.headers.get("Host") or ""))

    # ---- GET
    def do_GET(self):
        if not self.host_ok():
            return self.err(421, "bad host")
        p = urllib.parse.urlsplit(self.path)
        path = p.path
        if path in ("/", "/index.html"):
            return self.static("index.html")
        if path.startswith("/static/"):
            return self.static(path[len("/static/"):])
        if path == "/api/health":
            return self.send_json(200, {"ok": True})
        if path == "/api/session":
            return self.api_session()
        sid, s = self.session()
        if not s:
            return self.err(401, "sign in")
        a = self.app
        a.reload_cfg()
        if path == "/api/status":
            return self.send_json(200, self.status())
        if path == "/api/decoys":
            return self.send_json(200, pmstore.decoy_list(dict(a.alerts.last_touch)))
        if path in ("/api/decoyd/list", "/api/decoyd/options", "/api/decoyd/netinfo"):
            r = decoyclient.call(path.rsplit("/", 1)[1], {}, s["user"])
            return self.send_json(200 if r["ok"] else self.decoyd_status(r), r)
        if path == "/api/personalities":
            return self.send_json(200, {"personalities": pmstore.personalities()})
        if path == "/api/alerts":
            return self.send_json(200, {"alerts": a.alerts.snapshot(),
                                        "muted": a.cfg.get("muted", [])})
        if path == "/api/activity":
            with a.alerts.lock:
                ev = list(a.alerts.activity[-1000:])
            return self.send_json(200, {"events": ev[::-1]})
        if path == "/api/audit":
            return self.send_json(200, {"audit": pmstore.read_audit()})
        if path == "/api/settings":
            c = a.cfg
            return self.send_json(200, {k: c.get(k) for k in (
                "sensor_name", "port", "time_source", "ntp_server", "timezone",
                "alert_retention_days", "drift_warn_seconds", "muted")})
        return self.err(404, "not found")

    def static(self, name):
        rel = STATIC_FILES.get(name)
        if rel is None:
            return self.err(404, "not found")
        fp = os.path.join(STATIC, rel)
        ext = os.path.splitext(rel)[1]
        if ext not in TYPES or not os.path.isfile(fp):
            return self.err(404, "not found")
        with open(fp, "rb") as f:
            data = f.read()
        if ext == ".html":
            data = brand_html(data)
        self.send_response(200)
        self.headers_common(TYPES[ext], len(data), api=(ext == ".html"))
        self.end_headers()
        self.wfile.write(data)

    def api_session(self):
        sid, s = self.session()
        c = self.app.cfg
        base = {"sensor_name": c.get("sensor_name"), "version": VERSION,
                "time_source": c.get("time_source")}
        if s:
            base.update(authenticated=True, user=s["user"], csrf=s["csrf"])
            return self.send_json(200, base)
        import secrets
        tok = secrets.token_urlsafe(24)
        with self.app.lock:
            now = time.time()
            self.app.pre = {k: v for k, v in self.app.pre.items() if v > now}
            if len(self.app.pre) > 1000:
                self.app.pre.clear()
            self.app.pre[tok] = now + 600
        base.update(authenticated=False, csrf=tok)
        return self.send_json(200, base, cookies=[
            "%s=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600" % (PRE, tok)])

    def status(self):
        a = self.app
        c = a.cfg
        d = pmstore.read_default()
        alerts = a.alerts.snapshot()
        fp = ""
        try:
            with open(pmstore.path("cert.sha256")) as f:
                fp = f.read().strip()
        except OSError:
            pass
        return {
            "sensor_name": c.get("sensor_name"),
            "services": {u: pmstore.unit_state(u) for u in (
                "phantom-mirage", "farpd", "phantom-mirage-firewall")},
            "interface": d.get("INTERFACE", ""), "network": d.get("NETWORK", ""),
            "open_alerts": sum(1 for x in alerts if x["status"] == "Open"),
            "last_activity": a.alerts.last_event_ts,
            "event_log": os.path.exists(a.alerts.event_log),
            "server_time_ms": int(time.time() * 1000),
            "time_source": c.get("time_source"), "ntp_server": c.get("ntp_server"),
            "ntp_synced": pmstore.ntp_synced() if c.get("time_source") == "ntp" else None,
            "drift_warn_seconds": c.get("drift_warn_seconds", 60),
            "timezone": c.get("timezone"), "cert_sha256": fp, "version": VERSION,
            "retention_paused": a.alerts.prune_paused,
            "retention_pause_reason": a.alerts.pause_reason,
            "clock_refused": a.clock_refused,
        }

    # ---- POST
    def do_POST(self):
        if not self.host_ok():
            return self.err(421, "bad host")
        if not pmauth.same_origin_ok(self.headers, self.app.cfg.get("port", 8443)):
            return self.err(403, "cross-site request refused")
        path = urllib.parse.urlsplit(self.path).path
        data = self.body()
        if data is None:
            return self.err(400, "bad request")
        tok = self.headers.get("X-CSRF-Token") or ""
        if path == "/api/login":
            return self.login(data, tok)
        sid, s = self.session()
        if not s:
            return self.err(401, "sign in")
        if not self.app.sessions.check_csrf(sid, tok):
            pmstore.audit(s["user"], "csrf-reject", path, ok=False)
            return self.err(403, "bad CSRF token")
        user = s["user"]
        a = self.app
        a.reload_cfg()
        if path == "/api/logout":
            a.sessions.destroy(sid)
            pmstore.audit(user, "logout")
            return self.send_json(200, {"ok": True}, cookies=[
                "%s=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0" % COOKIE])
        m = re.match(r'^/api/alerts/(\d+)/(ack|close|reopen)$', path)
        if m:
            aid, op = int(m.group(1)), m.group(2)
            st = {"ack": "Acknowledged", "close": "Closed", "reopen": "Open"}[op]
            note = str(data.get("note", ""))[:500]
            if not a.alerts.update(aid, st, note):
                return self.err(404, "no such alert")
            pmstore.audit(user, "alert-" + op, "alert %d%s" % (aid, (": " + note) if note else ""))
            return self.send_json(200, {"ok": True})
        if path in ("/api/mute", "/api/unmute"):
            src = str(data.get("src", ""))
            if not re.match(r'^[0-9a-fA-F:.]{2,45}$', src):
                return self.err(400, "bad address")
            c = pmstore.load_config()
            muted = [x for x in c.get("muted", []) if x != src]
            if path == "/api/mute":
                muted.append(src)
            c["muted"] = muted
            pmstore.save_config(c)
            pmstore.audit(user, path[5:], src)
            return self.send_json(200, {"ok": True})
        if path == "/api/retention/resume":
            ok = a.alerts.resume_pruning(user, "admin confirmed the sensor clock in the console")
            a.clock_refused = ""
            return self.send_json(200, {"ok": True, "resumed": ok})
        if path == "/api/settings":
            c = pmstore.load_config()
            changes = []
            if "alert_retention_days" in data:
                try:
                    v = int(data["alert_retention_days"])
                except (TypeError, ValueError):
                    return self.err(400, "bad retention")
                if not 1 <= v <= 3650:
                    return self.err(400, "retention must be 1-3650 days")
                changes.append("alert_retention_days %s -> %s" % (c.get("alert_retention_days"), v))
                c["alert_retention_days"] = v
            if "timezone" in data:
                tz = str(data["timezone"])
                if not re.match(r'^[A-Za-z0-9_+\-/]{1,64}$', tz):
                    return self.err(400, "bad time zone")
                changes.append("timezone %s -> %s" % (c.get("timezone"), tz))
                c["timezone"] = tz
            pmstore.save_config(c)
            pmstore.audit(user, "settings", "; ".join(changes))
            return self.send_json(200, {"ok": True})
        if path == "/api/decoyd/change":
            return self.decoyd_change(user, data)
        if path == "/api/password":
            adm = pmstore.load_admin() or {}
            cur, new = data.get("current", ""), data.get("new", "")
            if not pmauth.verify_password(cur, adm.get("hash", "")):
                pmstore.audit(user, "password-change", "wrong current password", ok=False)
                return self.err(403, "current password is wrong")
            prob = pmauth.password_problem(new, user)
            if prob:
                return self.err(400, prob)
            pmstore.save_admin(user, pmauth.hash_password(new))
            a.sessions.destroy_user(user)
            pmstore.audit(user, "password-change", "all sessions signed out")
            return self.send_json(200, {"ok": True})
        return self.err(404, "not found")

    @staticmethod
    def decoyd_status(r):
        code = (r.get("error") or {}).get("code", "")
        if code in ("E_UNAVAILABLE", "E_TIMEOUT", "E_BAD_REPLY"):
            return 503
        if code == "E_BUSY":
            return 429
        if code in ("E_CONFLICT", "E_EXISTS", "E_NOT_FOUND", "E_NOT_RUNNING", "E_NOT_STOPPED", "E_UNCHANGED"):
            return 409
        if code in ("E_RELOAD_FAILED_ROLLED_BACK", "E_RESTART_FAILED_ROLLED_BACK", "E_ROLLBACK_FAILED", "E_INTERNAL", "E_PEER"):
            return 500
        return 400

    def decoyd_change(self, user, data):
        """Per decoy change: the admin re-enters the password every time.
        set_network changes the address block and interface; the helper
        validates it again and restarts the whole sensor."""
        a = self.app
        op, args, pw = data.get("op"), data.get("args"), data.get("password")
        if op not in decoyclient.CHANGE_OPS or not isinstance(args, dict) or set(data) - {"op", "args", "password"}:
            return self.err(400, "bad request")
        ip = args.get("ip")
        if op == "set_network":
            ip = None
        elif ip is None and isinstance(args.get("decoy"), dict):
            ip = args["decoy"].get("ip")
        kind = pmstore.reserved_address(ip, pmstore.parse_networks(
            pmstore.read_default().get("NETWORK", ""))) if isinstance(ip, str) else None
        if kind:
            field = "args.ip" if "ip" in args else "decoy.ip"
            pmstore.audit(user, "decoy-" + op, "%s refused E_ADDRESS_RESERVED" % re.sub(r'[^0-9.]', "", ip)[:15], ok=False)
            return self.send_json(400, {"ok": False, "error": {
                "code": "E_ADDRESS_RESERVED", "field": field,
                "message": "%s is the %s address of the decoy block and cannot be a decoy" % (ip, kind)}})
        src = self.source()
        key = "decoy-reauth:" + user
        until = a.lockout.locked_until(key, src)
        if until:
            pmstore.audit(user, "decoy-" + op, "password re-entry backing off", ok=False)
            return self.err(423, "too many wrong passwords; try again in %d s" % max(1, int(until - time.time())))
        adm = pmstore.load_admin() or {}
        if not (isinstance(pw, str) and pw and pmauth.verify_password(pw, adm.get("hash", ""))):
            a.lockout.failure(key, src)
            pmstore.audit(user, "decoy-" + op, "wrong password", ok=False)
            return self.err(403, "password is wrong")
        a.lockout.success(key, src)
        if op == "set_network":
            target = "%s on %s" % (re.sub(r'[^0-9./]', "", str(args.get("network")))[:18],
                                   re.sub(r'[^A-Za-z0-9_.-]', "", str(args.get("interface")))[:15])
        else:
            target = re.sub(r'[^0-9.]', "", str(ip))[:15] if ip is not None else "all"
        pmstore.audit(user, "decoy-" + op, "requested %s" % target)
        r = decoyclient.call(op, args, user)
        if r["ok"]:
            extra = ""
            if op == "set_network":
                d = (r.get("result") or {}).get("dropped") or []
                extra = ", dropped settings for %s" % (" ".join(d)[:400] or "none")
            pmstore.audit(user, "decoy-" + op, "%s applied%s%s" % (
                target, ", sensor reloaded" if r.get("reloaded") else ", sensor not running", extra))
            return self.send_json(200, r)
        e = r.get("error") or {}
        pmstore.audit(user, "decoy-" + op, "%s refused %s%s" % (
            target, e.get("code"), ", rolled back" if r.get("rolled_back") else ""), ok=False)
        return self.send_json(self.decoyd_status(r), r)

    def login(self, data, tok):
        a = self.app
        pre = self.cookie(PRE)
        with a.lock:
            valid = bool(pre and tok and pre == tok and a.pre.pop(tok, 0) > time.time())
        if not valid:
            return self.err(403, "bad CSRF token; reload the page")
        src = self.source()
        if a.lockout.rate_limited(src):
            pmstore.audit("-", "login-rate-limited", src, ok=False)
            return self.err(429, "too many sign-in attempts; wait a minute")
        user = str(data.get("username", ""))[:64]
        pw = data.get("password", "")
        adm = pmstore.load_admin()
        if not adm:
            return self.err(503, "no admin account; run phantom-mirage-setup on the sensor")
        until = a.lockout.locked_until(user, src)
        if until:
            pmstore.audit(user, "login", "backing off (%s)" % src, ok=False)
            return self.err(423, "too many failed sign-ins from here; try again in %d s or run "
                                 "phantom-mirage-setup --reset-admin on the sensor"
                            % max(1, int(until - time.time())))
        if user != adm.get("username"):
            pmauth.dummy_verify(str(pw))
            ok = False
        else:
            ok = pmauth.verify_password(pw if isinstance(pw, str) else "", adm.get("hash", ""))
        if not ok:
            until = a.lockout.failure(user, src)
            pmstore.audit(user, "login", "failed (%s)%s" % (src, " (backing off)" if until else ""),
                          ok=False)
            return self.err(401, "wrong username or password")
        a.lockout.success(user, src)
        sid = a.sessions.create(user)
        pmstore.audit(user, "login", "signed in")
        warn = self.clock_from_browser(user, data.get("browser_time_ms"))
        s = a.sessions.get(sid)
        return self.send_json(200, {"ok": True, "csrf": s["csrf"], "clock_warning": warn}, cookies=[
            "%s=%s; Path=/; Secure; HttpOnly; SameSite=Strict" % (COOKIE, sid),
            "%s=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0" % PRE])

    def source(self):
        """Rate-limit / back-off bucket for this connection (#120): the UID
        owning the client socket (all clients are loopback via SSH tunnels),
        else the peer address."""
        try:
            peer, local = self.client_address, self.connection.getsockname()
        except (OSError, AttributeError):
            return "-"
        uid = pmauth.peer_uid(peer, local)
        return "uid:%d" % uid if uid is not None else "addr:%s" % peer[0]

    def clock_from_browser(self, user, bt):
        """Set the sensor clock from the browser at sign-in (time_source=browser).
        Steps over CLOCK_MAX_STEP are refused. Returns a warning or None."""
        c = self.app.cfg
        if c.get("time_source") != "browser" or not isinstance(bt, (int, float)) \
                or isinstance(bt, bool):
            return None
        old = time.time()
        new = bt / 1000.0
        delta = new - old
        if abs(delta) < 5:
            return None
        fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) \
            if 0 < t < 253402300800 else repr(t)
        if abs(delta) > CLOCK_MAX_STEP:
            msg = ("browser clock differs from the sensor by %+.0f s (more than 24 h); not applied. "
                   "Check the browser's clock, or set the sensor clock on its terminal with "
                   "phantom-mirage-setup." % delta)
            self.app.clock_refused = msg
            pmstore.audit(user, "clock-set", "refused: sensor %s, browser %s, delta %+.0fs"
                          % (fmt(old), fmt(new), delta), ok=False)
            return msg
        try:
            time.clock_settime(time.CLOCK_REALTIME, new)
        except (OSError, AttributeError) as e:
            pmstore.audit(user, "clock-set", "failed: %s" % e.__class__.__name__, ok=False)
            return None
        self.app.alerts.note_clock_set(delta)
        pmstore.audit(user, "clock-set", "sensor clock set from browser: %s -> %s (delta %+.0fs)"
                      % (fmt(old), fmt(new), delta))
        return None


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32


def make_server(cfg, port=None, certfile=None, keyfile=None):
    port = int(cfg.get("port") or 8443) if port is None else int(port)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile or pmstore.path("cert.pem"), keyfile or pmstore.path("key.pem"))
    Handler.app = App(cfg)
    httpd = Server((BIND, port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True,
                                   do_handshake_on_connect=False)
    return httpd


def poller(app, stop):
    while not stop.wait(2):
        try:
            app.reload_cfg()
            app.alerts.poll(app.cfg)
        except Exception as e:  # keep serving; never dump data
            sys.stderr.write("console: ingest error: %s\n" % e.__class__.__name__)


def main():
    cfg = pmstore.load_config()
    if not pmstore.load_admin() or not cfg.get("sensor_name"):
        sys.stderr.write("console: not set up; run phantom-mirage-setup on the sensor\n")
        return 78
    httpd = make_server(cfg)
    stop = threading.Event()
    threading.Thread(target=poller, args=(Handler.app, stop), daemon=True).start()
    sys.stderr.write("console: listening on https://%s:%d\n" % (BIND, httpd.server_address[1]))
    try:
        httpd.serve_forever()
    finally:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
