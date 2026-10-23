#!/usr/bin/python3
"""CI helper: sign in to the console like a browser and read the API.

  console_login.py PORT USER            (password read from stdin)
  console_login.py PORT USER --expect-fail

Never prints the password or cookies. Exit 0 on success.
"""
import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

port, user = int(sys.argv[1]), sys.argv[2]
expect_fail = "--expect-fail" in sys.argv
pw = sys.stdin.readline().rstrip("\n")
base = "https://127.0.0.1:%d" % port
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE   # self-signed; CI checks the fingerprint separately
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                 urllib.request.HTTPCookieProcessor(jar))


def call(path, body=None, csrf=None, origin=True):
    h = {}
    if body is not None:
        h["Content-Type"] = "application/json"
        if origin:
            h["Origin"] = base
        if csrf:
            h["X-CSRF-Token"] = csrf
    r = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=h)
    try:
        with op.open(r, timeout=10) as f:
            return f.status, json.loads(f.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


st, s = call("/api/session")
check(st == 200 and not s["authenticated"], "pre-login session")
st, _ = call("/api/status")
check(st == 401, "API refuses without a session")
st, j = call("/api/login", {"username": user, "password": pw, "browser_time_ms": int(time.time() * 1000)}, s["csrf"])
if expect_fail:
    check(st in (401, 423), "login refused (%d)" % st)
    sys.exit(0)
check(st == 200, "login (%d %s)" % (st, j.get("error", "")))
csrf = j["csrf"]
st, s = call("/api/status")
check(st == 200 and s["sensor_name"], "status for sensor %s" % s.get("sensor_name"))
for p in ("/api/decoys", "/api/alerts", "/api/activity", "/api/audit", "/api/settings"):
    st, _ = call(p)
    check(st == 200, "GET " + p)
st, _ = call("/api/mute", {"src": "192.0.2.1"})
check(st == 403, "state change without CSRF token refused")
st, _ = call("/api/mute", {"src": "192.0.2.1"}, csrf, origin=False)
check(st == 403, "state change without Origin refused")
st, _ = call("/api/unmute", {"src": "192.0.2.1"}, csrf)
check(st == 200, "state change with CSRF token")
st, a = call("/api/audit")
check(any(x["action"] == "login" and x["ok"] for x in a["audit"]), "login is in the audit log")
st, _ = call("/api/logout", {}, csrf)
check(st == 200, "logout")
st, _ = call("/api/status")
check(st == 401, "session gone after logout")
