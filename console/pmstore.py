"""Phantom Mirage I console: on-box state (config, admin, alerts, audit)
and readers for the sensor's own files. Python 3 standard library only.

All state lives in STATE_DIR (default /var/lib/phantom-mirage/console),
which package upgrades and install.sh keep; only phantom-mirage-uninstall
removes it.
"""
import ipaddress
import json
import os
import re
import shlex
import subprocess
import threading
import time

STATE_DIR = os.environ.get("PM_CONSOLE_STATE", "/var/lib/phantom-mirage/console")
SENSOR_CONF = os.environ.get("PM_SENSOR_CONF", "/etc/phantom-mirage/phantom-mirage.conf")
SENSOR_DEFAULT = os.environ.get("PM_DEFAULT", "/etc/default/phantom-mirage")
EVENT_LOG = os.environ.get("PM_EVENT_LOG", "/var/log/phantom-mirage/events.jsonl")

GROUP_WINDOW = 600          # same source within 10 minutes -> one alert
MAX_ALERTS = 5000
ACTIVITY_KEEP = 2000        # events kept in memory for the Activity page
DEFAULTS = {"sensor_name": "", "port": 8443, "time_source": "browser",
            "ntp_server": "", "timezone": "UTC", "alert_retention_days": 90,
            "drift_warn_seconds": 60, "ssh_ports": [22], "muted": []}


def path(name):
    return os.path.join(STATE_DIR, name)


def read_json(name, default=None):
    try:
        with open(path(name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(name, data, mode=0o600):
    p = path(name)
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, p)


def load_config():
    c = dict(DEFAULTS)
    c.update(read_json("console.json", {}) or {})
    return c


def save_config(c):
    write_json("console.json", c, 0o640)


def load_admin():
    return read_json("admin.json")


def save_admin(user, pwhash):
    write_json("admin.json", {"username": user, "hash": pwhash,
                              "changed": int(time.time())}, 0o600)


def audit(actor, action, detail="", ok=True):
    """Append one line to the audit log. Never pass secrets in detail."""
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "actor": actor, "action": action, "detail": str(detail)[:500], "ok": bool(ok)}
    fd = os.open(path("audit.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def read_audit(limit=500):
    out = []
    try:
        with open(path("audit.jsonl")) as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out[-limit:][::-1]


# ---- sensor files -------------------------------------------------------

def read_default(p=None):
    """KEY=VALUE pairs from /etc/default/phantom-mirage (no shell eval)."""
    vals = {}
    try:
        with open(p or SENSOR_DEFAULT) as f:
            for line in f:
                m = re.match(r'^\s*([A-Z_]+)=(.*)$', line)
                if not m:
                    continue
                v = m.group(2).strip()
                try:
                    v = " ".join(shlex.split(v))
                except ValueError:
                    pass
                vals[m.group(1)] = v
    except OSError:
        pass
    return vals


def parse_decoys(conf=None):
    """Templates and bindings from the honeyd-style config."""
    tmpl, binds = {}, []
    try:
        with open(conf or SENSOR_CONF) as f:
            text = f.read()
    except OSError:
        return {"templates": {}, "binds": [], "error": "cannot read config"}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            w = shlex.split(line)
        except ValueError:
            continue
        if len(w) >= 2 and w[0] == "create":
            tmpl.setdefault(w[1], {"personality": "", "ports": [], "default": {}})
        elif len(w) >= 4 and w[0] == "set" and w[2] == "personality":
            tmpl.setdefault(w[1], {"personality": "", "ports": [], "default": {}})["personality"] = w[3]
        elif len(w) >= 6 and w[0] == "set" and w[2] == "default" and w[4] == "action":
            tmpl.setdefault(w[1], {"personality": "", "ports": [], "default": {}})["default"][w[3]] = w[5]
        elif len(w) >= 5 and w[0] == "add" and w[3] == "port":
            t = tmpl.setdefault(w[1], {"personality": "", "ports": [], "default": {}})
            if w[4] not in ("block", "reset", "closed"):
                t["ports"].append("%s/%s" % (w[2], w[3]))
        elif len(w) >= 3 and w[0] == "bind":
            binds.append({"ip": w[1], "template": w[2]})
    return {"templates": tmpl, "binds": binds}


def decoy_list(last_touch):
    d = parse_decoys()
    dflt = read_default()
    net = dflt.get("NETWORK", "")
    rows = []
    for b in d.get("binds", []):
        t = d["templates"].get(b["template"], {})
        rows.append({"ip": b["ip"], "template": b["template"],
                     "personality": t.get("personality", ""),
                     "ports": t.get("ports", []),
                     "last": last_touch.get(b["ip"])})
    if net and "default" in d.get("templates", {}):
        t = d["templates"]["default"]
        bound = {r["ip"] for r in rows}
        try:
            n = ipaddress.ip_network(net, strict=False)
            if n.num_addresses <= 256:
                for a in n:
                    s = str(a)
                    if s in bound:
                        continue
                    rows.append({"ip": s, "template": "default",
                                 "personality": t.get("personality", ""),
                                 "ports": t.get("ports", []), "last": last_touch.get(s)})
        except ValueError:
            pass
    return {"network": net, "interface": dflt.get("INTERFACE", ""), "decoys": rows,
            "error": d.get("error")}


def unit_state(name):
    try:
        r = subprocess.run(["systemctl", "is-active", name], capture_output=True,
                           text=True, timeout=5)
        return r.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def ntp_synced():
    try:
        r = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                           capture_output=True, text=True, timeout=5)
        v = r.stdout.strip()
        return {"yes": True, "no": False}.get(v)
    except (OSError, subprocess.SubprocessError):
        return None


# ---- alerts -------------------------------------------------------------

class AlertEngine:
    """Tails the sensor's JSON Lines event log and groups inbound touches
    on decoys into alerts (console only; nothing leaves the box)."""

    def __init__(self, event_log=None):
        self.event_log = event_log or EVENT_LOG
        self.lock = threading.Lock()
        d = read_json("alerts.json", {}) or {}
        self.alerts = d.get("alerts", [])
        self.next_id = d.get("next_id", 1)
        st = read_json("ingest.json", {}) or {}
        self.ino, self.off = st.get("ino"), st.get("off", 0)
        self.activity = []
        self.last_touch = {}
        self.last_event_ts = None

    def preload_activity(self):
        """Fill the Activity feed from the tail of the log (no alerts)."""
        try:
            with open(self.event_log, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                start = max(0, min(size, self.off or size) - 1024 * 1024)
                f.seek(start)
                data = f.read(max(0, (self.off or size) - start))
        except OSError:
            return
        alerts, self.alerts = self.alerts, []
        nid = self.next_id
        for line in data.splitlines()[1 if start else 0:]:
            try:
                self.handle(json.loads(line), set(load_config().get("muted", [])))
            except (ValueError, TypeError, AttributeError):
                pass
        self.alerts, self.next_id = alerts, nid

    def save(self):
        write_json("alerts.json", {"alerts": self.alerts, "next_id": self.next_id}, 0o640)
        write_json("ingest.json", {"ino": self.ino, "off": self.off}, 0o640)

    def handle(self, e, muted):
        if e.get("event") not in ("connection.start", "packet"):
            return
        if e.get("direction") == "outbound":
            return
        decoy = e.get("honeypot_ip") or e.get("dst_ip")
        src = e.get("src_ip")
        if not decoy or not src:
            return
        ts = e.get("ts", "")
        self.last_event_ts = ts
        self.last_touch[decoy] = ts
        self.activity.append({"ts": ts, "src": src, "decoy": decoy,
                              "port": e.get("dst_port"), "proto": (e.get("proto") or "").upper(),
                              "event": e.get("event"), "os": e.get("os_guess", "")})
        if len(self.activity) > ACTIVITY_KEEP:
            del self.activity[:len(self.activity) - ACTIVITY_KEEP]
        if src in muted:
            return
        t = _parse_ts(ts)
        for a in reversed(self.alerts):
            if a["src"] == src and a["status"] != "Closed" and t - a["last_t"] <= GROUP_WINDOW:
                a["count"] += 1
                a["last"], a["last_t"] = ts, t
                if decoy not in a["decoys"]:
                    a["decoys"].append(decoy)
                if len(a["decoys"]) >= 2:
                    a["severity"], a["why"] = "High", "Multi-decoy scan"
                return
        self.alerts.append({"id": self.next_id, "severity": "Medium", "why": "Any touch",
                            "src": src, "decoys": [decoy], "first": ts, "last": ts,
                            "last_t": t, "count": 1, "status": "Open", "note": ""})
        self.next_id += 1
        if len(self.alerts) > MAX_ALERTS:
            del self.alerts[:len(self.alerts) - MAX_ALERTS]

    def poll(self, cfg):
        """Read new lines from the event log; prune by retention."""
        muted = set(cfg.get("muted", []))
        changed = False
        with self.lock:
            try:
                st = os.stat(self.event_log)
                if st.st_ino != self.ino or st.st_size < self.off:
                    self.ino, self.off = st.st_ino, 0   # rotated / truncated
                if st.st_size > self.off:
                    with open(self.event_log, "rb") as f:
                        f.seek(self.off)
                        chunk = f.read(8 * 1024 * 1024)
                    end = chunk.rfind(b"\n") + 1
                    for line in chunk[:end].splitlines():
                        try:
                            self.handle(json.loads(line), muted)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    self.off += end
                    changed = end > 0
            except OSError:
                pass
            keep = time.time() - int(cfg.get("alert_retention_days", 90)) * 86400
            n = len(self.alerts)
            self.alerts = [a for a in self.alerts if a["last_t"] >= keep]
            if changed or n != len(self.alerts):
                self.save()

    def snapshot(self):
        with self.lock:
            return [dict(a) for a in reversed(self.alerts)]

    def update(self, aid, status, note=""):
        with self.lock:
            for a in self.alerts:
                if a["id"] == aid:
                    a["status"] = status
                    if note:
                        a["note"] = note[:500]
                    self.save()
                    return True
        return False


def _parse_ts(ts):
    try:
        import calendar
        return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return time.time()
