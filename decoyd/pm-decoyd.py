#!/usr/bin/python3 -I
"""pm-decoyd: privileged helper that applies per decoy overrides.

Started on demand by pm-decoyd.socket (systemd socket activation,
Accept=no) and exits after an idle period. It is not a daemon in the
long running sense and never listens on anything but the socket systemd
hands over on fd 3.

The console (user phantom-mirage-console) connects to
/run/phantom-mirage-decoyd.sock and sends one typed JSON request per
connection (docs/design/decoy-management.md, section 5). Every field is
checked against fixed lists; no request text is ever passed to a shell or
copied into the sensor config. The config is rebuilt from
/var/lib/phantom-mirage/decoys.json and fixed templates only.

A change runs: lock, rate limit, validate, render decoys.conf.new,
phantom-mirage --verify-config on a temp main config whose include line
points at the candidate, keep decoys.conf.prev, atomic rename, systemctl
reload, health check (active and MainPID unchanged). If the check fails
the previous file is restored FIRST and only then is the unit restarted:
the unit has RestartPreventExitStatus=78, so restarting onto a bad file
could leave it down for good.

Python 3 standard library only. Run with -I (isolated mode).
"""
import difflib
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import re
import socket
import struct
import copy
import subprocess
import sys
import syslog
import time

ETC = "/etc/phantom-mirage"
P = {
    "default": "/etc/default/phantom-mirage",
    "main_conf": ETC + "/phantom-mirage.conf",
    "decoys_conf": ETC + "/decoys.conf",
    "store": "/var/lib/phantom-mirage/decoys.json",
    "fpdb": ETC + "/columbo-v1.db",
    "fpdb_sha": ETC + "/columbo-v1.db.sha256",
    "services": "/usr/share/phantom-mirage/decoy-services.json",
    "rundir": "/run/phantom-mirage-decoyd",
    "daemon": "/usr/bin/phantom-mirage",
    "data": {"-a": ETC + "/nmap.assoc", "-0": ETC + "/pf.os",
             "-x": ETC + "/xprobe2.conf", "-m": ETC + "/nmap-mac-prefixes"},
    "systemctl": "/usr/bin/systemctl",
    "unit": "phantom-mirage.service",
    "console_user": "phantom-mirage-console",
    "console_uid": None,          # tests only; production looks up console_user
    # address block change (set_network)
    "farpd_default": "/etc/default/farpd",
    "farpd_unit": "farpd.service",
    "firewall_unit": "phantom-mirage-firewall.service",
    "ip": "/usr/sbin/ip",
    "sysfs_net": "/sys/class/net",
    # set_network writes this before it renames the first file and removes
    # it when done; if it is still there the swap was cut off, and the next
    # change (or helper start) puts back the .prev set it lists.
    "journal": "/var/lib/phantom-mirage/netchange.journal",
    "outcome": "/var/lib/phantom-mirage/netchange.last",
    # time source (set_time): only this helper's own server file changes
    "chrony_conf": "/etc/chrony/chrony.conf",
    "chrony_src": "/etc/chrony/sources.d/phantom-mirage.sources",
    "timesyncd_dropin": "/etc/systemd/timesyncd.conf.d/phantom-mirage.conf",
    "chronyc": "/usr/bin/chronyc",
    "timedatectl": "/usr/bin/timedatectl",
    "time_service": None,         # tests only; production asks systemd
    "time_journal": "/var/lib/phantom-mirage/timechange.journal",
}
# phantom-mirage-setup writes /etc/default/farpd with this first line; only
# then does set_network rewrite it (a hand written farpd config is left alone).
FARPD_MARK = "# written by phantom-mirage-setup"
HAND_EDITED = ("decoys.conf was edited by hand since the console last wrote it, so the console will not "
               "overwrite it. To drop the hand edits and all console decoy settings, run on the sensor: "
               "sudo rm /var/lib/phantom-mirage/decoys.json and try again")
PRIVATE = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MIN_PREFIX = 24               # the same limit pm-start applies without ALLOW_WIDE_NETWORK
IFACE_RE = re.compile(r'^[A-Za-z0-9_.-]{1,15}$')
# The include line the postinst adds to the main config (pm-decoys-include).
INCLUDE_RE = re.compile(r'^\s*include\s+"?(/etc/phantom-mirage/decoys\.conf)"?\s*$')
T = {
    "settle": 3.0,            # seconds after reload before the health check
    "restart_wait": 20.0,     # seconds to wait for active after a rollback restart
    "min_interval": 10.0,     # seconds between reloads
    "queue_wait": 25.0,       # how long a change may wait for the lock or the interval
    "idle": 30.0,             # exit after this long without a connection
    "read_timeout": 5.0,
    "ts_window": 60,
    "replay_ttl": 600,
    "verify_timeout": 60,
    "time_wait": 20.0,        # seconds for the time service to reach a new server
    "check_owner": True,      # refuse non root owned or symlinked config paths
}
MAX_REQ = 16384
MAX_PORTS = 64
MAX_ADDRS = 4096
STATES = ("open", "closed", "reset", "block", "filtered")
PROTOS = ("tcp", "udp")
READ_OPS = ("list", "options", "netinfo", "timeinfo")
CHANGE_OPS = ("add", "edit", "start", "stop", "reset", "reset_all", "set_network", "set_time")
OPS = READ_OPS + CHANGE_OPS
HEADER = ("# Generated by pm-decoyd from /var/lib/phantom-mirage/decoys.json.\n"
          "# Do not edit by hand: every change from the console rewrites this file.\n")
ID_RE = re.compile(r'^[A-Za-z0-9-]{1,64}$')
ACTOR_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
NAME_RE = re.compile(r'^[A-Za-z0-9._+-]{1,64}$')
SVC_ID_RE = re.compile(r'^[a-z0-9-]{1,32}$')
FP_RE = re.compile(r'^Fingerprint ([A-Za-z0-9._+-]{1,64})\s*$')
BAD_CHARS = re.compile(r'[\x00-\x1f\x7f"#\\]')


class Err(Exception):
    def __init__(self, code, field=None, message=""):
        Exception.__init__(self, message or code)
        self.code, self.field, self.message = code, field, message or code


def log(prio, msg):
    syslog.syslog(prio, msg)


# ---- JSON framing and envelope ------------------------------------------

def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Err("E_BAD_JSON", None, "duplicate key %s" % k[:32])
        d[k] = v
    return d


def parse_request(raw):
    if len(raw) > MAX_REQ:
        raise Err("E_BAD_JSON", None, "request too large")
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text, object_pairs_hook=_no_dups)
    except Err:
        raise
    except (UnicodeDecodeError, ValueError):
        raise Err("E_BAD_JSON", None, "not JSON")
    if not isinstance(obj, dict):
        raise Err("E_BAD_JSON", None, "not an object")
    return obj


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _str(v, field, rx=None, maxlen=64):
    if not isinstance(v, str):
        raise Err("E_TYPE", field, "%s must be a string" % field)
    if not v or len(v) > maxlen or BAD_CHARS.search(v):
        raise Err("E_TYPE", field, "%s has a bad length or character" % field)
    if rx is not None and not rx.match(v):
        raise Err("E_TYPE", field, "%s has a bad format" % field)
    return v


def _keys(obj, field, required, optional=()):
    if not isinstance(obj, dict):
        raise Err("E_TYPE", field, "%s must be an object" % field)
    for k in obj:
        if k not in required and k not in optional:
            raise Err("E_UNKNOWN_FIELD", ("%s.%s" % (field, k)) if field else k, "unknown field")
    for k in required:
        if k not in obj:
            raise Err("E_MISSING_FIELD", ("%s.%s" % (field, k)) if field else k, "missing field")


def check_envelope(req, now, seen):
    if "v" not in req or not _int(req["v"]) or req["v"] != 1:
        raise Err("E_VERSION", "v", "v must be 1")
    _keys(req, "", ("v", "id", "ts", "actor", "op", "args"))
    _str(req["id"], "id", ID_RE)
    _str(req["actor"], "actor", ACTOR_RE)
    if not _int(req["ts"]):
        raise Err("E_TYPE", "ts", "ts must be an integer")
    if abs(req["ts"] - now) > T["ts_window"]:
        raise Err("E_REPLAY", "ts", "request time is outside the allowed window")
    if req["id"] in seen:
        raise Err("E_REPLAY", "id", "request id already used")
    if not isinstance(req["op"], str) or req["op"] not in OPS:
        raise Err("E_UNKNOWN_OP", "op", "unknown operation")
    if not isinstance(req["args"], dict):
        raise Err("E_TYPE", "args", "args must be an object")


# ---- fixed inputs read from root owned files ------------------------------

def _unquote(v):
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    if any(c in v for c in "\"'`$\\"):
        raise Err("E_INTERNAL", None, "unsupported value in /etc/default/phantom-mirage")
    return v


def read_default():
    """NETWORK and INTERFACE, one KEY=VALUE per line like default-lib.sh."""
    out = {}
    with open(P["default"]) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r'^([A-Z_][A-Z0-9_]*)=(.*)$', s)
            if not m:
                raise Err("E_INTERNAL", None, "unparsable line in /etc/default/phantom-mirage")
            if m.group(1) in ("NETWORK", "INTERFACE"):
                out[m.group(1)] = _unquote(m.group(2))
    nets = []
    for w in out.get("NETWORK", "").split():
        try:
            nets.append(ipaddress.IPv4Network(w, strict=False))
        except ValueError:
            raise Err("E_INTERNAL", None, "NETWORK is not an IPv4 range")
    if not nets:
        raise Err("E_INTERNAL", None, "NETWORK is not set")
    iface = out.get("INTERFACE", "")
    if iface and not re.match(r'^[A-Za-z0-9_.:-]{1,15}$', iface):
        raise Err("E_INTERNAL", None, "INTERFACE is not valid")
    return nets, iface


def personalities():
    with open(P["fpdb"], "rb") as f:
        data = f.read()
    with open(P["fpdb_sha"]) as f:
        pinned = f.read().split()[0].strip().lower()
    if hashlib.sha256(data).hexdigest() != pinned:
        raise Err("E_INTERNAL", None, "personality database does not match its pinned sha256")
    out = []
    for line in data.decode("utf-8", "replace").splitlines():
        m = FP_RE.match(line)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def services():
    with open(P["services"]) as f:
        d = json.load(f, object_pairs_hook=_no_dups)
    out = {}
    for s in d.get("services", []):
        sid, proto, act = s.get("id"), s.get("proto"), s.get("action")
        port = s.get("port")
        if not (isinstance(sid, str) and SVC_ID_RE.match(sid) and proto in PROTOS
                and _int(port) and 1 <= port <= 65535 and act in STATES
                and isinstance(s.get("label"), str) and not BAD_CHARS.search(s["label"])):
            raise Err("E_INTERNAL", None, "bad entry in the service list")
        out[sid] = {"id": sid, "label": s["label"], "proto": proto, "port": port, "action": act}
    return out


def main_conf():
    """Return (text, set of bound IPv4 addresses outside the include)."""
    with open(P["main_conf"]) as f:
        text = f.read()
    binds = set()
    has_inc = False
    for line in text.splitlines():
        if INCLUDE_RE.match(line):
            has_inc = True
            continue
        m = re.match(r'^\s*bind\s+(\S+)\s', line)
        if m:
            try:
                binds.add(str(ipaddress.IPv4Address(m.group(1))))
            except ValueError:
                pass
    if not has_inc:
        raise Err("E_INTERNAL", None, "phantom-mirage.conf has no include line for decoys.conf")
    return text, binds


def check_paths():
    if not T["check_owner"]:
        return
    d = os.path.dirname(P["decoys_conf"])
    st = os.lstat(d)
    import stat as S
    if not S.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Err("E_INTERNAL", None, "%s must be a root owned directory not writable by others" % d)
    for p in (P["decoys_conf"], P["main_conf"]):
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            continue
        if not S.S_ISREG(st.st_mode) or st.st_uid != 0:
            raise Err("E_INTERNAL", None, "%s must be a root owned regular file" % p)


# ---- validation of a decoy object -----------------------------------------

def check_ip(v, field, nets, binds, reserved=True):
    _str(v, field, maxlen=15)
    try:
        ip = ipaddress.IPv4Address(v)
    except ValueError:
        raise Err("E_INVALID_ADDRESS", field, "not a valid IPv4 address")
    if str(ip) != v:
        raise Err("E_INVALID_ADDRESS", field, "use the canonical dotted form")
    owner = [n for n in nets if ip in n]
    if not owner:
        raise Err("E_ADDRESS_OUTSIDE_NETWORK", field, "%s is not inside %s" % (
            v, " ".join(str(n) for n in nets)))
    n = owner[0]
    if reserved and n.prefixlen <= 30 and ip in (n.network_address, n.broadcast_address):
        raise Err("E_ADDRESS_RESERVED", field, "%s is the network or broadcast address" % v)
    if v in binds:
        raise Err("E_ADDRESS_IN_MAIN_CONF", field, "%s is bound in phantom-mirage.conf" % v)
    return v


def check_decoy(d, nets, binds, pers, svcs):
    _keys(d, "decoy", ("ip", "personality", "defaults", "ports"))
    ip = check_ip(d["ip"], "decoy.ip", nets, binds)
    p = d["personality"]
    if p is not None:
        _str(p, "decoy.personality", NAME_RE)
        if p not in pers:
            raise Err("E_INVALID_PERSONALITY", "decoy.personality", "unknown personality")
    _keys(d["defaults"], "decoy.defaults", ("tcp", "udp", "icmp"))
    defaults = {}
    for k in ("tcp", "udp", "icmp"):
        v = d["defaults"][k]
        if not isinstance(v, str) or v not in STATES:
            raise Err("E_INVALID_STATE", "decoy.defaults." + k, "not an allowed action")
        defaults[k] = v
    ports = d["ports"]
    if not isinstance(ports, list):
        raise Err("E_TYPE", "decoy.ports", "ports must be a list")
    if len(ports) > MAX_PORTS:
        raise Err("E_TOO_MANY_PORTS", "decoy.ports", "at most %d ports" % MAX_PORTS)
    out, seen = [], set()
    for i, e in enumerate(ports):
        f = "decoy.ports[%d]" % i
        if not isinstance(e, dict):
            raise Err("E_TYPE", f, "port entry must be an object")
        kind = [k for k in ("state", "service") if k in e]
        if len(kind) != 1:
            raise Err("E_MISSING_FIELD", f, "exactly one of state or service")
        _keys(e, f, ("proto", "port", kind[0]))
        if not isinstance(e["proto"], str) or e["proto"] not in PROTOS:
            raise Err("E_INVALID_PORT", f + ".proto", "proto must be tcp or udp")
        if not _int(e["port"]) or not 1 <= e["port"] <= 65535:
            raise Err("E_INVALID_PORT", f + ".port", "port must be 1 to 65535")
        key = (e["proto"], e["port"])
        if key in seen:
            raise Err("E_INVALID_PORT", f, "duplicate %s/%d" % key)
        seen.add(key)
        if kind[0] == "state":
            if not isinstance(e["state"], str) or e["state"] not in STATES:
                raise Err("E_INVALID_STATE", f + ".state", "not an allowed action")
            out.append({"proto": e["proto"], "port": e["port"], "state": e["state"]})
        else:
            sid = e["service"]
            if not isinstance(sid, str) or sid not in svcs:
                raise Err("E_INVALID_SERVICE", f + ".service", "unknown service")
            if svcs[sid]["proto"] != e["proto"]:
                raise Err("E_INVALID_SERVICE", f + ".service", "service uses %s" % svcs[sid]["proto"])
            out.append({"proto": e["proto"], "port": e["port"], "service": sid})
    out.sort(key=lambda x: (x["proto"], x["port"]))
    return ip, {"personality": p, "defaults": defaults, "ports": out}


def _rev(args, field="expect_rev", required=True):
    if field not in args:
        if required:
            raise Err("E_MISSING_FIELD", "args." + field, "missing field")
        return None
    if not _int(args[field]) or args[field] < 0:
        raise Err("E_TYPE", "args." + field, "must be a non negative integer")
    return args[field]


# ---- store and rendering ----------------------------------------------------

def empty_store():
    return {"v": 1, "overrides": {}, "conf_sha256": None}


def load_store():
    try:
        with open(P["store"]) as f:
            s = json.load(f)
    except FileNotFoundError:
        return empty_store()
    if not isinstance(s, dict) or s.get("v") != 1 or not isinstance(s.get("overrides"), dict):
        raise Err("E_INTERNAL", None, "decoys.json is not in the expected format")
    s.setdefault("conf_sha256", None)
    return s


def tname(ip, stopped):
    return ("pm_s_" if stopped else "pm_d_") + ip.replace(".", "_")


def render(store, svcs):
    out = [HEADER]
    for ip in sorted(store["overrides"], key=lambda a: int(ipaddress.IPv4Address(a))):
        o = store["overrides"][ip]
        str(ipaddress.IPv4Address(ip))   # never trust the store blindly
        lines = []
        if o["state"] == "stopped":
            t = tname(ip, True)
            lines.append("create %s" % t)
            for proto in ("tcp", "udp", "icmp"):
                lines.append("set %s default %s action block" % (t, proto))
        else:
            d = o["decoy"]
            t = tname(ip, False)
            lines.append("create %s" % t)
            if d["personality"] is not None:
                if not NAME_RE.match(d["personality"]):
                    raise Err("E_INTERNAL", None, "bad personality in store")
                lines.append('set %s personality "%s"' % (t, d["personality"]))
            for proto in ("tcp", "udp", "icmp"):
                a = d["defaults"][proto]
                if a not in STATES:
                    raise Err("E_INTERNAL", None, "bad action in store")
                lines.append("set %s default %s action %s" % (t, proto, a))
            for e in d["ports"]:
                act = e["state"] if "state" in e else svcs[e["service"]]["action"]
                if act not in STATES or e["proto"] not in PROTOS or not 1 <= int(e["port"]) <= 65535:
                    raise Err("E_INTERNAL", None, "bad port in store")
                lines.append("add %s %s port %d %s" % (t, e["proto"], int(e["port"]), act))
        lines.append("bind %s %s" % (ip, t))
        out.append("\n" + "\n".join(lines) + "\n")
    return "".join(out)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ---- operations -------------------------------------------------------------

def public(ip, o):
    r = {"ip": ip, "source": "override", "state": o["state"], "rev": o["rev"]}
    if o["decoy"] is not None:
        r.update(o["decoy"])
    else:
        r["personality"] = None
        r["uses_default"] = True
    return r


def apply_op(op, args, store, nets, binds, pers, svcs):
    """Return (new_store, result). Raises Err. Never touches files."""
    ov = {k: dict(v) for k, v in store["overrides"].items()}
    new = {"v": 1, "overrides": ov, "conf_sha256": store.get("conf_sha256")}
    if op == "add":
        _keys(args, "args", ("decoy",))
        ip, d = check_decoy(args["decoy"], nets, binds, pers, svcs)
        if ip in ov:
            raise Err("E_EXISTS", "decoy.ip", "%s already has its own settings" % ip)
        ov[ip] = {"rev": 1, "state": "running", "decoy": d}
        return new, {"ip": ip, "state": "running", "rev": 1}
    if op == "edit":
        _keys(args, "args", ("decoy", "expect_rev"))
        rev = _rev(args)
        ip, d = check_decoy(args["decoy"], nets, binds, pers, svcs)
        o = ov.get(ip)
        if o is None:
            raise Err("E_NOT_FOUND", "decoy.ip", "%s has no settings of its own" % ip)
        if o["rev"] != rev:
            raise Err("E_CONFLICT", "args.expect_rev", "settings changed since you loaded them")
        ov[ip] = {"rev": rev + 1, "state": o["state"], "decoy": d}
        return new, {"ip": ip, "state": o["state"], "rev": rev + 1}
    if op in ("stop", "start", "reset"):
        _keys(args, "args", ("ip",), ("expect_rev",))
        ip = check_ip(args["ip"], "args.ip", nets, binds)
        o = ov.get(ip)
        rev = _rev(args, required=o is not None)
        if o is not None and o["rev"] != rev:
            raise Err("E_CONFLICT", "args.expect_rev", "settings changed since you loaded them")
        if op == "stop":
            if o is None:
                ov[ip] = {"rev": 1, "state": "stopped", "decoy": None}
                return new, {"ip": ip, "state": "stopped", "rev": 1, "arp": "still_answered"}
            if o["state"] == "stopped":
                raise Err("E_NOT_RUNNING", "args.ip", "%s is already stopped" % ip)
            ov[ip] = dict(o, state="stopped", rev=rev + 1)
            return new, {"ip": ip, "state": "stopped", "rev": rev + 1, "arp": "still_answered"}
        if o is None:
            raise Err("E_NOT_FOUND", "args.ip", "%s has no settings of its own" % ip)
        if op == "start":
            if o["state"] != "stopped":
                raise Err("E_NOT_STOPPED", "args.ip", "%s is not stopped" % ip)
            if o["decoy"] is None:
                del ov[ip]
                return new, {"ip": ip, "state": "running", "source": "default"}
            ov[ip] = dict(o, state="running", rev=rev + 1)
            return new, {"ip": ip, "state": "running", "rev": rev + 1}
        # reset: back to the default template (the decoy itself stays)
        del ov[ip]
        return new, {"ip": ip, "source": "default"}
    if op == "reset_all":
        _keys(args, "args", ("confirm",))
        if args["confirm"] != "reset-all":
            raise Err("E_TYPE", "args.confirm", 'confirm must be "reset-all"')
        new["overrides"] = {}
        return new, {"overrides": 0}
    raise Err("E_UNKNOWN_OP", "op", "unknown operation")


def op_list(store, nets, binds):
    decoys = []
    for n in nets:
        if n.num_addresses > MAX_ADDRS:
            raise Err("E_INTERNAL", None, "NETWORK is too large to list")
        for a in n:
            ip = str(a)
            o = store["overrides"].get(ip)
            if o is not None:
                decoys.append(public(ip, o))
            else:
                decoys.append({"ip": ip, "source": "main_conf" if ip in binds else "default"})
    return {"network": " ".join(str(n) for n in nets), "decoys": decoys}


def op_options(pers, svcs):
    return {"personalities": pers, "states": list(STATES),
            "services": [{k: s[k] for k in ("id", "label", "proto", "port")} for s in svcs.values()],
            "max_ports": MAX_PORTS}


# ---- files, verify, systemctl ---------------------------------------------

def write_excl(path, data, mode):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data.encode() if isinstance(data, str) else data)
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_dir(d):
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_file(path, data, mode):
    tmp = path + ".tmp"
    write_excl(tmp, data, mode)
    os.rename(tmp, path)
    fsync_dir(os.path.dirname(path))


def read_or_none(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def verify(candidate, main_text, iface, nets):
    """Run --verify-config on a temp copy of the main config whose include
    line names the candidate file. The real include path is fixed, so the
    real main config cannot be used for a candidate."""
    tmp_main = os.path.join(os.path.dirname(P["decoys_conf"]), ".pm-decoyd-verify.conf")
    lines, n = [], 0
    for line in main_text.splitlines(True):
        if INCLUDE_RE.match(line):
            lines.append("include %s\n" % candidate)
            n += 1
        else:
            lines.append(line)
    if n != 1:
        raise Err("E_INTERNAL", None, "expected exactly one include line, found %d" % n)
    write_excl(tmp_main, "".join(lines), 0o644)
    argv = [P["daemon"], "--verify-config", "-f", tmp_main, "-p", P["fpdb"]]
    for k in ("-a", "-0", "-x", "-m"):
        argv += [k, P["data"][k]]
    if iface:
        argv += ["-i", iface]
    argv += [str(n) for n in nets]
    try:
        r = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=T["verify_timeout"],
                           close_fds=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        rc, out = r.returncode, r.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        rc, out = -1, "verify timed out"
    finally:
        try:
            os.unlink(tmp_main)
        except FileNotFoundError:
            pass
    if rc != 0:
        msg = [l for l in out.splitlines() if l.strip()]
        # prefer the parser's "file:line: reason" over the generic summary
        first = next((l for l in msg if re.search(r':\d+: ', l)), None) or \
            next((l for l in msg if "error" in l.lower() or "fail" in l.lower()), msg[0] if msg else "")
        first = first.replace(candidate, "decoys.conf")
        raise Err("E_VERIFY_FAILED", None, "rejected by the sensor's config check: %s" % first[:300])


# The only systemctl calls this helper makes. Anything else is a bug and
# is refused before it runs.
SYSTEMCTL_VERBS = {"is-active", "show", "restart", "reload", "daemon-reload"}
SYSTEMCTL_UNITS = ("phantom-mirage.service", "phantom-mirage-firewall.service", "farpd.service",
                   "chrony.service", "chronyd.service", "systemd-timesyncd.service")


def systemctl(*args):
    units = [a for a in args[1:] if not a.startswith("-") and a not in ("MainPID", "NeedDaemonReload", "LoadState")]
    if not args or args[0] not in SYSTEMCTL_VERBS or any(
            u not in SYSTEMCTL_UNITS + (P["unit"], P["firewall_unit"], P["farpd_unit"]) for u in units) \
            or (args[0] == "daemon-reload" and len(args) > 1):
        log(syslog.LOG_ERR, "refused systemctl %s" % " ".join(args)[:200])
        return -1, "refused"
    try:
        r = subprocess.run([P["systemctl"]] + list(args), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60,
                           close_fds=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return r.returncode, r.stdout.decode("utf-8", "replace").strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"


def reload_units_if_stale():
    """This helper never writes unit files (the block lives in
    /etc/default/phantom-mirage, read by pm-start, not EnvironmentFile=).
    But if a unit file changed on disk without a daemon-reload (a manual
    copy, an interrupted upgrade), restart would use the old definition
    and systemctl status would warn; reload systemd first."""
    units = [P["unit"], P["firewall_unit"]]
    if any(systemctl("show", "-p", "NeedDaemonReload", "--value", u)[1] == "yes" for u in units):
        log(syslog.LOG_WARNING, "unit files changed on disk without daemon-reload; reloading systemd")
        systemctl("daemon-reload")


def is_active():
    return systemctl("is-active", P["unit"])[1] == "active"


def main_pid():
    rc, out = systemctl("show", "-p", "MainPID", "--value", P["unit"])
    return out if rc == 0 else ""


def wait_active(limit):
    end = time.monotonic() + limit
    while True:
        if is_active():
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(1.0)


# ---- the change pipeline ---------------------------------------------------

class Helper:
    def __init__(self):
        self.seen = {}

    def _rf(self, name):
        return os.path.join(P["rundir"], name)

    def _load_seen(self, now):
        try:
            with open(self._rf("seen.json")) as f:
                d = json.load(f)
            for k, v in d.items():
                if isinstance(k, str) and isinstance(v, (int, float)):
                    self.seen.setdefault(k, v)
        except (FileNotFoundError, ValueError):
            pass
        self.seen = {k: v for k, v in self.seen.items() if now - v < T["replay_ttl"]}

    def _remember(self, rid, now):
        self.seen[rid] = now
        try:
            replace_file(self._rf("seen.json"), json.dumps(self.seen), 0o600)
        except OSError:
            pass

    def _last_reload(self):
        try:
            with open(self._rf("last_reload")) as f:
                return float(f.read().strip() or 0)
        except (FileNotFoundError, ValueError):
            return 0.0

    def handle(self, req, now=None):
        """req is the parsed dict. Returns the response dict."""
        now = int(time.time()) if now is None else now
        rid = req.get("id") if isinstance(req.get("id"), str) and ID_RE.match(req.get("id", "")) else ""
        resp = {"v": 1, "id": rid, "ok": False, "reloaded": False, "rolled_back": False}
        try:
            self._load_seen(now)
            check_envelope(req, now, self.seen)
            self._remember(rid, now)
            op, args = req["op"], req["args"]
            log(syslog.LOG_INFO, "request id=%s actor=%s op=%s" % (rid, req["actor"], op))
            if op in READ_OPS:
                _keys(args, "args", ())
                if op == "timeinfo":
                    resp["result"] = op_timeinfo()
                elif op == "netinfo":
                    resp["result"] = op_netinfo()
                elif op == "list":
                    nets, _ = read_default()
                    _, binds = main_conf()
                    resp["result"] = op_list(load_store(), nets, binds)
                else:
                    resp["result"] = op_options(personalities(), services())
                resp["ok"] = True
                return resp
            if op == "set_time":
                res, reloaded = set_time(self, args, req["actor"], rid)
            elif op == "set_network":
                res, reloaded = self.set_network(args, req["actor"], rid)
            else:
                res, reloaded = self.change(op, args, req["actor"], rid)
            resp.update(ok=True, result=res, reloaded=reloaded)
        except Err as e:
            resp["error"] = {"code": e.code, "field": e.field, "message": e.message}
            resp["reloaded"] = getattr(e, "reloaded", False)
            resp["rolled_back"] = getattr(e, "rolled_back", False)
            log(syslog.LOG_WARNING if e.code not in ("E_ROLLBACK_FAILED", "E_INTERNAL") else syslog.LOG_ERR,
                "refused id=%s code=%s field=%s: %s" % (rid, e.code, e.field, e.message))
        except Exception as e:  # never leak a traceback to the client
            resp["error"] = {"code": "E_INTERNAL", "field": None, "message": "internal error"}
            log(syslog.LOG_ERR, "internal error id=%s: %s: %s" % (rid, e.__class__.__name__, e))
        return resp

    def _lock(self):
        fd = os.open(self._rf("lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        end = time.monotonic() + T["queue_wait"]
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                if time.monotonic() >= end:
                    os.close(fd)
                    raise Err("E_BUSY", None, "another change is in progress, try again")
                time.sleep(0.2)

    def _wait_interval(self):
        # Changes queue: wait out the rest of min_interval since the last
        # reload (never longer, even if the clock moved back).
        gap = min(T["min_interval"], T["min_interval"] - (time.time() - self._last_reload()))
        if gap > 0:
            time.sleep(gap)

    def change(self, op, args, actor, rid):
        lock = self._lock()
        try:
            recover_journal()
            self._wait_interval()
            check_paths()
            nets, iface = read_default()
            main_text, binds = main_conf()
            pers, svcs = personalities(), services()
            store = load_store()
            cur = read_or_none(P["decoys_conf"])
            if op != "reset_all" and cur is not None and store.get("conf_sha256") \
                    and sha(cur) != store["conf_sha256"]:
                raise Err("E_CONFLICT", None, HAND_EDITED)
            new, result = apply_op(op, args, store, nets, binds, pers, svcs)
            text = render(new, svcs)
            new["conf_sha256"] = sha(text)
            diff = "".join(difflib.unified_diff((cur or "").splitlines(True), text.splitlines(True),
                                                "decoys.conf", "decoys.conf.new", n=0))
            log(syslog.LOG_INFO, "id=%s actor=%s op=%s diff:\n%s" % (rid, actor, op, diff[:4000]))
            return result, self._swap_and_reload(text, cur, main_text, iface, nets, new, rid)
        finally:
            os.close(lock)

    # ---- address block change -------------------------------------------
    def set_network(self, args, actor, rid):
        """Change NETWORK and INTERFACE in /etc/default/phantom-mirage (and
        /etc/default/farpd when phantom-mirage-setup wrote it), drop the
        per decoy settings that fall outside the new block, verify, swap
        every file, restart the sensor, then the firewall and farpd. The result
        is kept in P["outcome"] for a console whose request was cut off. On any
        failure every file is put back BEFORE the units restart."""
        lock = self._lock()
        try:
            recover_journal()
            self._wait_interval()
            check_paths()
            old_nets, old_iface = read_default()
            _keys(args, "args", ("network", "interface", "expect"))
            _keys(args["expect"], "args.expect", ("network", "interface"))
            if args["expect"]["network"] != " ".join(str(n) for n in old_nets) or \
                    args["expect"]["interface"] != old_iface:
                raise Err("E_CONFLICT", "args.expect", "the address block changed since you loaded it")
            info = host_info()
            net, iface = check_network(args["network"], args["interface"], info)
            if [net] == old_nets and iface == old_iface:
                raise Err("E_UNCHANGED", "args.network", "that is already the address block")
            main_text, binds = main_conf()
            svcs = services()
            store = load_store()
            cur = read_or_none(P["decoys_conf"])
            if cur is not None and store.get("conf_sha256") and sha(cur) != store["conf_sha256"]:
                raise Err("E_CONFLICT", None, HAND_EDITED)
            new, dropped = retarget_store(store, net)
            text = render(new, svcs)
            new["conf_sha256"] = sha(text)
            dflt_old = read_or_none(P["default"])
            dflt_new = rewrite_default(dflt_old, str(net), iface)
            farpd_old = read_or_none(P["farpd_default"])
            farpd_new = None
            if farpd_old is not None and farpd_old.startswith(FARPD_MARK):
                farpd_new = rewrite_default(farpd_old, str(net), iface)
            # verify the new decoys.conf with the new interface and block
            cand = P["decoys_conf"] + ".new"
            write_excl(cand, text, 0o644)
            try:
                verify(cand, main_text, iface, [net])
            finally:
                try:
                    os.unlink(cand)
                except FileNotFoundError:
                    pass
            log(syslog.LOG_INFO, "id=%s actor=%s set_network %s %s -> %s %s, dropped %s" % (
                rid, actor, old_iface, " ".join(map(str, old_nets)), iface, net, " ".join(dropped) or "none"))
            files = [(P["default"], dflt_old, dflt_new, 0o644),
                     (P["decoys_conf"], cur, text, 0o644),
                     (P["store"], read_or_none(P["store"]), json.dumps(new, indent=1, sort_keys=True), 0o600)]
            if farpd_new is not None:
                files.append((P["farpd_default"], farpd_old, farpd_new, 0o644))
            was_active = is_active()
            prev = {"network": " ".join(str(n) for n in old_nets), "interface": old_iface}
            for path, old, data, mode in files:
                if old is not None:
                    replace_file(path + ".prev", old, mode)
            replace_file(P["journal"], json.dumps(
                {"id": rid, "files": [[path, old is not None, mode] for path, old, data, mode in files]}), 0o600)
            try:
                for path, old, data, mode in files:
                    replace_file(path, data, mode)
            except OSError as e:
                self._restore(files, rid)
                clear_journal()
                raise Err("E_INTERNAL", None, "could not write the new files (%s); nothing changed" % e.__class__.__name__)
            result = {"network": str(net), "interface": iface, "dropped": dropped,
                      "farpd": farpd_new is not None, "restarted": was_active}
            replace_file(self._rf("last_reload"), "%f" % time.time(), 0o600)
            if not was_active:
                clear_journal()
                record_outcome(rid, "applied_not_running", str(net), iface, prev, dropped)
                log(syslog.LOG_INFO, "id=%s address block changed, sensor not running, not started" % rid)
                self._restart_aux(farpd_new is not None)
                return result, False
            reload_units_if_stale()
            rc, out = systemctl("restart", P["unit"])
            if rc == 0 and wait_active(T["restart_wait"]) and (time.sleep(T["settle"]) or is_active()):
                clear_journal()
                record_outcome(rid, "applied", str(net), iface, prev, dropped)
                bad = self._restart_aux(farpd_new is not None)
                if bad:
                    result["warnings"] = bad
                log(syslog.LOG_INFO, "id=%s address block changed and sensor restarted" % rid)
                return result, True
            log(syslog.LOG_ERR, "id=%s restart on the new block failed (rc=%s %s), restoring" % (rid, rc, out[:200]))
            self._restore(files, rid)
            clear_journal()
            systemctl("restart", P["unit"])
            ok = wait_active(T["restart_wait"])
            record_outcome(rid, "rolled_back" if ok else "rollback_failed", prev["network"], prev["interface"], prev)
            self._restart_aux(farpd_new is not None)
            if ok:
                e = Err("E_RESTART_FAILED_ROLLED_BACK", None,
                        "the sensor did not start on the new block; the previous block is back and the sensor restarted")
            else:
                log(syslog.LOG_CRIT, "id=%s sensor is down after restoring the previous block" % rid)
                e = Err("E_ROLLBACK_FAILED", None, "sensor is down after rollback; see the journal for phantom-mirage")
            e.reloaded, e.rolled_back = True, True
            raise e
        finally:
            os.close(lock)

    def _restore(self, files, rid):
        for path, old, data, mode in files:
            try:
                if old is None:
                    os.unlink(path)
                else:
                    replace_file(path, old, mode)
            except FileNotFoundError:
                pass
            except OSError as e:
                log(syslog.LOG_CRIT, "id=%s could not restore %s: %s" % (rid, path, e))

    def _restart_aux(self, farpd):
        """The firewall first, then farpd (only if we rewrote its file);
        each only when it is already active. Used after a good restart and
        after a rollback. Failures are warnings: the sensor is up.

        The firewall is RELOADED, never restarted: the console unit has
        Requires=phantom-mirage-firewall.service, so a restart would also
        restart the console, cutting the request that asked for this change
        and ending every console session. Its ExecReload applies the new
        rules in one nft transaction."""
        bad = []
        units = [(P["firewall_unit"], "reload")] + ([(P["farpd_unit"], "restart")] if farpd else [])
        for u, how in units:
            if systemctl("is-active", u)[1] != "active":
                continue
            rc, out = systemctl(how, u)
            if rc != 0:
                bad.append("%s did not %s" % (u, how))
                log(syslog.LOG_ERR, "%s %s failed: %s" % (how, u, out[:200]))
        return bad

    def _swap_and_reload(self, text, cur, main_text, iface, nets, new, rid):
        live = P["decoys_conf"]
        cand, prev = live + ".new", live + ".prev"
        write_excl(cand, text, 0o644)
        try:
            verify(cand, main_text, iface, nets)
        except Err:
            os.unlink(cand)
            raise
        if cur is not None:
            replace_file(prev, cur, 0o644)
        os.rename(cand, live)
        fsync_dir(os.path.dirname(live))
        if not is_active():
            # Sensor not running: the file is in place for its next start
            # (pm-start verify checks it then). Nothing to reload.
            replace_file(P["store"], json.dumps(new, indent=1, sort_keys=True), 0o600)
            log(syslog.LOG_INFO, "id=%s applied, sensor not running, no reload" % rid)
            return False
        pid = main_pid()
        rc, out = systemctl("reload", P["unit"])
        replace_file(self._rf("last_reload"), "%f" % time.time(), 0o600)
        time.sleep(T["settle"])
        if rc == 0 and is_active() and main_pid() == pid and pid not in ("", "0"):
            replace_file(P["store"], json.dumps(new, indent=1, sort_keys=True), 0o600)
            log(syslog.LOG_INFO, "id=%s applied and reloaded" % rid)
            return True
        log(syslog.LOG_ERR, "id=%s reload failed (rc=%s %s), restoring previous decoys.conf" % (rid, rc, out[:200]))
        # Restore BEFORE restart: RestartPreventExitStatus=78 means a
        # restart onto the bad file could stop the unit for good.
        replace_file(live, cur if cur is not None else HEADER, 0o644)
        systemctl("restart", P["unit"])
        e = None
        if wait_active(T["restart_wait"]):
            e = Err("E_RELOAD_FAILED_ROLLED_BACK", None,
                    "change failed, previous decoys restored and the sensor restarted")
        else:
            log(syslog.LOG_CRIT, "id=%s sensor is down after rollback" % rid)
            e = Err("E_ROLLBACK_FAILED", None, "sensor is down after rollback; see the journal for phantom-mirage")
        e.reloaded, e.rolled_back = True, True
        raise e


# ---- address block ---------------------------------------------------------

def record_outcome(rid, result, network, interface, old, dropped=()):
    """Keep the result of the last address block change so the console can
    show it even if the HTTP request that asked for it was cut off."""
    try:
        replace_file(P["outcome"], json.dumps({
            "id": rid, "result": result, "network": network, "interface": interface,
            "previous": old, "dropped": list(dropped), "time": time.time()}), 0o644)
    except OSError as e:
        log(syslog.LOG_ERR, "could not record the change outcome: %s" % e)


def last_outcome():
    try:
        with open(P["outcome"]) as f:
            o = json.load(f)
        return o if isinstance(o, dict) else None
    except (OSError, ValueError):
        return None


def clear_journal():
    try:
        os.unlink(P["journal"])
    except FileNotFoundError:
        pass


def recover_journal():
    """A set_network swap was cut off (crash or kill between renames):
    put every listed file back from its .prev copy (or remove it if it did
    not exist before), then restart the sensor if it is running. Returns
    True if it recovered something."""
    try:
        with open(P["journal"]) as f:
            j = json.load(f)
        files = [(str(p), bool(had), int(m)) for p, had, m in j["files"]]
    except FileNotFoundError:
        return False
    except (ValueError, KeyError, TypeError) as e:
        log(syslog.LOG_CRIT, "netchange journal unreadable (%s), left for the admin" % e)
        raise Err("E_INTERNAL", None, "an interrupted address block change needs checking: " + P["journal"])
    allowed = {P["default"], P["decoys_conf"], P["store"], P["farpd_default"]}
    for path, had, mode in files:
        if path not in allowed:
            raise Err("E_INTERNAL", None, "unexpected path in " + P["journal"])
    for path, had, mode in files:
        if had:
            with open(path + ".prev") as f:
                replace_file(path, f.read(), mode)
        else:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    clear_journal()
    log(syslog.LOG_CRIT, "interrupted address block change %s: previous files restored" % j.get("id", "?"))
    nets, iface = read_default()
    cur = " ".join(str(n) for n in nets)
    record_outcome(str(j.get("id", "")), "interrupted", cur, iface, {"network": cur, "interface": iface})
    if is_active():
        systemctl("restart", P["unit"])
    return True


def host_info():
    """Interfaces with their IPv4 addresses (prefix included) and the
    default gateways, from iproute2's JSON output. Read only."""
    def ipj(*a):
        try:
            r = subprocess.run([P["ip"], "-j", "-4"] + list(a), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                               close_fds=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            return json.loads(r.stdout.decode() or "[]") if r.returncode == 0 else []
        except (subprocess.TimeoutExpired, ValueError, OSError):
            return []
    ifaces = {}
    for i in ipj("addr", "show"):
        name = i.get("ifname")
        if not isinstance(name, str) or not IFACE_RE.match(name):
            continue
        addrs = []
        for a in i.get("addr_info") or []:
            try:
                addrs.append(ipaddress.IPv4Interface("%s/%s" % (a["local"], a["prefixlen"])))
            except (KeyError, ValueError, TypeError):
                pass
        ifaces[name] = {"addrs": addrs, "up": "UP" in (i.get("flags") or []), "lo": "LOOPBACK" in (i.get("flags") or [])}
    gws = []
    for rt in ipj("route", "show", "default"):
        try:
            g = ipaddress.IPv4Address(rt["gateway"])
            if g not in gws:
                gws.append(g)
        except (KeyError, ValueError, TypeError):
            pass
    return {"ifaces": ifaces, "gateways": gws}


def check_network(v, iface, info):
    """The new block: one IPv4 CIDR, private, /24 to /32, on the LAN of
    the chosen interface, and not holding any of this host's addresses or
    a gateway."""
    _str(v, "args.network", maxlen=18)
    _str(iface, "args.interface", IFACE_RE, maxlen=15)
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', v):
        raise Err("E_INVALID_NETWORK", "args.network", "write the block as address/prefix, e.g. 192.168.50.8/29")
    try:
        net = ipaddress.IPv4Network(v, strict=True)
    except ValueError as e:
        if "host bits" in str(e):
            n = ipaddress.IPv4Network(v, strict=False)
            raise Err("E_INVALID_NETWORK", "args.network", "%s is not the start of a block; did you mean %s?" % (v, n))
        raise Err("E_INVALID_NETWORK", "args.network", "not a valid IPv4 block")
    if net.prefixlen < MIN_PREFIX:
        raise Err("E_NETWORK_TOO_WIDE", "args.network", "use a block of /%d or smaller (at most 256 addresses)" % MIN_PREFIX)
    if not any(net.subnet_of(p) for p in PRIVATE):
        raise Err("E_NOT_PRIVATE", "args.network", "use a private range (10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16)")
    i = info["ifaces"].get(iface)
    if i is None or not os.path.exists(os.path.join(P["sysfs_net"], iface)):
        raise Err("E_INVALID_INTERFACE", "args.interface", "interface %s does not exist" % iface)
    if i["lo"]:
        raise Err("E_INVALID_INTERFACE", "args.interface", "the loopback interface cannot carry decoys")
    lans = [a.network for a in i["addrs"]]
    if not lans:
        raise Err("E_INVALID_INTERFACE", "args.interface", "%s has no IPv4 address, so its LAN is unknown" % iface)
    if not any(net.subnet_of(l) for l in lans):
        raise Err("E_NOT_ON_LAN", "args.network", "%s is not inside the LAN of %s (%s)" % (
            net, iface, ", ".join(str(l) for l in lans)))
    for name, x in info["ifaces"].items():
        for a in x["addrs"]:
            if a.ip in net:
                raise Err("E_HOST_ADDRESS", "args.network", "%s includes this sensor's own address %s (%s)" % (net, a.ip, name))
    for g in info["gateways"]:
        if g in net:
            raise Err("E_GATEWAY", "args.network", "%s includes the gateway %s" % (net, g))
    for l in lans:
        if net.subnet_of(l) and l.prefixlen <= 30 and \
                (l.network_address in net or l.broadcast_address in net):
            raise Err("E_LAN_EDGE", "args.network", "%s includes the network or broadcast address of the LAN %s" % (net, l))
    return net, iface


def retarget_store(store, net):
    """Copy of the store keeping only overrides inside net and not on its
    network or broadcast address. Returns (store, dropped ips)."""
    new = copy.deepcopy(store)
    dropped = []
    for ip in sorted(new["overrides"], key=lambda a: ipaddress.IPv4Address(a)):
        a = ipaddress.IPv4Address(ip)
        if a not in net or (net.prefixlen <= 30 and a in (net.network_address, net.broadcast_address)):
            dropped.append(ip)
            del new["overrides"][ip]
    return new, dropped


def rewrite_default(text, network, iface):
    """Replace exactly one NETWORK= and one INTERFACE= line, keep the rest
    byte for byte. Both values were validated before."""
    out, seen = [], {"NETWORK": 0, "INTERFACE": 0}
    for line in (text or "").splitlines(True):
        m = re.match(r'^(\s*)(NETWORK|INTERFACE)=', line)
        if m:
            seen[m.group(2)] += 1
            out.append('%s%s="%s"\n' % (m.group(1), m.group(2), network if m.group(2) == "NETWORK" else iface))
        else:
            out.append(line)
    if seen != {"NETWORK": 1, "INTERFACE": 1}:
        raise Err("E_INTERNAL", None, "expected one NETWORK and one INTERFACE line in the settings file")
    return "".join(out)


def op_netinfo():
    nets, iface = read_default()
    info = host_info()
    return {"network": " ".join(str(n) for n in nets), "interface": iface,
            "interfaces": [{"name": n, "addrs": [str(a) for a in x["addrs"]]}
                           for n, x in sorted(info["ifaces"].items()) if not x["lo"] and x["addrs"]],
            "gateways": sorted({str(g) for g in info["gateways"]}, key=ipaddress.IPv4Address),
            "last_change": last_outcome(),
            "min_prefix": MIN_PREFIX}


# ---- time source (timeinfo, set_time) ---------------------------------------
#
# The sensor's clock comes from chrony or systemd-timesyncd, whichever runs.
# phantom-mirage-setup sets that service up for local NTP servers only (for
# chrony it sets aside the internet pool files). set_time changes just the
# server list in this helper's own file, restarts only that time service,
# waits for it to reach one of the servers and rolls back if it does not
# (unless the admin asked to keep the change anyway). No NTS, no pools.

TIME_UNITS = {"chrony": ("chrony.service", "chronyd.service"), "timesyncd": ("systemd-timesyncd.service",)}
TIME_MARK = "# written by pm-decoyd (console time settings); edit from the console\n"
HOST_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
MAX_SERVERS = 3


def time_service():
    """(kind, unit) of the time service in use: an active one first, then an
    installed one; (None, None) if there is neither."""
    if P.get("time_service"):             # tests only
        kind = P["time_service"]
        return (kind, TIME_UNITS[kind][0]) if kind in TIME_UNITS else (None, None)
    units = [(k, u) for k in ("chrony", "timesyncd") for u in TIME_UNITS[k]]
    for k, u in units:
        if systemctl("is-active", u)[1] == "active":
            return k, u
    for k, u in units:
        if systemctl("show", "-p", "LoadState", "--value", u)[1] == "loaded":
            return k, u
    return None, None


def time_file(kind):
    return P["chrony_src"] if kind == "chrony" else P["timesyncd_dropin"]


def read_servers(kind):
    text = read_or_none(time_file(kind)) or ""
    out = []
    for line in text.splitlines():
        w = line.split("#", 1)[0].split()
        if kind == "chrony" and len(w) >= 2 and w[0] == "server":
            out.append(w[1])
        elif kind == "timesyncd" and w and w[0].startswith("NTP="):
            out = [w[0][4:]] + w[1:] if w[0][4:] else w[1:]
    return [s for s in out if s]


def render_time(kind, servers):
    if kind == "chrony":
        return TIME_MARK + "".join("server %s iburst\n" % s for s in servers)
    return TIME_MARK + "[Time]\nNTP=%s\nFallbackNTP=\n" % " ".join(servers)


def own_addresses():
    """This host's IPv4 addresses on every interface (loopback included)."""
    return {a.ip for i in host_info()["ifaces"].values() for a in i["addrs"]}


def check_servers(v, nets, own=()):
    """1 to 3 servers, each an IPv4 address or a plain host name; no
    duplicates, nothing inside the decoy block, no loopback/multicast, and
    never one of this sensor's own addresses."""
    if not isinstance(v, list) or not 1 <= len(v) <= MAX_SERVERS:
        raise Err("E_INVALID", "args.servers", "give 1 to %d NTP servers" % MAX_SERVERS)
    out = []
    for i, s in enumerate(v):
        f = "args.servers[%d]" % i
        if not isinstance(s, str) or not s or len(s) > 253:
            raise Err("E_INVALID", f, "not a server address")
        s = s.strip().lower()
        if re.match(r'^[0-9.]+$', s):
            try:
                a = ipaddress.IPv4Address(s)
            except ValueError:
                raise Err("E_INVALID", f, "%s is not a valid IPv4 address" % s[:40])
            if a.is_loopback:
                raise Err("E_INVALID", f, "%s is a loopback address, so the sensor would ask itself; "
                          "use another host on your network that runs NTP" % s)
            if a.is_multicast or a.is_unspecified or a.is_link_local or a.is_reserved \
                    or a == ipaddress.IPv4Address("255.255.255.255"):
                raise Err("E_INVALID", f, "%s cannot be an NTP server (unspecified, multicast, "
                          "broadcast, link-local or reserved address)" % s)
            if a in own:
                raise Err("E_INVALID", f, "%s is an address of this sensor; "
                          "use another host on your network that runs NTP" % s)
            if any(a in n for n in nets):
                raise Err("E_INVALID", f, "%s is inside the decoy block; use a real host for time" % s)
        elif s == "localhost" or s.endswith(".localhost"):
            raise Err("E_INVALID", f, "%s is this sensor itself; use another host on your network that runs NTP" % s)
        elif not HOST_RE.match(s):
            raise Err("E_INVALID", f, "use an IPv4 address or a host name (letters, digits, dots, hyphens)")
        if s in out:
            raise Err("E_INVALID", f, "%s is listed twice" % s)
        out.append(s)
    return out


def _num(v):
    v = v.strip()
    return int(v) if v.isdigit() else None


def _tool(*argv):
    try:
        r = subprocess.run(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=10, close_fds=True,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return r.returncode, r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


# chronyc reads chronyd over UDP on the loopback command port 127.0.0.1:323
# (monitoring commands are allowed from localhost by default). Started as
# root, chronyc 4.8 and later switches to the chrony user first, which needs
# setgroups/setuid that the unit does not grant; "-u root" tells it to stay
# as it is (it then holds no capabilities but CAP_NET_RAW and only talks
# UDP to loopback). Older chronyc has no -u and never switches, so a usage
# error is retried without it. The reason of a failure goes to the journal.
CHRONYC = ("-h", "127.0.0.1")


def _tool_err(*argv):
    """(rc, stdout, short stderr reason)."""
    try:
        r = subprocess.run(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=10, close_fds=True,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        err = re.sub(r'[\x00-\x1f\x7f]+', " ", r.stderr.decode("utf-8", "replace")).strip()[:200]
        return r.returncode, r.stdout.decode("utf-8", "replace"), err
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except OSError as e:
        return -1, "", "could not run: %s" % (e.strerror or e)


def chrony_sources():
    """[{name, state, reach}] from chronyc -n -c sources, or None when
    chronyd cannot be read (the reason is logged)."""
    rc, out, err = _tool_err(P["chronyc"], "-u", "root", *CHRONYC, "-n", "-c", "sources")
    if rc != 0 and ("invalid option" in err or "Usage" in err):
        rc, out, err = _tool_err(P["chronyc"], *CHRONYC, "-n", "-c", "sources")
    if rc != 0:
        log(syslog.LOG_WARNING, "chronyc sources failed: %s" % (err or "exit %d" % rc))
        return None
    res = []
    for line in out.splitlines():
        f = line.split(",")
        if len(f) >= 6:
            res.append({"name": f[2], "state": f[1], "reach": f[5]})
    return res


def timesyncd_synced():
    """True, False, or None when it cannot be read."""
    rc, out, err = _tool_err(P["timedatectl"], "show", "-p", "NTPSynchronized", "--value")
    v = {"yes": True, "no": False}.get(out.strip()) if rc == 0 else None
    if v is None:
        log(syslog.LOG_WARNING, "timedatectl show failed: %s" % (err or "exit %d" % rc))
    return v


def timesyncd_reached():
    rc, out = _tool(P["timedatectl"], "timesync-status")
    for line in out.splitlines() if rc == 0 else ():
        k, _, v = line.partition(":")
        if k.strip() == "Packet count":
            return v.strip().strip("0") != ""
    return False


def time_reached(kind):
    if kind == "chrony":
        return any(s["reach"] not in ("", "0") for s in chrony_sources() or ())
    return timesyncd_reached()


def chrony_ready():
    """Only our sources file may feed chrony, or the check after a change
    proves nothing. Setup arranges that; refuse otherwise."""
    conf = read_or_none(P["chrony_conf"])
    if conf is None:
        return "chrony.conf not found"
    want = "sourcedir " + os.path.dirname(P["chrony_src"])
    lines = [l.split("#", 1)[0].strip() for l in conf.splitlines()]
    if not any(re.sub(r'\s+', " ", l).rstrip("/") == want for l in lines):
        return "chrony.conf has no '%s' line" % want
    if any(re.match(r'^(pool|server|peer)\s', l) for l in lines):
        return "chrony.conf still has pool or server lines"
    d = os.path.dirname(P["chrony_src"])
    other = [n for n in sorted(os.listdir(d)) if n.endswith(".sources") and
             os.path.join(d, n) != P["chrony_src"]] if os.path.isdir(d) else []
    if other:
        return "other source files are active in %s: %s" % (d, " ".join(other)[:200])
    return None


def op_timeinfo():
    """The servers set and one status: up (synchronised with a source),
    not_reached (running, no source selected yet), not_running, or
    unreadable (the reason is in the journal only)."""
    kind, unit = time_service()
    r = {"service": kind, "unit": unit, "servers": [], "status": "unreadable",
         "ready": None, "max_servers": MAX_SERVERS}
    if not kind:
        r["ready"] = "no time service (chrony or systemd-timesyncd) is installed"
        return r
    r["servers"] = read_servers(kind)
    if kind == "chrony":
        r["ready"] = chrony_ready()
    if systemctl("is-active", unit)[1] != "active":
        r["status"] = "not_running"
    elif kind == "chrony":
        src = chrony_sources()
        if src is not None:
            r["status"] = "up" if any(x["state"] == "*" for x in src) else "not_reached"
    else:
        v = timesyncd_synced()
        if v is not None:
            r["status"] = "up" if v else "not_reached"
    return r


def clear_time_journal():
    try:
        os.unlink(P["time_journal"])
    except FileNotFoundError:
        pass


def recover_time_journal():
    """A set_time swap was cut off: put the previous server file back and
    restart the time service it named."""
    try:
        with open(P["time_journal"]) as f:
            j = json.load(f)
        path, had, unit = str(j["path"]), bool(j["had"]), str(j["unit"])
    except FileNotFoundError:
        return False
    except (ValueError, KeyError, TypeError):
        raise Err("E_INTERNAL", None, "an interrupted time change needs checking: " + P["time_journal"])
    if path not in (P["chrony_src"], P["timesyncd_dropin"]) or unit not in sum(TIME_UNITS.values(), ()):
        raise Err("E_INTERNAL", None, "unexpected entry in " + P["time_journal"])
    if had:
        with open(path + ".prev") as f:
            replace_file(path, f.read(), 0o644)
    else:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    clear_time_journal()
    systemctl("restart", unit)
    log(syslog.LOG_CRIT, "interrupted time change %s: previous servers restored" % j.get("id", "?"))
    return True


def wait_reached(kind, limit):
    end = time.monotonic() + limit
    while True:
        if time_reached(kind):
            return True
        if time.monotonic() >= end:
            return False
        time.sleep(1.0)


def set_time(helper, args, actor, rid):
    _keys(args, "args", ("servers", "expect"), ("keep",))
    keep = args.get("keep", False)
    if not isinstance(keep, bool):
        raise Err("E_INVALID", "args.keep", "keep must be true or false")
    nets, _ = read_default()
    servers = check_servers(args["servers"], nets, own_addresses())
    lock = helper._lock()
    try:
        recover_time_journal()
        kind, unit = time_service()
        if not kind:
            raise Err("E_NO_TIME_SERVICE", None, "no time service (chrony or systemd-timesyncd) is installed")
        if kind == "chrony":
            why = chrony_ready()
            if why:
                raise Err("E_SETUP_NEEDED", None, "%s; run sudo phantom-mirage-setup and choose local NTP first" % why)
        old_servers = read_servers(kind)
        if not isinstance(args["expect"], list) or args["expect"] != old_servers:
            raise Err("E_CONFLICT", "args.expect", "the time servers changed since you loaded them")
        if servers == old_servers:
            raise Err("E_UNCHANGED", "args.servers", "those are already the time servers")
        path = time_file(kind)
        old = read_or_none(path)
        new = render_time(kind, servers)
        if old is not None:
            replace_file(path + ".prev", old, 0o644)
        replace_file(P["time_journal"], json.dumps({"id": rid, "path": path, "had": old is not None,
                                                    "unit": unit, "previous": old_servers}), 0o600)
        try:
            os.makedirs(os.path.dirname(path), 0o755, exist_ok=True)
            replace_file(path, new, 0o644)
        except OSError as e:
            clear_time_journal()
            raise Err("E_INTERNAL", None, "could not write %s (%s); nothing changed" % (path, e.__class__.__name__))

        def back(code, msg):
            log(syslog.LOG_ERR, "id=%s %s, restoring previous time servers" % (rid, msg))
            if old is None:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
            else:
                replace_file(path, old, 0o644)
            clear_time_journal()
            rc2, _ = systemctl("restart", unit)
            ok = rc2 == 0 and systemctl("is-active", unit)[1] == "active"
            e = Err(code if ok else "E_ROLLBACK_FAILED", None, msg + ("; the previous servers are back"
                    if ok else "; %s is not running after restoring the previous servers" % unit))
            e.reloaded, e.rolled_back = True, True
            raise e

        rc, out = systemctl("restart", unit)
        if rc != 0 or systemctl("is-active", unit)[1] != "active":
            back("E_RESTART_FAILED_ROLLED_BACK", "%s did not start with the new servers" % unit)
        reached = wait_reached(kind, T["time_wait"])
        if not reached and not keep:
            back("E_TIME_UNREACHABLE_ROLLED_BACK",
                 "%s could not reach %s within %d s" % (unit, " ".join(servers), int(T["time_wait"])))
        clear_time_journal()
        result = "applied" if reached else "applied_unverified"
        log(syslog.LOG_INFO, "id=%s time servers %s -> %s (%s, %s)" % (
            rid, " ".join(old_servers) or "-", " ".join(servers), unit, result))
        res = {"service": kind, "unit": unit, "servers": servers, "reached": reached}
        if not reached:
            res["warnings"] = ["%s has not reached the new servers yet; kept as asked" % unit]
        return res, True
    finally:
        os.close(lock)


# ---- socket ----------------------------------------------------------------

def peer_uid(conn):
    data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", data)[1]


def allowed_uid():
    if P["console_uid"] is not None:
        return P["console_uid"]
    return pwd.getpwnam(P["console_user"]).pw_uid


def read_line(conn):
    conn.settimeout(T["read_timeout"])
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_REQ + 1:
            raise Err("E_BAD_JSON", None, "request too large")
    line = buf.split(b"\n", 1)[0]
    if len(line) > MAX_REQ:
        raise Err("E_BAD_JSON", None, "request too large")
    return line


def serve_conn(helper, conn):
    resp = {"v": 1, "id": "", "ok": False, "reloaded": False, "rolled_back": False}
    try:
        try:
            uid = peer_uid(conn)
            ok_uid = allowed_uid()
        except (OSError, KeyError):
            uid, ok_uid = -1, -2
        if uid != ok_uid:
            log(syslog.LOG_WARNING, "refused peer uid %d" % uid)
            raise Err("E_PEER", None, "caller not permitted")
        try:
            raw = read_line(conn)
        except socket.timeout:
            raise Err("E_BAD_JSON", None, "timed out reading the request")
        resp = helper.handle(parse_request(raw))
    except Err as e:
        resp["error"] = {"code": e.code, "field": e.field, "message": e.message}
    try:
        conn.sendall((json.dumps(resp, sort_keys=True) + "\n").encode())
    except OSError:
        pass


def serve(lsock, helper=None):
    helper = helper or Helper()
    lsock.settimeout(T["idle"])
    while True:
        try:
            conn, _ = lsock.accept()
        except socket.timeout:
            return 0
        with conn:
            conn.settimeout(T["read_timeout"])
            serve_conn(helper, conn)


def main():
    syslog.openlog("pm-decoyd", syslog.LOG_PID, syslog.LOG_DAEMON)
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        sys.stderr.write("pm-decoyd: start through pm-decoyd.socket only\n")
        return 2
    os.umask(0o022)
    os.makedirs(P["rundir"], mode=0o700, exist_ok=True)
    lsock = socket.socket(fileno=3)
    try:
        recover_journal()
    except Err as e:
        log(syslog.LOG_CRIT, e.message)
    return serve(lsock)


if __name__ == "__main__":
    sys.exit(main())
