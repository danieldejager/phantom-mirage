"""Client for pm-decoyd, the root helper that writes per decoy settings.

One request per connection: a JSON line out, a JSON line back. The socket
is root:phantom-mirage-console 0660 and the helper checks SO_PEERCRED, so
only the console user gets through. Standard library only.
"""
import json
import os
import re
import socket
import time
import uuid

DEFAULT_SOCK = "/run/phantom-mirage-decoyd.sock"
CHANGE_OPS = ("add", "edit", "start", "stop", "reset", "reset_all", "set_network", "set_time")
READ_OPS = ("list", "options", "netinfo", "timeinfo")
MAX_REPLY = 1 << 20
# A change waits for the queue, verify, reload, settle and maybe a
# rollback restart in the helper, so allow well over a minute.
TIMEOUT = 90.0
# set_network also restarts the whole sensor, farpd and the firewall and
# may restart again on rollback, so it gets longer. set_time restarts the
# time service, waits for it to reach a server and may restart it again.
NET_TIMEOUT = 240.0


def sock_path():
    return os.environ.get("PM_DECOYD_SOCK") or DEFAULT_SOCK


def _fail(code, message):
    return {"v": 1, "ok": False, "reloaded": False, "rolled_back": False,
            "error": {"code": code, "field": None, "message": message}}


def call(op, args, actor, timeout=None):
    """Send one request; always returns a response dict (never raises)."""
    if timeout is None:
        timeout = NET_TIMEOUT if op in ("set_network", "set_time") else TIMEOUT
    if op not in CHANGE_OPS + READ_OPS:
        return _fail("E_UNKNOWN_OP", "unknown operation")
    actor = re.sub(r'[^A-Za-z0-9._-]', "_", str(actor))[:64] or "-"
    req = {"v": 1, "id": uuid.uuid4().hex, "ts": int(time.time()), "actor": actor,
           "op": op, "args": args}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect(sock_path())
        except OSError:
            return _fail("E_UNAVAILABLE", "the decoy settings helper is not running "
                         "(systemctl enable --now pm-decoyd.socket)")
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REPLY:
                return _fail("E_BAD_REPLY", "reply too large")
    except socket.timeout:
        return _fail("E_TIMEOUT", "the helper did not answer in time; check the sensor status")
    except OSError:
        return _fail("E_UNAVAILABLE", "lost the connection to the helper")
    finally:
        s.close()
    try:
        r = json.loads(buf)
    except ValueError:
        return _fail("E_BAD_REPLY", "bad reply from the helper")
    if not isinstance(r, dict) or r.get("v") != 1 or not isinstance(r.get("ok"), bool):
        return _fail("E_BAD_REPLY", "bad reply from the helper")
    if r.get("id") not in (req["id"], ""):
        return _fail("E_BAD_REPLY", "reply for another request")
    return r
