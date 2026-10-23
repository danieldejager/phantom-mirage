"""Phantom Mirage I console: password hashing, sessions, CSRF, lockout.

Python 3 standard library only. argon2id is used when python3-argon2 is
installed; otherwise hashlib.scrypt (always available with OpenSSL).
Nothing here logs or returns secrets.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

try:  # optional: Debian/Ubuntu package python3-argon2
    import argon2  # type: ignore
    from argon2 import PasswordHasher  # type: ignore
    _ARGON2 = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2,
                             type=argon2.Type.ID)
except Exception:  # pragma: no cover - depends on the host
    _ARGON2 = None

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MIN_PASSWORD = 12
MAX_PASSWORD = 1024


def _b64(b):
    return base64.b64encode(b).decode("ascii").rstrip("=")


def _unb64(s):
    return base64.b64decode(s + "=" * (-len(s) % 4))


def password_problem(pw, username=""):
    """Return a reason the password is unacceptable, or None."""
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD:
        return "password must be at least %d characters" % MIN_PASSWORD
    if len(pw) > MAX_PASSWORD:
        return "password is too long"
    if username and pw.lower() == username.lower():
        return "password must not be the username"
    if len(set(pw)) < 4:
        return "password is too simple"
    return None


def hash_password(pw, prefer_argon2=True):
    if prefer_argon2 and _ARGON2 is not None:
        return _ARGON2.hash(pw)
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=32)
    return "$scrypt$n=%d,r=%d,p=%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P,
                                            _b64(salt), _b64(dk))


def hash_scheme(h):
    if h.startswith("$argon2id$"):
        return "argon2id"
    if h.startswith("$scrypt$"):
        return "scrypt"
    return "unknown"


def verify_password(pw, h):
    """Constant-time check; False for any malformed hash."""
    if not isinstance(pw, str) or not isinstance(h, str) or len(pw) > MAX_PASSWORD:
        return False
    if h.startswith("$argon2"):
        if _ARGON2 is None:
            return False
        try:
            return _ARGON2.verify(h, pw)
        except Exception:
            return False
    if h.startswith("$scrypt$"):
        try:
            _, _, params, salt, dk = h.split("$")
            kv = dict(x.split("=") for x in params.split(","))
            n, r, p = int(kv["n"]), int(kv["r"]), int(kv["p"])
            if n > 2 ** 20 or r > 32 or p > 16:
                return False
            want = _unb64(dk)
            got = hashlib.scrypt(pw.encode("utf-8"), salt=_unb64(salt), n=n,
                                 r=r, p=p, maxmem=256 * 1024 * 1024,
                                 dklen=len(want))
            return hmac.compare_digest(got, want)
        except Exception:
            return False
    return False


# A fixed dummy hash so unknown usernames cost the same time as real ones.
_DUMMY = None


def dummy_verify(pw):
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("dummy-password-not-used", prefer_argon2=_ARGON2 is not None)
    verify_password(pw, _DUMMY)


class Lockout:
    """Failure counter and rate limit, keyed per (username, source) (#120).

    The console listens on 127.0.0.1 only and is reached through an SSH
    tunnel, so every client address is loopback. The source is therefore
    the local UID owning the connecting socket (peer_uid(), from
    /proc/net/tcp[6]) when it can be found, else the peer address. A local
    user hammering the login only fills their own bucket.

    There is no hard lockout: after max_failures in window, the bucket
    backs off exponentially (lock_base, doubling, capped at lock_for), so
    even an attacker sharing the admin's bucket cannot block the admin
    for longer than lock_for at a time. phantom-mirage-setup --reset-admin
    clears everything. State is persisted so a restart does not reset it.
    """

    def __init__(self, path=None, max_failures=5, window=900, lock_for=900,
                 rate=10, rate_window=60, clock=time.time, lock_base=60):
        self.path, self.max_failures, self.window = path, max_failures, window
        self.lock_for, self.rate, self.rate_window = lock_for, rate, rate_window
        self.lock_base = min(lock_base, lock_for)
        self.clock = clock
        self._lock = threading.Lock()
        self._attempts = {}          # source -> [timestamps of attempts]
        self._fail = {}              # "user|source" -> [timestamps]
        self._locked = {}            # "user|source" -> until
        self._strikes = {}           # "user|source" -> lockouts so far
        self._load()

    @staticmethod
    def key(user, source="-"):
        return "%s|%s" % (user, source)

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                d = json.load(f)
            self._fail = {k: list(v) for k, v in d.get("fail", {}).items()}
            self._locked = {k: float(v) for k, v in d.get("locked", {}).items()}
            self._strikes = {k: int(v) for k, v in d.get("strikes", {}).items()}
        except Exception:
            pass

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"fail": self._fail, "locked": self._locked,
                       "strikes": self._strikes}, f)
        os.replace(tmp, self.path)

    def rate_limited(self, source="-"):
        """Record an attempt from source; True if that source is over the rate."""
        now = self.clock()
        with self._lock:
            if len(self._attempts) > 1000:
                self._attempts = {k: v for k, v in self._attempts.items()
                                  if v and now - v[-1] < self.rate_window}
            a = [t for t in self._attempts.get(source, []) if now - t < self.rate_window]
            a.append(now)
            self._attempts[source] = a
            return len(a) > self.rate

    def locked_until(self, user, source="-"):
        now = self.clock()
        with self._lock:
            u = self._locked.get(self.key(user, source), 0)
            return u if u > now else 0

    def failure(self, user, source="-"):
        """Record a failure; returns back-off-until (0 if not backing off)."""
        now = self.clock()
        k = self.key(user, source)
        with self._lock:
            f = [t for t in self._fail.get(k, []) if now - t < self.window]
            f.append(now)
            self._fail[k] = f
            if len(self._fail) > 1000:   # bound memory: drop stale buckets
                self._fail = {x: v for x, v in self._fail.items()
                              if x == k or (v and now - v[-1] < self.window)}
                self._locked = {x: v for x, v in self._locked.items() if v > now}
                self._strikes = {x: v for x, v in self._strikes.items()
                                 if x in self._fail or x in self._locked}
            until = 0
            if len(f) >= self.max_failures:
                n = self._strikes.get(k, 0)
                until = now + min(self.lock_for, self.lock_base * (2 ** min(n, 20)))
                self._locked[k] = until
                self._strikes[k] = n + 1
                self._fail[k] = []
            self._save()
            return until

    def success(self, user, source="-"):
        k = self.key(user, source)
        with self._lock:
            for d in (self._fail, self._locked, self._strikes):
                d.pop(k, None)
            self._save()

    def reset(self):
        with self._lock:
            self._fail, self._locked, self._strikes = {}, {}, {}
            self._attempts = {}
            self._save()


def _hexaddr(ip, port):
    """/proc/net/tcp[6] encoding of (ip, port)."""
    import socket
    import struct
    if ":" in ip:
        raw = socket.inet_pton(socket.AF_INET6, ip)
        h = "".join("%08X" % struct.unpack("<I", raw[i:i + 4])[0] for i in range(0, 16, 4))
    else:
        h = "%08X" % struct.unpack("<I", socket.inet_aton(ip))[0]
    return "%s:%04X" % (h, port)


def peer_uid(peer, local, proc="/proc/net"):
    """UID owning the client end of a loopback TCP connection, or None.

    peer and local are (ip, port) as seen by the server. The client's
    socket is the row whose local address is our peer and whose remote
    address is our local address."""
    try:
        want_l, want_r = _hexaddr(peer[0], peer[1]), _hexaddr(local[0], local[1])
    except (OSError, ValueError, TypeError, IndexError):
        return None
    for name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc, name)) as f:
                rows = f.read().splitlines()[1:]
        except OSError:
            continue
        for r in rows:
            c = r.split()
            if len(c) > 7 and c[1].upper() == want_l and c[2].upper() == want_r:
                try:
                    return int(c[7])
                except ValueError:
                    return None
    return None


class Sessions:
    """In-memory sessions with idle and absolute timeouts and a CSRF token."""

    def __init__(self, idle=1800, absolute=12 * 3600, clock=time.time):
        self.idle, self.absolute, self.clock = idle, absolute, clock
        self._s = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(sid):
        return hashlib.sha256(sid.encode()).hexdigest()

    def create(self, user):
        sid = secrets.token_urlsafe(32)
        now = self.clock()
        with self._lock:
            self._s[self._key(sid)] = {"user": user, "csrf": secrets.token_urlsafe(32),
                                       "created": now, "seen": now}
        return sid

    def get(self, sid, touch=True):
        if not sid or len(sid) > 128:
            return None
        k = self._key(sid)
        now = self.clock()
        with self._lock:
            s = self._s.get(k)
            if not s:
                return None
            if now - s["seen"] > self.idle or now - s["created"] > self.absolute:
                del self._s[k]
                return None
            if touch:
                s["seen"] = now
            return dict(s)

    def destroy(self, sid):
        if sid:
            with self._lock:
                self._s.pop(self._key(sid), None)

    def destroy_user(self, user):
        with self._lock:
            for k in [k for k, v in self._s.items() if v["user"] == user]:
                del self._s[k]

    def check_csrf(self, sid, token):
        s = self.get(sid, touch=False)
        return bool(s and token and hmac.compare_digest(s["csrf"], token))


def same_origin_ok(headers, port):
    """Reject cross-site requests. Browsers send Origin on every POST made
    with fetch(); a missing Origin is refused (defence in depth on top of
    the CSRF token)."""
    sfs = headers.get("Sec-Fetch-Site")
    if sfs and sfs not in ("same-origin", "none"):
        return False
    origin = headers.get("Origin")
    if not origin:
        return False
    # #120: the origin must be loopback on the configured console port.
    # SSH tunnels must forward the same local port (ssh -L PORT:127.0.0.1:PORT).
    import urllib.parse
    try:
        u = urllib.parse.urlsplit(origin)
        oport = u.port
    except ValueError:
        return False
    return (u.scheme == "https" and u.hostname in ("localhost", "127.0.0.1", "::1")
            and oport == int(port) and not u.path.strip("/"))
