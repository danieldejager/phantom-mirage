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
    """Per-username failure counter with lockout, plus a global rate limit.

    State is persisted (path) so a restart does not reset a lockout.
    """

    def __init__(self, path=None, max_failures=5, window=900, lock_for=900,
                 rate=10, rate_window=60, clock=time.time):
        self.path, self.max_failures, self.window = path, max_failures, window
        self.lock_for, self.rate, self.rate_window = lock_for, rate, rate_window
        self.clock = clock
        self._lock = threading.Lock()
        self._attempts = []          # timestamps of all login attempts
        self._fail = {}              # user -> [timestamps]
        self._locked = {}            # user -> until
        self._load()

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                d = json.load(f)
            self._fail = {k: list(v) for k, v in d.get("fail", {}).items()}
            self._locked = {k: float(v) for k, v in d.get("locked", {}).items()}
        except Exception:
            pass

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"fail": self._fail, "locked": self._locked}, f)
        os.replace(tmp, self.path)

    def rate_limited(self):
        """Record an attempt; True if over the global rate."""
        now = self.clock()
        with self._lock:
            self._attempts = [t for t in self._attempts if now - t < self.rate_window]
            self._attempts.append(now)
            return len(self._attempts) > self.rate

    def locked_until(self, user):
        now = self.clock()
        with self._lock:
            u = self._locked.get(user, 0)
            return u if u > now else 0

    def failure(self, user):
        """Record a failure; returns lock-until (0 if not locked)."""
        now = self.clock()
        with self._lock:
            f = [t for t in self._fail.get(user, []) if now - t < self.window]
            f.append(now)
            self._fail[user] = f
            if len(self._fail) > 1000:   # bound memory: drop stale names
                self._fail = {k: v for k, v in self._fail.items()
                              if k == user or (v and now - v[-1] < self.window)}
                self._locked = {k: v for k, v in self._locked.items() if v > now}
            until = 0
            if len(f) >= self.max_failures:
                until = now + self.lock_for
                self._locked[user] = until
                self._fail[user] = []
            self._save()
            return until

    def success(self, user):
        with self._lock:
            self._fail.pop(user, None)
            self._locked.pop(user, None)
            self._save()
            self._save()

    def reset(self):
        with self._lock:
            self._fail, self._locked = {}, {}
            self._save()


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
    if origin not in ("https://localhost:%d" % port,
                                 "https://127.0.0.1:%d" % port):
        # tunnels may use another local port: accept any loopback origin
        import urllib.parse
        u = urllib.parse.urlsplit(origin)
        if u.scheme != "https" or u.hostname not in ("localhost", "127.0.0.1", "::1"):
            return False
    return True
