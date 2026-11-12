#!/usr/bin/python3
"""Console part of phantom-mirage-setup (run as root from the terminal).

  pm-console-setup.py first-run [--sensor-name N] [--admin-user U]
        [--console-port P] [--time-source ntp|browser] [--ntp-server HOST]
        [--timezone TZ] [--retention DAYS] [--reconfigure] [--dry-run]
  pm-console-setup.py reset-admin
  pm-console-setup.py status
  pm-console-setup.py restore-time

The sensor clock: setup finds the time service the machine runs (chrony,
the default on Ubuntu 26.04, or systemd-timesyncd) and points that one at
a single NTP server on the local network, with no internet fallback. For
chrony the distribution's internet pool files are set aside (renamed
*.pm-disabled) and chrony.conf is backed up once as chrony.conf.pm-backup;
restore-time puts them back.

The admin password is never accepted as an option. On a terminal it is
read at a hidden prompt. With no terminal, setup generates one and writes
it to a root-only file (the path is printed; the password is not).
Test-only: PM_TEST_STDIN=1 reads the answers (including the password,
twice) from stdin lines instead of the terminal.
"""
import errno
import grp
import ipaddress
import os
import signal
import pwd
import re
import secrets
import subprocess
import sys
import termios

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmauth  # noqa: E402
import pmstore  # noqa: E402

USER = "phantom-mirage-console"
TIMESYNCD_DROPIN = os.environ.get("PM_TIMESYNCD_DROPIN",
                                  "/etc/systemd/timesyncd.conf.d/phantom-mirage.conf")
CHRONY_DIR = os.environ.get("PM_CHRONY_DIR", "/etc/chrony")
MARK = "# written by phantom-mirage-setup"
DISABLED = ".pm-disabled"
SRC_LINE = re.compile(r'^\s*(pool|server|peer)\s', re.I)
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}$')
TEST = os.environ.get("PM_TEST_STDIN") == "1"


def say(msg):
    print("phantom-mirage-setup: " + msg, flush=True)


def die(msg, code=1):
    sys.stderr.write("phantom-mirage-setup: %s\n" % msg)
    sys.exit(code)


def _controlling_rdev():
    """Device number of this process's terminal, or None.

    fstat(/dev/tty) is the /dev/tty node itself, not the pty behind it.
    /proc/self/stat field tty_nr is that pty."""
    try:
        data = open("/proc/self/stat").read()
        n = int(data.rsplit(")", 1)[1].split()[4])
    except (OSError, IndexError, ValueError):
        return None
    return n or None


# After the first open, the pty sudo delivers keystrokes on.
_kbd_fd = None


def _remember_tty(fd):
    path = os.environ.get("PM_TTY_FILE")
    if not path:
        return
    try:
        name = os.ttyname(fd)
    except OSError:
        return
    try:
        fd_out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    except OSError:
        return
    try:
        os.write(fd_out, (name + "\n").encode())
    finally:
        os.close(fd_out)


def _keyboard():
    """The pty sudo created for this command, in the foreground.

    sudo and sudo-rs (Ubuntu 26.04) deliver keystrokes to that pty, but
    the monitor process keeps the foreground. A read from the background
    never completes, which is the hang after the first answer. Taking
    the foreground makes the answers arrive on /dev/tty.
    """
    global _kbd_fd
    if _kbd_fd is not None:
        return _kbd_fd
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return None
    try:
        os.tcsetpgrp(fd, os.getpgrp())
    except OSError:
        pass
    # If the foreground could not be taken, a read must return an error
    # instead of stopping the process. A stopped read is the hang.
    signal.signal(signal.SIGTTIN, signal.SIG_IGN)
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    _kbd_fd = fd
    _remember_tty(fd)
    return fd


def _outer_ttys():
    """Terminals above us, other than our own pty. Echo is turned off
    here for the password: sudo-rs echoes on the terminal it was
    started from, not on /dev/tty."""
    ctty = _controlling_rdev()
    found = []
    seen = set()
    pid = os.getppid()
    for _ in range(12):
        if pid <= 1:
            break
        for n in (0, 1, 2):
            try:
                t = os.readlink("/proc/%d/fd/%d" % (pid, n))
            except OSError:
                continue
            if not t.startswith("/dev/pts/") or t in seen:
                continue
            seen.add(t)
            try:
                if ctty is not None and os.stat(t).st_rdev == ctty:
                    continue
                fd = os.open(t, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            except OSError:
                continue
            found.append(fd)
        try:
            ppid = None
            with open("/proc/%d/status" % pid) as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = int(line.split()[1])
                        break
            if ppid is None:
                break
            pid = ppid
        except (OSError, ValueError):
            break
    return found


def interactive():
    """True when a person can answer. Piped sudo still has /dev/tty;
    with no terminal at all, setup uses its defaults."""
    if TEST:
        return True
    if sys.stdin.isatty():
        return True
    fd = _keyboard()
    return fd is not None


def _read_fd(fd):
    buf = b""
    while b"\n" not in buf and b"\r" not in buf:
        try:
            chunk = os.read(fd, 256)
        except OSError as e:
            if e.errno == errno.EIO:
                raise EOFError
            raise
        if not chunk:
            raise EOFError
        buf += chunk
    raw = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return raw.split(b"\n", 1)[0].decode("utf-8", "replace")


def _read_line(prompt):
    fd = _keyboard()
    if fd is None:
        raise EOFError
    sys.stdout.write(prompt)
    sys.stdout.flush()
    return _read_fd(fd)


def _hidden(prompt):
    """Password on /dev/tty, with echo off there and on the outer terminal.

    The stdlib getpass opens /dev/tty first and would work once this
    process is in the foreground, but sudo-rs still echoes on the
    terminal that started sudo unless echo is off there too.
    """
    fd = _keyboard()
    if fd is None:
        raise EOFError
    outers = _outer_ttys()
    saved = []
    for one in [fd] + outers:
        try:
            old = termios.tcgetattr(one)
            new = old[:]
            new[3] &= ~termios.ECHO
            termios.tcsetattr(one, termios.TCSANOW, new)
            saved.append((one, old))
        except termios.error:
            pass
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = _read_fd(fd)
    finally:
        for one, old in saved:
            try:
                termios.tcsetattr(one, termios.TCSANOW, old)
            except termios.error:
                pass
        for one in outers:
            try:
                os.close(one)
            except OSError:
                pass
    sys.stderr.write("\n")
    sys.stderr.flush()
    return line


def ask(prompt, default=None, check=None):
    for _ in range(5):
        if TEST:
            line = sys.stdin.readline()
            if not line:
                die("test stdin ended at: " + prompt)
            v = line.rstrip("\n")
        else:
            shown = "%s%s: " % (prompt, " [%s]" % default if default not in (None, "") else "")
            if os.environ.get("PM_SETUP_TRACE") == "1":
                sys.stderr.write("setup-trace: asking %s\n" % shown.split(":", 1)[0])
                sys.stderr.flush()
            try:
                v = _read_line(shown)
            except EOFError:
                die("no answer for '%s' (input ended); nothing was changed" % prompt, 2)
            if os.environ.get("PM_SETUP_TRACE") == "1":
                sys.stderr.write("setup-trace: answered %s\n" % shown.split(":", 1)[0])
                sys.stderr.flush()
        v = v.strip() or (str(default) if default is not None else "")
        err = check(v) if check else None
        if not err:
            return v
        print("  " + err)
    die("too many invalid answers")


def ask_password(user):
    for _ in range(3):
        if TEST:
            p1 = sys.stdin.readline().rstrip("\n")
            p2 = sys.stdin.readline().rstrip("\n")
        else:
            p1 = _hidden("Admin password (hidden, %d+ characters): " % pmauth.MIN_PASSWORD)
            p2 = _hidden("Repeat password: ")
        if p1 != p2:
            print("  passwords do not match")
            continue
        prob = pmauth.password_problem(p1, user)
        if prob:
            print("  " + prob)
            continue
        return p1
    die("no acceptable password entered")


def chk_name(v):
    return None if NAME_RE.match(v) else "letters, digits, . _ - (max 63), starting with a letter or digit"


def chk_user(v):
    return None if USER_RE.match(v) else "lower-case letters, digits, _ . - (max 32)"


def chk_port(v):
    return None if v.isdigit() and 1024 <= int(v) <= 65535 and int(v) != 22 else "a port 1024-65535"


def chk_ts(v):
    return None if v in ("ntp", "browser") else "ntp or browser"


def own_addrs():
    """This machine's own addresses (all interfaces, IPv4 and IPv6)."""
    if os.environ.get("PM_OWN_ADDRS") is not None and TEST:   # tests only
        return {ipaddress.ip_address(x) for x in os.environ["PM_OWN_ADDRS"].split()}
    out = set()
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=10, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            w = line.split()
            if len(w) > 3 and w[2] in ("inet", "inet6"):
                try:
                    out.add(ipaddress.ip_interface(w[3]).ip)
                except ValueError:
                    pass
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def chk_ntp(v, own=None):
    """A host on the local network only: no internet time servers, and never
    this sensor itself."""
    if not v:
        return "enter the address of an NTP server on your local network (there is no default)"
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        if v.lower() == "localhost" or v.lower().endswith(".localhost"):
            return "%s is this sensor itself; enter another host on your network that runs NTP" % v
        if re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$', v) and (
                v.endswith((".lan", ".local", ".internal", ".home.arpa")) or "." not in v):
            return None
        return "use a private IP or a local hostname (.lan, .local, .internal, .home.arpa)"
    if a.is_loopback:
        return "%s is a loopback address, so the sensor would ask itself for the time; " \
               "enter another host on your network that runs NTP" % v
    if a.is_unspecified or a.is_multicast or a.is_link_local or a == ipaddress.ip_address("255.255.255.255"):
        return "%s cannot be an NTP server (unspecified, multicast, broadcast or link-local address)" % v
    if a in (own_addrs() if own is None else own):
        return "%s is an address of this sensor; enter another host on your network that runs NTP" % v
    if not a.is_private:
        return "use the address of an NTP server on your local network (private address)"
    return None


def chk_tz(v):
    if v == "UTC" or (re.match(r'^[A-Za-z0-9_+\-/]{1,64}$', v) and ".." not in v and
                      os.path.isfile(os.path.join("/usr/share/zoneinfo", v))):
        return None
    return "a time zone such as UTC or Australia/Melbourne"


def chk_ret(v):
    return None if v.isdigit() and 1 <= int(v) <= 3650 else "1-3650 days"


def owner():
    try:
        return pwd.getpwnam(USER).pw_uid, grp.getgrnam(USER).gr_gid
    except KeyError:
        return None


def admin_file():
    return os.environ.get("PM_ADMIN_FILE", "/etc/phantom-mirage/initial-admin.txt")


def write_initial_admin(user, pw):
    """Root-only file. The password is not printed and is not logged."""
    path = admin_file()
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        os.write(fd, ("username: %s\npassword: %s\n" % (user, pw)).encode())
    finally:
        os.close(fd)
    say("console: admin login for %s is in %s (root only; the password is not printed)" % (user, path))


def forget_initial_admin():
    try:
        os.remove(admin_file())
    except OSError:
        pass


def save_first_run(cfg, vals, pw):
    os.makedirs(pmstore.STATE_DIR, mode=0o770, exist_ok=True)
    cfg.update(sensor_name=vals["sensor_name"], port=int(vals["port"]),
               time_source=vals["time_source"], ntp_server=vals["ntp_server"],
               timezone=vals["timezone"],
               alert_retention_days=int(vals["alert_retention_days"]))
    pmstore.save_config(cfg)
    h = pmauth.hash_password(pw)
    pmstore.save_admin(vals["admin_user"], h)
    pmauth.Lockout(pmstore.path("lockout.json")).reset()
    pmstore.audit("setup", "first-run", "sensor %s, admin %s, port %s, time %s, hash %s" % (
        cfg["sensor_name"], vals["admin_user"], cfg["port"], cfg["time_source"],
        pmauth.hash_scheme(h)))
    fp = ensure_cert(cfg["sensor_name"])
    apply_time(cfg, False)
    fix_perms()
    say("console: admin %s set (password stored as a salted %s hash)" % (
        vals["admin_user"], pmauth.hash_scheme(h)))
    say("console certificate SHA-256 fingerprint: " + fp)


def fix_perms():
    o = owner()
    if not o or os.geteuid() != 0:
        return
    os.chown(pmstore.STATE_DIR, 0, o[1])
    os.chmod(pmstore.STATE_DIR, 0o770)
    for n in os.listdir(pmstore.STATE_DIR):
        os.chown(pmstore.path(n), o[0], o[1])


def ensure_cert(name):
    cert, key = pmstore.path("cert.pem"), pmstore.path("key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        old = os.umask(0o077)
        try:
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                 "ec_paramgen_curve:prime256v1", "-nodes", "-days", "825",
                 "-subj", "/CN=%s Phantom Mirage I console" % name,
                 "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                 "-keyout", key, "-out", cert],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            os.umask(old)
        say("created the console TLS certificate")
    r = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", cert],
                       check=True, capture_output=True, text=True)
    fp = r.stdout.strip().split("=", 1)[-1]
    with open(pmstore.path("cert.sha256"), "w") as f:
        f.write(fp + "\n")
    os.chmod(key, 0o600)
    return fp


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
                           universal_newlines=True)
        return r.returncode, r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def chrony_unit():
    for u in ("chrony.service", "chronyd.service"):
        if _run(["systemctl", "cat", u])[0] == 0:
            return u
    return "chrony.service"


def time_service():
    """Which time service this machine actually runs: 'chrony',
    'timesyncd' or 'none'. An active unit wins; otherwise an installed one."""
    forced = os.environ.get("PM_TIME_SERVICE")
    if forced in ("chrony", "timesyncd", "none"):
        return forced
    for u, name in (("chrony.service", "chrony"), ("chronyd.service", "chrony"),
                    ("systemd-timesyncd.service", "timesyncd")):
        if _run(["systemctl", "is-active", u])[1] == "active":
            return name
    if os.path.isfile(os.path.join(CHRONY_DIR, "chrony.conf")):
        return "chrony"
    if any(os.path.exists(p) for p in ("/usr/lib/systemd/systemd-timesyncd", "/lib/systemd/systemd-timesyncd")):
        return "timesyncd"
    return "none"


def _write(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(body)
    os.chmod(tmp, 0o644)
    os.rename(tmp, path)


def chrony_files(cfg):
    """Configure chrony: comment out pool/server/peer lines in chrony.conf
    (backup kept once), make sure it reads sources.d, set aside every other
    *.sources file there (the Ubuntu internet NTS pools), and write ours.
    Returns the list of things changed. Idempotent."""
    conf = os.path.join(CHRONY_DIR, "chrony.conf")
    sdir = os.path.join(CHRONY_DIR, "sources.d")
    done = []
    text = open(conf).read() if os.path.isfile(conf) else ""
    out, changed, has_dir = [], False, False
    for line in text.splitlines(True):
        if SRC_LINE.match(line):
            out.append("#pm-disabled " + line)
            changed = True
        else:
            if re.match(r'^\s*sourcedir\s+%s/?\s*$' % re.escape(sdir), line):
                has_dir = True
            out.append(line)
    if not has_dir:
        out.append("%s\nsourcedir %s\n" % (MARK, sdir))
        changed = True
    if changed:
        if text and not os.path.exists(conf + ".pm-backup"):
            _write(conf + ".pm-backup", text)
        _write(conf, "".join(out))
        done.append("chrony.conf: internet pool/server lines commented out (backup chrony.conf.pm-backup)")
    os.makedirs(sdir, exist_ok=True)
    for n in sorted(os.listdir(sdir)):
        if n.endswith(".sources") and n != "phantom-mirage.sources":
            os.rename(os.path.join(sdir, n), os.path.join(sdir, n + DISABLED))
            done.append("set aside %s (now %s%s)" % (n, n, DISABLED))
    ours = os.path.join(sdir, "phantom-mirage.sources")
    if cfg["time_source"] == "ntp":
        _write(ours, "%s\nserver %s iburst\n" % (MARK, cfg["ntp_server"]))
    elif os.path.exists(ours):
        os.unlink(ours)
    return done


def apply_time(cfg, dry):
    """NTP from one local server, or no NTP at all (browser sets the clock).
    Configures whichever time service runs here; never an internet server."""
    svc = time_service()
    ntp = cfg["time_source"] == "ntp"
    what = ("server %s" % cfg["ntp_server"]) if ntp else "no servers (clock set from the admin browser)"
    if dry:
        say("dry run: time service %s; would configure %s with no internet fallback" % (svc, what))
        return svc
    if svc == "none":
        say("time: no time service found (neither chrony nor systemd-timesyncd); sensor clock left unchanged. "
            "Install chrony and run setup again for NTP")
        return svc
    test = "PM_TIMESYNCD_DROPIN" in os.environ or "PM_CHRONY_DIR" in os.environ
    if os.geteuid() != 0 and not test:
        say("not root: sensor clock settings left unchanged")
        return svc
    if svc == "chrony":
        for d in chrony_files(cfg):
            say("time: " + d)
        if os.geteuid() == 0:
            u = chrony_unit()
            rc, _ = _run(["systemctl", "restart", u], 30)
            if rc != 0:
                say("time: warning: systemctl restart %s failed" % u)
        say("time: chrony configured with %s; no internet fallback" % what)
        if os.geteuid() == 0 and ntp:
            rc, out = _run(["chronyc", "-n", "sources"])
            say("time: chrony sources now: " + (" | ".join(out.splitlines()[-3:]) if rc == 0 and out else "not readable yet"))
            say("time: undo the pool changes with: sudo /usr/bin/python3 -I %s restore-time" % os.path.abspath(__file__))
    else:
        if ntp:
            body = "%s\n[Time]\nNTP=%s\nFallbackNTP=\n" % (MARK, cfg["ntp_server"])
        else:
            body = "%s (clock set from the admin browser)\n[Time]\nNTP=\nFallbackNTP=\n" % MARK
        _write(TIMESYNCD_DROPIN, body)
        if os.geteuid() == 0:
            for cmd in (["timedatectl", "set-ntp", "true" if ntp else "false"],
                        ["systemctl", "try-restart", "systemd-timesyncd"]):
                _run(cmd)
        say("time: systemd-timesyncd configured with %s; no internet fallback" % what)
        if os.geteuid() == 0 and ntp:
            rc, out = _run(["timedatectl", "show-timesync", "-p", "ServerAddress", "--value"])
            say("time: timesyncd server now: " + (out or "not contacted yet"))
    if cfg["timezone"] and os.geteuid() == 0:
        _run(["timedatectl", "set-timezone", cfg["timezone"]])
    return svc


def restore_time(_):
    """Put back what setup set aside for chrony and remove our time files."""
    sdir = os.path.join(CHRONY_DIR, "sources.d")
    conf = os.path.join(CHRONY_DIR, "chrony.conf")
    n = 0
    if os.path.isdir(sdir):
        for f in sorted(os.listdir(sdir)):
            if f.endswith(DISABLED):
                os.rename(os.path.join(sdir, f), os.path.join(sdir, f[:-len(DISABLED)]))
                n += 1
        try:
            os.unlink(os.path.join(sdir, "phantom-mirage.sources"))
            n += 1
        except FileNotFoundError:
            pass
    if os.path.exists(conf + ".pm-backup"):
        os.rename(conf + ".pm-backup", conf)
        n += 1
    try:
        os.unlink(TIMESYNCD_DROPIN)
        n += 1
    except FileNotFoundError:
        pass
    if os.geteuid() == 0:
        _run(["systemctl", "try-restart", chrony_unit()], 30)
        _run(["systemctl", "try-restart", "systemd-timesyncd"])
    say("time: %s restored" % ("distribution time settings" if n else "nothing to restore;"))
    return 0


def parse(argv):
    opts, i = {}, 0
    names = {"--sensor-name": "sensor_name", "--admin-user": "admin_user",
             "--console-port": "port", "--time-source": "time_source",
             "--ntp-server": "ntp_server", "--timezone": "timezone",
             "--retention": "alert_retention_days"}
    while i < len(argv):
        a = argv[i]
        k, eq, v = a.partition("=")
        if k.startswith("--pass") or k in ("-p", "--pw", "--secret"):
            die("the admin password is never accepted as an option; you will be asked for it", 2)
        if k in names:
            if not eq:
                i += 1
                if i >= len(argv):
                    die("%s needs a value" % k, 2)
                v = argv[i]
            opts[names[k]] = v
        elif a in ("--reconfigure", "--dry-run"):
            opts[a[2:]] = True
        else:
            die("unknown console option: %s" % a, 2)
        i += 1
    return opts


def first_run(argv):
    o = parse(argv)
    dry = o.get("dry-run")
    adm = pmstore.load_admin()
    cfg = pmstore.load_config()
    if adm and cfg.get("sensor_name") and not o.get("reconfigure"):
        say("console: keeping the existing setup (sensor %s, admin %s); "
            "use --reconfigure-console to change it, --reset-admin for the password"
            % (cfg["sensor_name"], adm.get("username")))
        if not dry and os.path.exists(pmstore.path("cert.pem")):
            say("console certificate SHA-256 fingerprint: " + ensure_cert(cfg["sensor_name"]))
            fix_perms()
        return 0
    if "ntp_server" in o:
        err = chk_ntp(o["ntp_server"])
        if err:
            die("ntp-server: " + err, 2)
    if not interactive():
        if o.get("time_source") == "ntp" and "ntp_server" not in o:
            die("--time-source ntp needs --ntp-server ADDRESS (an NTP host on your network); "
                "there is no default", 2)
        vals = {
            "sensor_name": o.get("sensor_name") or "mirage",
            "admin_user": o.get("admin_user") or "admin",
            "port": str(o.get("port") or 8443),
            "time_source": o.get("time_source") or "browser",
            "timezone": o.get("timezone") or "UTC",
            "alert_retention_days": str(o.get("alert_retention_days") or 90),
            "ntp_server": o.get("ntp_server") or "",
        }
        if vals["time_source"] != "ntp":
            vals["ntp_server"] = ""
        for key, chk in (("sensor_name", chk_name), ("admin_user", chk_user),
                         ("port", chk_port), ("time_source", chk_ts),
                         ("timezone", chk_tz), ("alert_retention_days", chk_ret)):
            err = chk(vals[key])
            if err:
                die("%s: %s" % (key.replace("_", "-"), err), 2)
        if vals["time_source"] == "ntp":
            err = chk_ntp(vals["ntp_server"])
            if err:
                die("ntp-server: " + err, 2)
        pw = None
        for _ in range(5):
            cand = secrets.token_urlsafe(18)
            if not pmauth.password_problem(cand, vals["admin_user"]):
                pw = cand
                break
        if not pw:
            die("could not generate an admin password")
        if dry:
            say("dry run: console would be set up for sensor %s, admin %s, https://127.0.0.1:%s"
                % (vals["sensor_name"], vals["admin_user"], vals["port"]))
            say("dry run: admin login for %s would be written to %s" % (vals["admin_user"], admin_file()))
            apply_time(vals, True)
            return 0
        save_first_run(cfg, vals, pw)
        write_initial_admin(vals["admin_user"], pw)
        del pw
        return 0
    checks = [("sensor_name", "Sensor name (required)", None, chk_name),
              ("admin_user", "Admin username", (adm or {}).get("username") or "", chk_user),
              ("port", "Console port (on 127.0.0.1 only)", cfg.get("port", 8443), chk_port),
              ("time_source", "Time source: 'ntp' (an NTP server on your local network) or "
               "'browser' (set the sensor clock from your browser at sign-in)",
               cfg.get("time_source", "browser"), chk_ts)]
    vals = {}
    for key, prompt, dflt, chk in checks:
        if key in o:
            err = chk(str(o[key]))
            if err:
                die("%s: %s" % (key.replace("_", "-"), err), 2)
            vals[key] = str(o[key])
        else:
            vals[key] = ask(prompt, cfg.get(key) or dflt, chk)
    if vals["time_source"] == "ntp":
        if "ntp_server" in o:
            vals["ntp_server"] = o["ntp_server"]
        else:
            # No default: a stale or loopback value must never be offered.
            vals["ntp_server"] = ask("Local NTP server (address of an NTP host on your network)", None, chk_ntp)
    else:
        vals["ntp_server"] = ""
    for key, prompt, dflt, chk in (
            ("timezone", "Time zone", cfg.get("timezone", "UTC"), chk_tz),
            ("alert_retention_days", "Alert retention (days)", cfg.get("alert_retention_days", 90), chk_ret)):
        if key in o:
            err = chk(str(o[key]))
            if err:
                die("%s: %s" % (key, err), 2)
            vals[key] = str(o[key])
        else:
            vals[key] = ask(prompt, dflt, chk)
    pw = ask_password(vals["admin_user"])
    if dry:
        say("dry run: console would be set up for sensor %s, admin %s, https://127.0.0.1:%s"
            % (vals["sensor_name"], vals["admin_user"], vals["port"]))
        apply_time(vals, True)
        return 0
    save_first_run(cfg, vals, pw)
    forget_initial_admin()
    del pw
    return 0


def reset_admin(argv):
    if argv:
        parse(argv)  # rejects password flags
    if not interactive():
        die("--reset-admin must be run from the sensor's terminal")
    if os.geteuid() != 0 and not TEST:
        die("must be run as root")
    adm = pmstore.load_admin() or {}
    user = ask("Admin username", adm.get("username") or None, chk_user)
    pw = ask_password(user)
    os.makedirs(pmstore.STATE_DIR, mode=0o770, exist_ok=True)
    pmstore.save_admin(user, pmauth.hash_password(pw))
    del pw
    pmauth.Lockout(pmstore.path("lockout.json")).reset()
    pmstore.audit("terminal", "reset-admin", "admin %s; lockouts cleared" % user)
    fix_perms()
    say("console: admin %s reset; lockouts cleared. Restart signs everyone out:" % user)
    try:
        subprocess.run(["systemctl", "try-restart", "phantom-mirage-console"], timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass
    return 0


def read_tty(argv):
    """Print one line from the keyboard. The prompt goes to stderr.

    The shell captures stdout, so the prompt must not be written there.
    Used for the final [Y/n] when setup was piped into sudo.
    """
    prompt = argv[0] if argv else ""
    fd = _keyboard()
    if fd is None:
        return 1
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = _read_fd(fd)
    except EOFError:
        return 1
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    return 0


def status(_):
    cfg, adm = pmstore.load_config(), pmstore.load_admin()
    if not adm:
        print("console: not set up")
        return 3
    print("console: sensor %s, admin %s, https://127.0.0.1:%s" % (cfg["sensor_name"], adm["username"], cfg["port"]))
    try:
        print("certificate SHA-256: " + open(pmstore.path("cert.sha256")).read().strip())
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("first-run", "reset-admin", "status", "restore-time", "read-tty"):
        die("usage: pm-console-setup.py first-run|reset-admin|status|restore-time [options]", 2)
    try:
        sys.exit({"first-run": first_run, "reset-admin": reset_admin, "status": status,
                  "restore-time": restore_time, "read-tty": read_tty}[sys.argv[1]](sys.argv[2:]))
    except (KeyboardInterrupt, EOFError):
        print()
        die("aborted")
