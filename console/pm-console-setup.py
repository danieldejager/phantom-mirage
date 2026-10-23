#!/usr/bin/python3
"""Console part of phantom-mirage-setup (run as root from the terminal).

  pm-console-setup.py first-run [--sensor-name N] [--admin-user U]
        [--console-port P] [--time-source ntp|browser] [--ntp-server HOST]
        [--timezone TZ] [--retention DAYS] [--reconfigure] [--dry-run]
  pm-console-setup.py reset-admin
  pm-console-setup.py status

The admin password is only ever read at a hidden prompt; it is never
accepted as an option. Test-only: PM_TEST_STDIN=1 reads the answers
(including the password, twice) from stdin lines instead of the terminal.
"""
import getpass
import grp
import ipaddress
import os
import pwd
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pmauth  # noqa: E402
import pmstore  # noqa: E402

USER = "phantom-mirage-console"
TIMESYNCD_DROPIN = os.environ.get("PM_TIMESYNCD_DROPIN",
                                  "/etc/systemd/timesyncd.conf.d/phantom-mirage.conf")
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')
USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}$')
TEST = os.environ.get("PM_TEST_STDIN") == "1"


def say(msg):
    print("phantom-mirage-setup: " + msg, flush=True)


def die(msg, code=1):
    sys.stderr.write("phantom-mirage-setup: %s\n" % msg)
    sys.exit(code)


def interactive():
    return TEST or (sys.stdin.isatty() and sys.stdout.isatty())


def ask(prompt, default=None, check=None):
    for _ in range(5):
        if TEST:
            line = sys.stdin.readline()
            if not line:
                die("test stdin ended at: " + prompt)
            v = line.rstrip("\n")
        else:
            v = input("%s%s: " % (prompt, " [%s]" % default if default not in (None, "") else ""))
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
            p1 = getpass.getpass("Admin password (hidden, %d+ characters): " % pmauth.MIN_PASSWORD)
            p2 = getpass.getpass("Repeat password: ")
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


def chk_ntp(v):
    """A host on the local network only: no internet time servers."""
    try:
        a = ipaddress.ip_address(v)
        return None if (a.is_private or a.is_link_local) and not a.is_loopback else \
            "use the address of an NTP server on your local network (private address)"
    except ValueError:
        if re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$', v) and (
                v.endswith((".lan", ".local", ".internal", ".home.arpa")) or "." not in v):
            return None
        return "use a private IP or a local hostname (.lan, .local, .internal, .home.arpa)"


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


def apply_time(cfg, dry):
    """NTP from a local server, or no NTP at all (browser sets the clock):
    either way no internet time servers (FallbackNTP= is emptied)."""
    if cfg["time_source"] == "ntp":
        body = "# written by phantom-mirage-setup\n[Time]\nNTP=%s\nFallbackNTP=\n" % cfg["ntp_server"]
    else:
        body = "# written by phantom-mirage-setup (clock set from the admin browser)\n[Time]\nNTP=\nFallbackNTP=\n"
    if dry:
        say("dry run: would write %s and run timedatectl set-ntp %s" % (
            TIMESYNCD_DROPIN, "true" if cfg["time_source"] == "ntp" else "false"))
        return
    if os.geteuid() != 0 and "PM_TIMESYNCD_DROPIN" not in os.environ:
        say("not root: sensor clock settings left unchanged")
        return
    os.makedirs(os.path.dirname(TIMESYNCD_DROPIN), exist_ok=True)
    with open(TIMESYNCD_DROPIN, "w") as f:
        f.write(body)
    if os.geteuid() != 0:
        return
    for cmd in (["timedatectl", "set-ntp", "true" if cfg["time_source"] == "ntp" else "false"],
                ["systemctl", "try-restart", "systemd-timesyncd"]):
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass
    if cfg["timezone"]:
        try:
            subprocess.run(["timedatectl", "set-timezone", cfg["timezone"]],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


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
    if not interactive():
        say("console: NOT set up (no terminal). Run on the sensor: sudo phantom-mirage-setup --console")
        return 3
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
            err = chk_ntp(o["ntp_server"])
            if err:
                die("ntp-server: " + err, 2)
            vals["ntp_server"] = o["ntp_server"]
        else:
            vals["ntp_server"] = ask("Local NTP server", cfg.get("ntp_server") or None, chk_ntp)
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
    os.makedirs(pmstore.STATE_DIR, mode=0o770, exist_ok=True)
    cfg.update(sensor_name=vals["sensor_name"], port=int(vals["port"]),
               time_source=vals["time_source"], ntp_server=vals["ntp_server"],
               timezone=vals["timezone"], alert_retention_days=int(vals["alert_retention_days"]))
    pmstore.save_config(cfg)
    h = pmauth.hash_password(pw)
    del pw
    pmstore.save_admin(vals["admin_user"], h)
    pmauth.Lockout(pmstore.path("lockout.json")).reset()
    pmstore.audit("setup", "first-run", "sensor %s, admin %s, port %s, time %s, hash %s" % (
        cfg["sensor_name"], vals["admin_user"], cfg["port"], cfg["time_source"], pmauth.hash_scheme(h)))
    fp = ensure_cert(cfg["sensor_name"])
    apply_time(cfg, False)
    fix_perms()
    say("console: admin %s set (password stored as a salted %s hash)" % (vals["admin_user"], pmauth.hash_scheme(h)))
    say("console certificate SHA-256 fingerprint: " + fp)
    return 0


def reset_admin(argv):
    if argv:
        parse(argv)  # rejects password flags
    if not TEST and not (sys.stdin.isatty() and sys.stdout.isatty()):
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
    if len(sys.argv) < 2 or sys.argv[1] not in ("first-run", "reset-admin", "status"):
        die("usage: pm-console-setup.py first-run|reset-admin|status [options]", 2)
    try:
        sys.exit({"first-run": first_run, "reset-admin": reset_admin, "status": status}[sys.argv[1]](sys.argv[2:]))
    except (KeyboardInterrupt, EOFError):
        print()
        die("aborted")
