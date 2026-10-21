#!/usr/bin/env python3
"""#16: connect to the probe script port, read its report, and check the
/proc/<pid>/status of honeyd and of the script child.

usage: check_sandbox.py MODE HONEYD_PID   (MODE: default | sandbox)
"""
import socket, subprocess, sys, time

mode, hpid = sys.argv[1], sys.argv[2]
fail = []

def status(pid):
    d = {}
    for line in open("/proc/%s/status" % pid):
        k, _, v = line.partition(":")
        d[k] = v.split()
    return d

def check(what, cond):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fail.append(what)

def hardened(name, st, bnd=True):
    check(name + " Uid all 65534", st["Uid"] == ["65534"] * 4)
    check(name + " Gid all 65534", st["Gid"] == ["65534"] * 4)
    check(name + " Groups 65534", st["Groups"] == ["65534"])
    for k in ("CapInh", "CapPrm", "CapEff", "CapAmb") + (("CapBnd",) if bnd else ()):
        check("%s %s=0" % (name, k), int(st[k][0], 16) == 0)
    check(name + " NoNewPrivs=1", st["NoNewPrivs"] == ["1"])

hardened("honeyd", status(hpid))

s = socket.create_connection(("10.99.0.10", 2325), timeout=10)
buf, t0 = b"", time.time()
while b"READY" not in buf and time.time() - t0 < 10:
    d = s.recv(4096)
    if not d:
        break
    buf += d
report = dict(l.split("=", 1) for l in buf.decode().split() if "=" in l)
print("probe:", report)
pid = subprocess.run(["pgrep", "-n", "-f", "sandbox_probe.sh"],
                     capture_output=True, text=True).stdout.strip()
st = status(pid)
hardened("script", st)

landlock = len(sys.argv) < 4 or sys.argv[3] != "no-landlock"
if mode == "default":
    check("script not seccomp-filtered", st["Seccomp"] == ["0"])
    check("script may write /tmp", report.get("write_tmp") == "ok")
else:
    check("script Seccomp=2 (filter)", st["Seccomp"] == ["2"])
    check("unshare denied (seccomp)", report.get("unshare") == "denied")
    if landlock:
        check("write /tmp denied (landlock)", report.get("write_tmp") == "denied")
        check("write --sandbox-allow-write dir ok", report.get("write_allow") == "ok")
        check("/root,/home hidden", report.get("list_home") == "denied")
        check("/proc host view hidden", report.get("proc_host") == "denied")
        check("/etc readable", report.get("read_etc") == "ok")
    else:
        print("::warning::Landlock unavailable on this runner; filesystem checks skipped")
sys.exit(1 if fail else 0)
