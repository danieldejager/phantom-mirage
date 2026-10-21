#!/usr/bin/env python3
#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
# Nmap OS fingerprint regression test (Python 3, #36).
#
# Binds a fixed set of personalities from ../nmap-os-db to 192.18.0.x,
# runs real nmap OS detection against each over the regress veth pair
# (regress.py) and writes, per personality, how nmap classified it:
#   MATCH    nmap's OS details or OS guesses name the personality
#   OTHER    nmap named something else
#   NONE     nmap had no OS match
# (Whether nmap reports an exact "OS details" line or only a top guess
# depends on timing-based tests such as TCP ISN rate, so the two are not
# told apart; nmap.log has the full output, EXACT/GUESS per target.)
# The result is compared with nmap.output.1. honeyd runs with -R 1, so
# its answers are the same every run. Needs root, nmap, python3-dpkt.
#
#   python3 nmap.py        compare      -g  regenerate      -d  debug
#
import getopt
import os
import re
import subprocess
import sys
import tempfile

import regress

PERSONALITIES = [
    "Linux 2.6.11 - 2.6.20",
    "Microsoft Windows XP SP2 or SP3",
    "FreeBSD 6.2-RELEASE",
    "OpenBSD 4.0",
    "Sun Solaris 10",
    "Cisco 2948G switch (CatOS 6.3)",
    "Apple Mac OS X 10.5.6 (Leopard) (Darwin 9.6.0)",
    "HP LaserJet 4250 printer",
]
SRC = "192.0.2.1"
NETNS = "hdnmap"
OUTPUT = "nmap.output.1"


def target(i):
    return "192.18.0.%d" % (10 + i)


def known(db):
    with open(db, encoding="latin-1") as f:
        names = set(m.group(1).rstrip() for m in
                    (re.match(r"^Fingerprint ([^#]*)$", l.rstrip("\n"))
                     for l in f) if m)
    missing = [p for p in PERSONALITIES if p not in names]
    if missing:
        sys.stderr.write("not in %s: %s\n" % (db, missing))
        sys.exit(1)


def cleanup(reg):
    subprocess.call(["ip", "netns", "del", NETNS], stderr=subprocess.DEVNULL)
    reg.RemoveAllRoutes()


def make_configuration(filename):
    with open(filename, "w") as out:
        out.write("create template\n"
                  "set template default tcp action closed\n"
                  "set template default udp action closed\n"
                  "add template tcp port 23 open\n")
        for i, name in enumerate(PERSONALITIES):
            out.write('bind %s template\n' % target(i))
            out.write('set %s personality "%s"\n' % (target(i), name))


def classify(name, text):
    details = re.search(r"^OS details: (.*)$", text, re.M)
    guesses = re.search(r"^Aggressive OS guesses: (.*)$", text, re.M)
    if details and details.group(1).strip() == name:
        return "EXACT"
    for m in (details, guesses):
        if m and name in m.group(1):
            return "GUESS"
    if details or guesses or re.search(r"^Running", text, re.M):
        return "OTHER"
    return "NONE"


def nmap(ip):
    cmd = ["ip", "netns", "exec", NETNS, "nmap", "-n", "-Pn", "-O",
           "--osscan-guess", "--max-os-tries", "1", "-p", "1,23", ip]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=180)
    return p.stdout.decode(errors="replace")


def main():
    opts, _ = getopt.getopt(sys.argv[1:], "dg")
    flags = dict(opts)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    known("../nmap-os-db")
    make_configuration("config.nmap")
    reg = regress.regress("Nmap fingerprints", "../honeyd", "config.nmap",
                          debug="-d" in flags)
    reg.generate = "-g" in flags
    # nmap runs in its own network namespace on hdt1 (192.0.2.1), so
    # nothing it uses is a local address for honeyd's side: honeyd's
    # replies go out hdt0 and nmap sees them like a remote scanner would.
    ns = ["ip", "-n", NETNS]
    steps = [("ip", "netns", "add", NETNS),
             ("ip", "link", "set", regress.TEST_IF, "netns", NETNS),
             ns + ["link", "set", "lo", "up"],
             ns + ["addr", "add", "10.250.0.1/30", "dev", regress.TEST_IF],
             ns + ["addr", "add", SRC + "/32", "dev", regress.TEST_IF],
             ns + ["link", "set", regress.TEST_IF, "up"],
             ns + ["route", "add", "192.18.0.0/15", "via", "10.250.0.2",
                   "dev", regress.TEST_IF, "src", SRC]]
    for st in steps:
        if subprocess.call(st):
            sys.stderr.write("failed: %s\n" % " ".join(st))
            cleanup(reg)
            sys.exit(1)
    sys.stderr.write("\tRunning nmap -O against %d personalities: " %
                     len(PERSONALITIES))
    reg.start_honeyd()
    lines, logs = [], []
    try:
        for i, name in enumerate(PERSONALITIES):
            text = nmap(target(i))
            res = classify(name, text)
            lines.append("%s %s\n" % (
                "MATCH" if res in ("EXACT", "GUESS") else res, name))
            logs.append("== %s (%s) -> %s\n%s" % (target(i), name, res, text))
            sys.stderr.write(res[0])
            sys.stderr.flush()
    finally:
        reg.stop_honeyd()
        subprocess.call(["ip", "netns", "del", NETNS])
    sys.stderr.write("\n")
    fd, got = tempfile.mkstemp(prefix="nmap.output.")
    with os.fdopen(fd, "w") as f:
        f.writelines(lines)
    os.chmod(got, 0o644)
    with open("nmap.log", "w") as f:
        f.writelines(logs)
    reg.runtests = 1
    reg.dpktfile = got
    if reg.generate:
        os.replace(got, OUTPUT)
        sys.stderr.write("Generated output file '%s'\n" % OUTPUT)
        sys.stdout.write("".join(lines))
    else:
        reg.outputfile = OUTPUT
        sys.stdout.write("".join(lines))
        if reg.compare():
            reg.oktests = 1
            os.remove(got)
        else:
            subprocess.call(["diff", "-u", OUTPUT, got], stdout=sys.stderr)
            sys.stderr.write("nmap output: regress/nmap.log\n")
    reg.finish()


if __name__ == "__main__":
    main()
