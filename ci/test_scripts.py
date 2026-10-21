#!/usr/bin/env python3
"""Python 3 service scripts under scripts/ (#36): canned requests get a
sane reply, and binary junk (non-UTF-8, NULs, truncated packets, random
bytes) never crashes a script (exit 0, no traceback, no hang)."""
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile

TOP = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
S = os.path.join(TOP, "scripts")
sys.path.insert(0, os.path.join(S, "lib"))
import names  # noqa: E402

tmp = tempfile.mkdtemp(prefix="hdscripts.")
db = os.path.join(tmp, "names.db")
names.AddNames(db, ["WKSTN01"])
namescfg = os.path.join(tmp, "names.cfg")
with open(namescfg, "w") as f:
    f.write("NAMES_FILE %s\n" % db)
smbcfg = os.path.join(tmp, "smb.cfg")
with open(smbcfg, "w") as f:
    f.write("NATIVE_OS Windows 5.1\nLAN_MANAGER Windows 2000 LAN Manager\n"
            "PRIMARY_DOMAIN WORKGROUP\nTIME_ZONE 65176\n")
ENV = dict(os.environ, PHANTOM_MIRAGE_HOME="", PHANTOM_MIRAGE_TEMPLATE_NAME="10.99.0.10",
           PHANTOM_MIRAGE_IP_SRC="10.0.0.1", PHANTOM_MIRAGE_IP_DST="10.99.0.10",
           PHANTOM_MIRAGE_INTERFACE="lo", PATH="/usr/bin:/bin")
failures = []


def run(script, data, cfg="-", close=True):
    """Runs script with data on stdin; returns stdout bytes."""
    p = subprocess.Popen([sys.executable, os.path.join(S, script), "x", cfg],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=ENV, cwd=tmp)
    try:
        out, err = p.communicate(data, timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        failures.append("%s: hung on %r" % (script, data[:40]))
        return b""
    if p.returncode != 0 or b"Traceback" in err:
        failures.append("%s: rc=%d on %r\n%s" % (
            script, p.returncode, data[:40], err.decode(errors="replace")))
    return out


def check(cond, what):
    if not cond:
        failures.append(what)


# --- canned requests -------------------------------------------------------
def smb_hdr(cmd, pid=b"\x34\x12", mid=b"\x01\x00"):
    return (b"\xffSMB" + cmd + b"\x00" * 4 + b"\x18" + b"\x01\x28" +
            b"\x00" * 2 + b"\x00" * 8 + b"\x00" * 2 + b"\x00" * 2 +
            pid + b"\x00\x00" + mid)


def nbss(smb):
    return b"\x00" + struct.pack(">I", len(smb))[1:] + smb


dialects = b"\x02PC NETWORK PROGRAM 1.0\x00\x02NT LM 0.12\x00"
smb_negotiate = nbss(smb_hdr(b"\x72") + b"\x00" +
                     struct.pack("<H", len(dialects)) + dialects)
smb_setup = nbss(smb_hdr(b"\x73") + b"\x00" + struct.pack("<H", 0))
smb_tree = nbss(smb_hdr(b"\x75") + b"\x00" + struct.pack("<H", 4) +
                b"\\\\x\x00")
smb_req = smb_negotiate + smb_setup + smb_tree
out = run("misc/smb-autofail.py", smb_req, smbcfg)
msgs = []
while len(out) >= 4:
    n = struct.unpack(">I", b"\x00" + out[1:4])[0]
    msgs.append(out[4:4 + n])
    out = out[4 + n:]
check(len(msgs) == 3 and not out, "smb: want 3 framed replies, got %d" %
      len(msgs))
if len(msgs) == 3:
    check(all(m[:4] == b"\xffSMB" for m in msgs), "smb: bad magic")
    check(msgs[0][4] == 0x72 and msgs[0][26:28] == b"\x34\x12",
          "smb: negotiate reply / pid")
    check(struct.unpack("<H", msgs[0][33:35])[0] == 1, "smb: dialect index")
    check(b"WORKGROUP\x00" in msgs[0], "smb: domain")
    check(msgs[1][4] == 0x73 and b"Windows 5.1\x00" in msgs[1],
          "smb: session setup reply")
    check(msgs[2][4] == 0x75 and msgs[2][5:9] == b"\x22\x00\x00\xc0",
          "smb: tree connect must be access denied")

prelogin_tokens = (b"\x00" + struct.pack("!HH", 21, 6) +
                   b"\x01" + struct.pack("!HH", 27, 1) +
                   b"\x03" + struct.pack("!HH", 28, 4) + b"\xff")
prelogin_payload = b"\x09\x00\x00\x00\x00\x00" + b"\x01" + b"\xaa\xbb\xcc\xdd"
prelogin = (struct.pack("!BBHHBB", 18, 1, 8 + len(prelogin_tokens) +
                        len(prelogin_payload), 0, 0, 0) +
            prelogin_tokens + prelogin_payload)
login = struct.pack("!BBHHBB", 16, 1, 8 + 4, 0, 1, 0) + b"\x00\xff\x00\x80"
out = run("win32/mssql.py", prelogin + login)
check(out[:1] == b"\x04" and len(out) > len(prelogin), "mssql: prelogin")
pre = out[:len(prelogin)]
check(pre[8 + len(prelogin_tokens) + 6] == 2, "mssql: encryption not forced off")
check(pre[-4:] == b"\x00\x00\x00\x00", "mssql: thread id not zeroed")
err = out[len(prelogin):]
check(err[:1] == b"\x04" and err[8:9] == b"\xaa" and
      struct.unpack("<I", err[11:15])[0] == 18456 and
      "Login failed for user.".encode("utf-16-le") in err,
      "mssql: login error 18456")
check(struct.unpack("!H", err[2:4])[0] == len(err), "mssql: TDS length")

out = run("linux/mysql.py", b"")
check(out[4:7] == b"\xff\x6a\x04" and
      struct.unpack("<I", out[:3] + b"\x00")[0] == len(out) - 4 and
      out.endswith(b"MySQL server"), "mysql: error 1130 greeting")

out = run("broadcasts/nbns-wpad-query.py", b"")
check(len(out) == 50 and out[2:12] == b"\x01\x10\x00\x01" + b"\x00" * 6 and
      out[12:46] == b" FHFAEBEECACACACACACACACACACACAAA\x00",
      "nbns-wpad-query: query format %r" % out)


def nb_encode(name, suffix=b"\x20"):
    raw = name.ljust(15) + suffix
    return b"\x20" + bytes(c for b in raw for c in
                           (0x41 + (b >> 4), 0x41 + (b & 0xf))) + b"\x00"


def nbns_query(name, qtype):
    return (b"\xab\xcd" + b"\x01\x10" + struct.pack("!HHHH", 1, 0, 0, 0) +
            nb_encode(name) + qtype + b"\x00\x01")


q = nbns_query(b"WKSTN01", b"\x00\x20")
out = run("win32/nbns.py", q, namescfg)
check(out[:2] == b"\xab\xcd" and out[2:4] == b"\x85\x80" and
      out.endswith(socket.inet_aton("10.99.0.10")), "nbns: NB answer")
check(run("win32/nbns.py", nbns_query(b"OTHER", b"\x00\x20"),
          namescfg) == b"", "nbns: answered for another name")
out = run("win32/nbns.py", nbns_query(b"WKSTN01", b"\x00\x21"), namescfg)
check(out[:2] == b"\xab\xcd" and b"WKSTN01" + b"\x20" * 8 + b"\x00" in out,
      "nbns: NBSTAT answer")


def mdns_query(name):
    q = b"".join(bytes([len(l)]) + l for l in name.split(b".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0, 1, 0, 0, 0) + q + b"\x00\x01\x00\x01"


out = run("linux/mdns/mdns.py", mdns_query(b"wkstn01.local"), namescfg)
check(out[:4] == b"\x12\x34\x84\x00" and
      out[12:27] == b"\x07WKSTN01\x05LOCAL\x00" and
      out.endswith(socket.inet_aton("10.99.0.10")), "mdns: A answer %r" % out)
check(run("linux/mdns/mdns.py", mdns_query(b"other.local"), namescfg) == b"",
      "mdns: answered for another name")

# --- junk: must not crash ------------------------------------------------
rnd = random.Random(36)
canned = {
    "misc/smb-autofail.py": (smb_req, smbcfg),
    "win32/mssql.py": (prelogin + login, "-"),
    "linux/mysql.py": (b"\x00", "-"),
    "broadcasts/nbns-wpad-query.py": (b"\x00", "-"),
    "win32/nbns.py": (q, namescfg),
    "linux/mdns/mdns.py": (mdns_query(b"wkstn01.local"), namescfg),
}
junk = [b"", b"\x00", b"\x00" * 4096, b"\xff\xfe\xfd\x80\xc3\x28" * 50,
        "é€😀".encode("utf-16-le") * 20, b"\xffSMB" + b"\xff" * 64,
        b"\x12" + b"\xff" * 7, b"\x12\x01\xff\xff\x00\x00\x00\x00" + b"\x00" * 9,
        b"\x00\x01\x00\x01" * 8 + b"\x3f" + b"\xc0" * 30]
junk += [bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 600)))
         for _ in range(20)]
runs = 0
for script, (req, cfg) in canned.items():
    cases = list(junk)
    cases += [req[:n] for n in sorted({1, 3, 4, 5, 12, 13, 20, 33, 40,
                                       len(req) // 2, len(req) - 1})
              if 0 < n < len(req)]                      # truncated
    cases += [req + b"\x00\xff" * 8, req.replace(b"\x00", b"\xff")]
    for data in cases:
        run(script, data, cfg)
        runs += 1

if failures:
    print("FAILED:\n" + "\n".join(failures))
    sys.exit(1)
print("service scripts: canned requests OK, %d junk/truncated inputs OK" %
      runs)
