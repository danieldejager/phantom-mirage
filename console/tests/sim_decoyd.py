"""A stand-in for pm-decoyd for console tests and screenshots.

It speaks the helper's socket protocol and runs the helper's own
validation and operation code (apply_op, op_list, op_options, render from
decoyd/pm-decoyd.py) on an in-memory store, and writes the rendered
decoys.conf where the console reads it. No root, verify or systemctl:
those parts are covered by decoyd/tests.
"""
import importlib.util
import ipaddress
import json
import os
import socket
import threading

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
_spec = importlib.util.spec_from_file_location("pmdecoyd_sim", os.path.join(REPO, "decoyd", "pm-decoyd.py"))
D = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(D)
D.P["services"] = os.path.join(REPO, "decoyd", "decoy-services.json")


class SimHelper:
    def __init__(self, sock_path, conf_out, network, binds=(), pers=("ws2022-fwoff", "linux-6")):
        self.path, self.conf_out = sock_path, conf_out
        self.nets = [ipaddress.IPv4Network(network, strict=False)]
        self.binds, self.pers = set(binds), list(pers)
        self.svcs = D.services()
        self.store = D.empty_store()
        self.reqs, self.force = [], None      # force: an error code to return once
        self.reloaded = True
        with open(conf_out, "w") as f:
            f.write(D.render(self.store, self.svcs))
        self.ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ls.bind(sock_path)
        self.ls.listen(8)
        self.ls.settimeout(0.2)
        self.stop = False
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def handle(self, q):
        if self.force:
            code, self.force = self.force, None
            raise D.Err(code, None, "forced by the test")
        op, args = q["op"], q["args"]
        if op == "list":
            return D.op_list(self.store, self.nets, self.binds)
        if op == "options":
            return D.op_options(self.pers, self.svcs)
        new, res = D.apply_op(op, args, self.store, self.nets, self.binds, self.pers, self.svcs)
        text = D.render(new, self.svcs)
        with open(self.conf_out, "w") as f:
            f.write(text)
        self.store = new
        return res

    def run(self):
        while not self.stop:
            try:
                c, _ = self.ls.accept()
            except socket.timeout:
                continue
            with c:
                buf = b""
                while not buf.endswith(b"\n"):
                    ch = c.recv(65536)
                    if not ch:
                        break
                    buf += ch
                q = json.loads(buf)
                self.reqs.append(q)
                r = {"v": 1, "id": q.get("id", ""), "ok": False, "reloaded": False, "rolled_back": False}
                try:
                    r["result"] = self.handle(q)
                    r["ok"] = True
                    r["reloaded"] = q["op"] not in ("list", "options") and self.reloaded
                except D.Err as e:
                    r["error"] = {"code": e.code, "field": e.field, "message": e.message}
                c.sendall((json.dumps(r) + "\n").encode())

    def close(self):
        self.stop = True
        self.t.join(2)
        self.ls.close()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
