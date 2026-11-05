"""A stand-in for pm-decoyd for console tests and screenshots.

It speaks the helper's socket protocol and runs the helper's own
validation and operation code (apply_op, op_list, op_options, render,
and for set_network check_network, retarget_store, rewrite_default from
decoyd/pm-decoyd.py) on an in-memory store, and writes the rendered
decoys.conf where the console reads it. No root, verify or systemctl:
those parts are covered by decoyd/tests.
"""
import importlib.util
import ipaddress
import json
import os
import socket
import time
import tempfile
import threading

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
_spec = importlib.util.spec_from_file_location("pmdecoyd_sim", os.path.join(REPO, "decoyd", "pm-decoyd.py"))
D = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(D)
D.P["services"] = os.path.join(REPO, "decoyd", "decoy-services.json")


class SimHelper:
    def __init__(self, sock_path, conf_out, network, binds=(), pers=("ws2022-fwoff", "linux-6"),
                 iface="eth0", info=None, default_path=None):
        # info: what host_info() would return; default_path: the
        # /etc/default/phantom-mirage stand in that set_network rewrites
        self.iface, self.default_path = iface, default_path
        self.info = info or {"ifaces": {}, "gateways": []}
        self.sys = tempfile.mkdtemp()
        for n in self.info["ifaces"]:
            os.mkdir(os.path.join(self.sys, n))
        self.path, self.conf_out = sock_path, conf_out
        self.nets = [ipaddress.IPv4Network(network, strict=False)]
        self.binds, self.pers = set(binds), list(pers)
        self.svcs = D.services()
        self.store = D.empty_store()
        self.reqs, self.force = [], None      # force: an error code to return once
        self.reloaded = True
        # what timeinfo reports; set_time to a server in unreachable fails
        self.time = {"service": "chrony", "unit": "chrony.service", "active": True,
                     "servers": ["192.168.1.5"], "synced": True, "reference": "192.168.1.5",
                     "stratum": 3, "offset_s": -0.000412, "sources": [], "ready": None, "max_servers": 3}
        self.unreachable = set()
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
        if op == "netinfo":
            return {"network": " ".join(map(str, self.nets)), "interface": self.iface,
                    "interfaces": [{"name": n, "addrs": [str(a) for a in x["addrs"]]}
                                   for n, x in sorted(self.info["ifaces"].items()) if not x["lo"] and x["addrs"]],
                    "gateways": sorted({str(g) for g in self.info["gateways"]}),
                    "min_prefix": D.MIN_PREFIX, "last_change": getattr(self, "last_change", None)}
        if op == "timeinfo":
            t = dict(self.time)
            t["last_change"] = getattr(self, "time_change", None)
            return t
        if op == "set_time":
            D._keys(args, "args", ("servers", "expect"), ("keep",))
            servers = D.check_servers(args["servers"], self.nets)
            if args["expect"] != self.time["servers"]:
                raise D.Err("E_CONFLICT", "args.expect", "the time servers changed since you loaded them")
            if servers == self.time["servers"]:
                raise D.Err("E_UNCHANGED", "args.servers", "those are already the time servers")
            reached = not any(s in self.unreachable for s in servers)
            if not reached and not args.get("keep"):
                self.time_change = {"id": "", "result": "rolled_back", "servers": self.time["servers"],
                                    "previous": self.time["servers"], "time": time.time()}
                e = D.Err("E_TIME_UNREACHABLE_ROLLED_BACK", None, "%s could not reach %s within 20 s; "
                          "the previous servers are back" % (self.time["unit"], " ".join(servers)))
                raise e
            prev = self.time["servers"]
            self.time.update(servers=servers, synced=reached, reference=servers[0] if reached else None)
            self.time_change = {"id": "", "result": "applied" if reached else "applied_unverified",
                                "servers": servers, "previous": prev, "time": time.time()}
            res = {"service": self.time["service"], "unit": self.time["unit"], "servers": servers, "reached": reached}
            if not reached:
                res["warnings"] = ["%s has not reached the new servers yet; kept as asked" % self.time["unit"]]
            return res
        if op == "set_network":
            D._keys(args, "args", ("network", "interface", "expect"))
            D._keys(args["expect"], "args.expect", ("network", "interface"))
            if args["expect"] != {"network": " ".join(map(str, self.nets)), "interface": self.iface}:
                raise D.Err("E_CONFLICT", "args.expect", "the address block changed since you loaded it")
            D.P["sysfs_net"] = self.sys
            net, iface = D.check_network(args["network"], args["interface"], self.info)
            if [net] == self.nets and iface == self.iface:
                raise D.Err("E_UNCHANGED", "args.network", "that is already the address block")
            new, dropped = D.retarget_store(self.store, net)
            if self.default_path:
                with open(self.default_path) as f:
                    t = D.rewrite_default(f.read(), str(net), iface)
                with open(self.default_path, "w") as f:
                    f.write(t)
            with open(self.conf_out, "w") as f:
                f.write(D.render(new, self.svcs))
            prev = {"network": " ".join(map(str, self.nets)), "interface": self.iface}
            self.store, self.nets, self.iface = new, [net], iface
            self.last_change = {"id": "", "result": "applied", "network": str(net), "interface": iface,
                                "previous": prev, "dropped": dropped, "time": time.time()}
            return {"network": str(net), "interface": iface, "dropped": dropped, "farpd": False,
                    "restarted": self.reloaded}
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
                    r["reloaded"] = q["op"] not in ("list", "options", "netinfo", "timeinfo") and self.reloaded
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
