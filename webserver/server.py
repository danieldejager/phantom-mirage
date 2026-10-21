#
# Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
# All rights reserved.
#
"""Honeyd internal web server: a read-only, local status page.

pyextend.c calls make_server(root) once, then handle_request(server,
request_bytes, client_address) for each complete HTTP request and writes
the returned bytes back to the client.  There is no socket here; honeyd
owns the listening socket (bound to 127.0.0.1 unless --webserver-address
says otherwise).

Only GET and HEAD are accepted.  "/" (also /index.html, /index.py) is the
status page, generated from the honeyd module with the standard library.
Everything else is served as a static file from the styles/, images/ and
graphs/ directories under the web root.  Nothing is executed from the web
root and nothing changes honeyd state.
"""

import html
import http.server
import io
import mimetypes
import os
import posixpath
import time
import urllib.parse

try:
    import honeyd
except ImportError:          # imported outside honeyd (tests)
    honeyd = None

__version__ = "0.2"

STATIC_DIRS = ("styles", "images", "graphs")
INDEX_PATHS = ("/", "/index.html", "/index.htm", "/index.py")


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def humanize(number, postfix):
    number = float(number)
    units = ("B", "KB", "MB", "GB", "TB")
    scale = 0
    while number > 1000 and scale < len(units) - 1:
        scale += 1
        number /= 1000
    return "%.2f %s%s" % (number, units[scale], postfix)


def format_uptime(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return "%d days %02d:%02d:%02d" % (days, hours, minutes, seconds)


def table(title, explanation, headings, rows, empty=None):
    out = ['<div class="status">', "<h1>%s</h1>" % esc(title),
           "<p>%s</p>" % esc(explanation)]
    if not rows and empty:
        out.append("<p>%s</p>" % esc(empty))
    else:
        out.append("<table>")
        out.append("<tr>" + "".join(
            '<td class="tableHeadingInside">%s</td>' % esc(h)
            for h in headings) + "</tr>")
        for row in rows:
            out.append("<tr>" + "".join(
                "<td>%s</td>" % esc(c) for c in row) + "</tr>")
        out.append("</table>")
    out.append("</div>")
    return "\n".join(out)


def status_page(mod):
    """Builds the status page from the honeyd module (or a stand-in)."""
    config = mod.config()
    parts = []

    parts.append(table(
        "Interface Information",
        "The interfaces Honeyd listens on.",
        ("Name", "Address", "MTU", "Link Address"),
        [(i["name"], i["address"], i["mtu"], i["link"])
         for i in mod.interfaces()]))

    stats = mod.stats_network()
    parts.append(table(
        "Honeyd Statistics",
        "Average traffic over the last minute, hour and day.",
        ("Name", "Minute", "Hour", "Day"),
        [(k, humanize(v[0], "/s"), humanize(v[1], "/s"), humanize(v[2], "/s"))
         for k, v in sorted(stats.items())]))

    for proto in ("tcp", "udp"):
        conns = mod.status_connections(proto)
        parts.append(table(
            "Active %s Connections" % proto.upper(),
            "Connections Honeyd is currently handling.",
            ("Src IP", "Src Port", "Dst IP", "Dst Port", "Received", "Sent"),
            [(c["src"], c["sport"], c["dst"], c["dport"],
              c["received"], c["sent"]) for c in conns],
            empty="There are currently no active %s connections." %
            proto.upper()))

    parts.append(table(
        "Bound IP addresses",
        "The currently configured virtual honeypots.",
        ("Address", "Personality", "Ethernet", "TCP", "UDP", "ICMP"),
        [(t["address"], t["personality"], t["ethernet"], t["tcp_action"],
          t["udp_action"], t["icmp_action"]) for t in mod.config_ips()],
        empty="No addresses are bound."))

    parts.append(table(
        "Honeyd Static Configuration", "Files Honeyd was started with.",
        ("Key", "Value"), sorted(config.items())))

    title = "Honeyd %s Status" % config.get("version", "")
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>%s</title>
<link rel="stylesheet" type="text/css" href="/styles/layout.css">
</head>
<body>
<div id="header">
<h1>%s</h1>
<div class="date">Uptime: %s</div>
</div>
<div class="content">
%s
<div class="graphs">
<img height="155" width="484" alt="hourly traffic" src="/graphs/traffic_hourly.gif"><br>
<img height="155" width="484" alt="daily traffic" src="/graphs/traffic_daily.gif">
</div>
</div>
</body>
</html>
""" % (esc(title), esc(title), esc(format_uptime(mod.uptime())),
       "\n".join(parts))


class HoneydServer:
    """Holds the web root and the last response for pyextend.c."""

    def __init__(self, root, mod=None):
        self.root = os.path.realpath(root)
        self.mod = mod if mod is not None else honeyd
        self.result = b""

    def handle_request(self, request, client_address):
        if isinstance(request, str):
            request = request.encode("latin-1")
        self.result = b""
        HoneydRequestHandler(request, client_address, self)
        return self.result


class HoneydRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "HoneydHTTP/" + __version__
    protocol_version = "HTTP/1.0"

    def __init__(self, request, client_address, server):
        self.client_address = (client_address, 0)
        self.server = server
        self.rfile = io.BytesIO(request)
        self.wfile = io.BytesIO()
        self.close_connection = True
        try:
            self.handle_one_request()
        except Exception as e:                  # never take honeyd down
            self.log_message("internal error: %r", e)
            self.wfile = io.BytesIO()
            self.send_error(500)
        server.result = self.wfile.getvalue()

    def send_body(self, body, ctype, head_only, nocache=False):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if nocache:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def static_path(self, path):
        """Maps a URL path to a file under one of STATIC_DIRS, or None."""
        path = posixpath.normpath(urllib.parse.unquote(path))
        words = [w for w in path.split("/") if w and w not in (".", "..")]
        if len(words) < 2 or words[0] not in STATIC_DIRS:
            return None
        full = os.path.realpath(os.path.join(self.server.root, *words))
        if not full.startswith(self.server.root + os.sep):
            return None
        return full if os.path.isfile(full) else None

    def serve(self, head_only):
        path = urllib.parse.urlsplit(self.path).path
        if path in INDEX_PATHS:
            if self.server.mod is None:
                self.send_error(503, "honeyd module not available")
                return
            body = status_page(self.server.mod).encode("utf-8")
            self.send_body(body, "text/html; charset=utf-8", head_only, True)
            return
        full = self.static_path(path)
        if full is None:
            self.send_error(404, "File not found")
            return
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        with open(full, "rb") as f:
            body = f.read()
        self.send_body(body, ctype, head_only)

    def do_GET(self):
        self.serve(False)

    def do_HEAD(self):
        self.serve(True)

    def log_message(self, format, *args):
        message = "%s - - [%s] %s" % (self.client_address[0],
                                      self.log_date_time_string(),
                                      format % args)
        try:
            honeyd.raw_log(message)
        except Exception:
            pass

    def version_string(self):
        return self.server_version


def make_server(root):
    return HoneydServer(root)


def handle_request(server, request, client_address):
    return server.handle_request(request, client_address)
