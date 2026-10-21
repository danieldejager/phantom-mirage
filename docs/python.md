# Embedded Python 3 services

honeyd can run Python 3 code inside the daemon to answer connections
("internal" services). This is the `pyextend.c` code. It is **off by
default**. A default `./configure` build does not link libpython. See #36.

## Building

```sh
# Debian/Ubuntu: apt install python3-dev
./configure --with-python               # uses python3 / python3-config from PATH
./configure --with-python=/opt/py/bin/python3.12   # a specific interpreter
```

You need Python 3.8 or newer and its `pythonX.Y-config`. configure reads the
flags from `python3-config --includes` and `--ldflags --embed` and checks
that a small embedded program links. If any of that fails, configure
stops. It does not quietly build without Python. `--without-python`, or
leaving the option out, builds without Python. In that case an `internal`
line in the config fails with "Python support is not available."

## Writing a service

```
add linux tcp port 7 internal "echo_banner"
```

`echo_banner` is a Python **module name**, not a path. honeyd imports it
once, while it reads the config (before it drops privileges), from
`sys.path`. That path covers `PYTHONPATH`, the current directory, and
`$(datadir)/honeyd`. A module that cannot be imported, or that lacks one of
the four hooks, is a config error ("Bad python module").

The module must define:

| hook | called | returns |
|---|---|---|
| `honeyd_init(env)` | per connection; `env` has `HONEYD_IP_SRC`, `HONEYD_IP_DST`, `HONEYD_SRC_PORT`, `HONEYD_DST_PORT`, `HONEYD_REMOTE_OS` | per-connection state object |
| `honeyd_readdata(state, data)` | attacker sent `data` (**bytes**) | ignored |
| `honeyd_writedata(state)` | socket writable and writes enabled | **bytes** to send (a `str` is sent as UTF-8), or `None` to close |
| `honeyd_end(state)` | connection gone | ignored |

Inside the hooks, `import honeyd` gives you:

- `honeyd.read_selector(honeyd.EVENT_ON|EVENT_OFF)` and `honeyd.write_selector(...)`. Read events are one-shot: call `read_selector(EVENT_ON)` again in `honeyd_readdata` to get the next chunk.
- `honeyd.log(str)` writes to the service log (`-s`); `honeyd.raw_log(str)` writes to syslog.
- `honeyd.version`, `uptime()`, `interfaces()`, `config()`, `config_ips()`, `stats_network()`, `status_connections("tcp"|"udp")`, `delete_template(name)`, `delete_connection(proto, src, sport, dst, dport)`.

[`scripts/python/echo_banner.py`](../scripts/python/echo_banner.py) is a
complete example. CI runs it under ASan/UBSan
([`ci/python_service.sh`](../ci/python_service.sh)).

Changes from the old Python 2 interface: data is `bytes` instead of `str`,
and `honeyd_writedata` may return `bytes`, `bytearray` or `str`.

## honeydctl `!`

With Python built in, `! <python statement>` on the control socket runs one
line inside honeyd and returns its stdout and stderr, for example
`! import honeyd; print(honeyd.uptime())`. Anyone who can reach the socket
can already run commands as honeyd, so treat this as root-equivalent too
(see docs/architecture/07).

## Status page (built-in webserver)

`webserver/server.py` is a small Python 3 module that renders one
read-only status page at `/` (interfaces, traffic statistics, active
TCP/UDP connections, bound addresses, static configuration) with the
standard library (`http.server`, `html`). The old Python 2 UI, its
`htmltmpl` template library, the `.tmpl` files and the delete-template /
kill-connection links are gone: the page cannot change honeyd state and
does not execute anything from the web root. Static files are served only
from `styles/`, `images/` and `graphs/` under `--webserver-root`; GET and
HEAD only.

It listens on `127.0.0.1` (`--webserver-address`) port 80
(`--webserver-port`) by default. Only change the address if the page
should be reachable from elsewhere. If `server` does not import, honeyd
logs `internal webserver disabled` and keeps running; `--disable-webserver`
turns it off. `ci/test_webserver.py` unit-tests the module and the
sanitizer job fetches the page from a running honeyd.

## Not ported yet

- `pydataprocessing.c` and `pydatahoneyd.c` (the honeydstats filter
  helpers) compile against Python 3 and pass `honeyd -T`, but nothing else
  uses them yet. Map filters must return `[[bytes key, bytes value], ...]`.
