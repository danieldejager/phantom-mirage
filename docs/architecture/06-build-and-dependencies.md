# 06 – Build system and dependencies

## Build system (facts from the source)

- **GNU Autotools.** `autogen.sh` runs aclocal/libtoolize/autoheader/automake/autoconf over `configure.in` (old name; modern autoconf expects `configure.ac`) and `Makefile.am`. Package version: `AM_INIT_AUTOMAKE(honeyd, 1.6d)` (configure.in:8).
- **Targets** (`Makefile.am`): `bin_PROGRAMS = honeyd honeydctl honeydstats hsniff`; optional `smtp`, `proxy` subsystems; `libhoneyd.so` built by a hand-written libtool rule ("libtool is so broken" comment) from honeyd_overload.c, atomicio.c, fdpass.c; data files installed to `$(datadir)/honeyd` (nmap-os-db, xprobe2.conf, nmap.assoc, pf.os, nmap-mac-prefixes, config.sample …). Plugin headers (hooks.h, plugins.h, plugins_config.h, debug.h) are installed so third-party plugins can be built; `honeyd_LDFLAGS = -export-dynamic` exposes daemon symbols to dlopen'd plugins.
- **Generated parser:** `parse.y` → `parse.c` (yacc/bison) and `lex.l` → `lex.c` (flex). Pre-generated `parse.c`/`lex.c` are committed too.
- **Optional subdirectories:** `pypcap`, `dpkt` (Python modules, for Python support) and `regress` (tests).
- **Debian packaging:** `debian/` (control, rules, init script, logrotate) and `generateDebs`.

## Dependencies

| Library | How configure finds it | Used for | Version on test box (Debian 13) |
|---|---|---|---|
| libpcap | `--with-libpcap` or header search (configure.in:112–160); checks `pcap_get_selectable_fd` | packet capture (interface.c) | 1.10.5 |
| libdnet (Debian: libdumbnet) | `dnet-config` (configure.in:165–215); falls back to `compat/libdnet` shim for "dumbnet" naming; runtime test for working `addr_cmp` | raw IP/Ethernet send, address types, `intf`, `rand`, `ip_checksum` | libdumbnet 1.18 |
| libevent | `--with-libevent`; requires `event_priority_init` (configure.in:218–262) | event loop, timers, evbuffers. Code uses the libevent 2 API (`event_base_new`, `evtimer_new`) | 2.1 |
| zlib | standard check | per-packet compression of stats reports (`stats_compress`, stats.c:179; also honeydstats.c) | system |
| libpcre | `pcre-config`, optional (configure.in:266+) | **No C file includes pcre** in master (grep), so effectively unused | not available on Debian 13 (PCRE1 removed) |
| libedit / readline | optional | honeydctl line editing | libedit |
| Python | `--with-python`; looks for `python`, `python2.4` (configure.in:430–495) | embedded services and web UI (pyextend.c uses `Py_InitModule`, a Python 2 only API) | not built (no `python` binary) |
| rrdtool | optional path | graphs via rrdtool.c | not built |

## Observed build on modern Linux (this run, 2026-10-17)

Box: Debian GNU/Linux 13 (trixie), GCC 14.2, autoconf 2.72 era automake/libtool, packages `build-essential autoconf automake libtool bison flex libpcap-dev libevent-dev libdumbnet-dev zlib1g-dev libedit-dev`.

| Step | Result | Cause | Workaround used |
|---|---|---|---|
| `apt install libpcre3-dev` | **fails** – no installation candidate | PCRE1 dropped from Debian 13 (debian/control still lists it) | omit; configure treats pcre as optional |
| `./autogen.sh` | OK with many warnings | `configure.in` name, obsolete macros (`AC_CANONICAL_SYSTEM`, `AM_PROG_LIBTOOL`, `AC_ERROR`, 3-arg `AM_INIT_AUTOMAKE`), `subdir-objects` warnings for subsystems/*.c | none needed |
| `./configure` | **fails**: "you need to install a more recent version of libdnet" | The `addr_cmp` runtime test (configure.in:652) calls `memset` without `#include <string.h>`; GCC 14 makes implicit function declarations an error, so the test fails to compile and is misreported as an old libdnet | `CC="gcc -fpermissive"` |
| `make` | **link fails**: `multiple definition of libevent_base, personalities, xp_fprints, record_tags, address_tags, …` | Globals *defined* in headers (e.g. `struct event_base *libevent_base;` honeyd.h, `SPLAY_HEAD(perstree…) personalities;` personality.h:303). GCC ≥ 10 defaults to `-fno-common` | `CC="gcc -fpermissive -fcommon"` |
| `make -j8` | intermittent link error `cannot find fdpass.o` | the hand-written `libhoneyd.so` rule has no proper dependency on objects; parallel-make race | build with plain `make` |
| `make` (serial, with workarounds) | **succeeds**; honeyd, honeydctl, honeydstats, hsniff, libhoneyd.so built; 37 compiler warnings (unused variables/values, deprecated declarations, `stringop-truncation`) | | |
| `honeyd --verify-config -f config.sample` with absolute DB paths | fingerprint DBs load; config parsing stops at line 35: template "windows" has an ethernet address but no interface reaches 192.168.3.137 | expected: sample is site-specific | n/a |
| `honeyd` without installed data | "Could not find path PATH_HONEYDDATA: /usr/share/honeyd" | startup checks the compiled-in data dir | `make install` or create the dir |

The table above records the build as it was on `master` before the fix. [PR #44](https://github.com/danieldejager/honeyd/pull/44) (issue #18) fixes the three causes: it adds the missing includes to the configure checks, gives each header global a single definition in a `.c` file, and gives the shared library and `honeyd` separate object files. It also renames `configure.in` to `configure.ac`.

Recipe once PR #44 is merged (no workarounds, parallel build works, checked by CI on Debian 13 / GCC 14):

```sh
./autogen.sh
./configure
make -j
```

Recipe for `master` before PR #44:

```sh
./autogen.sh
CC="gcc -fpermissive -fcommon" ./configure
make            # not -j
```

The 37 compiler warnings are still present; cleaning them up is separate work. To run `honeyd` from a build tree, `/usr/share/honeyd` must exist (issue #43).

Python support was not tested: it needs Python 2 headers (`Py_InitModule`), which modern distributions no longer ship.
