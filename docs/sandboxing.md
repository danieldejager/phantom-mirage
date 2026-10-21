# Privilege hardening and script sandboxing

phantom-mirage needs root only to open its raw sockets and pcap handles. After
that it drops to `nobody` (or `-u`/`-g`). Every script and subsystem it
starts is forked, dropped to the template's uid/gid, and exec'd. This page
describes what happens at those points on Linux (#16).

## Always on (Linux)

These apply whenever `cmd_droppriv()` runs: in the daemon after start-up,
and in every script or subsystem child before `exec`.

| Measure | Effect |
|---|---|
| `setgroups(1, {gid})` → `setresgid(g,g,g)` → `setresuid(u,u,u)` | Supplementary groups, then real, effective **and saved** gid, then uid. The order matters: the gid can't be changed once the uid is gone. |
| `getresuid`/`getresgid` check, plus the existing `setuid(0)` test | phantom-mirage exits unless all three IDs equal the target and root cannot be regained. |
| Bounding set emptied (`PR_CAPBSET_DROP`), ambient set cleared | Nothing exec'd later can pick up capabilities from file caps. Skipped with a notice if phantom-mirage lacks `CAP_SETPCAP`, e.g. under `docker --cap-drop ALL`. |
| Inheritable, permitted and effective sets cleared (`capset`), then read back | phantom-mirage exits if any capability remains. |
| `PR_SET_NO_NEW_PRIVS` | setuid/setgid binaries and file capabilities can't raise privileges for phantom-mirage or anything it execs. A script that relies on a setuid helper, such as an old `ping`, will no longer get root through it. |

Expected `/proc/<pid>/status` for the daemon and any script:

```
Uid:  65534 65534 65534 65534
Gid:  65534 65534 65534 65534
Groups: 65534
CapInh/CapPrm/CapEff/CapAmb: 0000000000000000
CapBnd: 0000000000000000        (non-zero only without CAP_SETPCAP)
NoNewPrivs: 1
```

When phantom-mirage itself has to keep root, it logs "Running with root
privileges". This happens when templates use different uids or gids. Only
the children are hardened in that case.

## Opt-in: `--sandbox-scripts`

```
phantom-mirage ... --sandbox-scripts [--sandbox-allow-write=/var/lib/honeyd/scripts ...]
```

Each script or subsystem child is restricted just before `exec`, after
the privilege drop above:

* **Landlock** (kernel 5.13+, best ABI available) builds a filesystem
  allowlist.
  * Read and execute only: `/usr /bin /sbin /lib* /etc /opt`, phantom-mirage's
    data directory, its working directory, `/dev/{urandom,random,zero}`,
    and each absolute path on the command line (the program and the
    script file).
  * Read and write: `/dev/null` and each `--sandbox-allow-write` directory
    (absolute paths, at most 16).
  * Everything else is invisible, including `/home`, `/root`, `/proc`
    (no view of host processes), `/sys`, `/tmp` and `/var`.
* **seccomp** applies a syscall **deny-list**, which returns `EPERM`.
  * Denied: `ptrace`, `process_vm_*`, `mount`/`umount`/new mount API,
    `pivot_root`, `chroot`, `unshare`, `setns`, `kexec_*`, module
    loading, `bpf`, `perf_event_open`, keyrings, `userfaultfd`,
    `io_uring_*`, `open_by_handle_at`, `reboot`, `swapon`/`swapoff`,
    `iopl`/`ioperm`, `acct`, `quotactl`, `fanotify_init` and
    clock-setting calls.
  * Syscalls from a foreign ABI (i386 or x32 on x86_64) kill the process.
* If the kernel lacks Landlock or seccomp, the child logs "sandbox:
  Landlock unavailable … NOT filesystem-restricted" (or the seccomp
  equivalent) and **still runs**. This keeps services up on older
  kernels. Check the log if you depend on it.

### Per-script namespaces

With `--sandbox-scripts`, every **service script** (a `tcp`/`udp port`
command; subsystems are not affected) also runs in its own namespaces:

| Namespace | Effect |
|---|---|
| user | unprivileged; the script's uid/gid are mapped 1:1, nothing else |
| mount | `/` is private, `/tmp` is a fresh 64 MB tmpfs (writable, gone when the script exits) |
| PID | the script is pid 1 and sees only its own processes; killing it kills them all |
| IPC, UTS | no shared SysV IPC / POSIX queues; hostname `phantom-mirage-script` |
| network | only a downed `lo`, so no network at all. Scripts get their connection on stdin/stdout, so they normally don't need one |

`--sandbox-script-net=PATH` (repeatable, absolute) keeps the host
network for scripts whose command line contains `PATH` as a word, for
proxy-style scripts. They still get every other namespace.

**How it fits with `--sandbox-daemon`.** The daemon's seccomp allowlist
and Landlock both forbid `unshare` and `mount` (Landlock refuses mounts
to any restricted process), and children inherit both. So honeyd forks a
small launcher (`pm-script-ns`, `sandbox_ns.c`) right after its
privilege drop, after the Landlock paths are collected and before its
own filters go on. For each connection the daemon still forks a child as
before (so pid tracking, timeouts and reaping are unchanged). That child
(`pm-script-wait`) passes the connection, stderr pipe, argv and
environment to the launcher over a socketpair and waits. The launcher
forks, enters the namespaces, mounts `/tmp` and forks the script as
pid 1. The script then gets the script sandbox (Landlock with `/tmp`
writable, the deny-list) and, with `--sandbox-daemon`, also the daemon's
allowlist and its Landlock TCP rules (no bind, connect only to proxy
ports). So nothing is looser than when the daemon forked the script
itself. The exit status (including "killed by SIGSYS") is passed back
and reported as before. If the daemon's child goes away, the launcher
kills the script's PID namespace. If the daemon dies, the launcher dies
too. The daemon's allowlist gained nothing.

**Degrading.** At start the launcher tries everything once (all six
namespaces, the id maps, the tmpfs) and logs either `sandbox: scripts run
in their own user, mount, PID, IPC, UTS and network namespaces with a
private /tmp` or `sandbox: unprivileged user namespaces unavailable
(<errno>); scripts run WITHOUT namespaces or a private /tmp (Landlock and
seccomp still apply)`. Typical reasons are `user.max_user_namespaces=0`,
Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`, Debian's
older `kernel.unprivileged_userns_clone=0`, or Docker's default seccomp
or AppArmor profile.

**Caveats.**
* Scripts must not live in `/tmp`, because they would be hidden by the
  private one.
* The launcher itself is not under the daemon's filters, since it must
  call `unshare` and `mount`. It runs as the daemon's dropped user, has
  closed all the daemon's descriptors, and only takes requests from the
  daemon over an inherited socketpair.
* Python `internal` services run inside the daemon and get none of this.

Tested on Debian 13 (kernel 6.12, Landlock ABI 6) and in the GitHub
Actions container. In the Docker image the option starts and the
privilege checks are verified, but the image's example config has no
script ports, so CI does not run the script sandbox checks there.
Raspberry Pi OS uses Debian's userland. Whether Landlock is active
depends on the Raspberry Pi kernel's `lsm=` list
(`cat /sys/kernel/security/lsm`); seccomp is available there.

## Opt-in: `--sandbox-daemon`

```
phantom-mirage ... --sandbox-daemon [--sandbox-scripts ...]
```

Right after the daemon's privilege drop (or the "Running with root
privileges" notice), phantom-mirage installs a seccomp **allowlist** for itself
(`sandbox_daemon.c`, list in `sandbox_daemon_list.h`, about 200 calls on
x86_64). If the filter can't be installed, phantom-mirage exits.

* **What is allowed.** The list covers what the daemon and its children
  used under `strace -f` across the CI suites on an ASan build: smoke,
  subsystem echo (through the `libphantom-mirage.so` shim), a shell script port,
  an `internal` Python 3 service, the status page, phantom-mirage-ctl (including
  `!`), SIGHUP/SIGUSR1, `--sandbox-scripts` (Landlock and the stacked
  deny-list), and `regress/` including `nmap.py`. It also includes the
  usual sh, Perl and Python 3 runtime calls (sleep, poll/select, stat
  variants, rename/unlink, pipes, signals and so on).
* **Children inherit the filter.** seccomp filters can't be removed, so
  every script and subsystem phantom-mirage forks and execs runs under the same
  allowlist (and, with `--sandbox-scripts`, under the stricter deny-list
  and Landlock on top). That is why the list includes `execve`, `clone`,
  `vfork` and the ID-changing calls the child needs for its own
  privilege drop.
* **Never allowed.** Everything not on the list, in particular the
  deny-list calls from `--sandbox-scripts`: `ptrace`, `mount` and the
  new mount API, `unshare`, `setns`, `bpf`, `keyctl`, `perf_event_open`,
  `io_uring_*`, module loading, `kexec_*`, `reboot` and clock setting.
  Foreign ABIs (i386, x32 on x86_64) kill the process.
* **What a denial looks like.** The filter returns `SECCOMP_RET_TRAP`:
  * In the daemon (or a forked child that has not exec'd yet) a SIGSYS
    handler writes `phantom-mirage: sandbox-daemon: denied syscall <nr>` to
    stderr and syslog (`LOG_CRIT`), then the process dies with SIGSYS.
  * An exec'd script or subsystem dies with SIGSYS, and the daemon logs
    `child <pid> killed by SIGSYS (seccomp: denied syscall)`.
  * Look up `<nr>` with `ausyscall <nr>` or
    `grep -w <nr> /usr/include/asm/unistd_64.h`. If a legitimate
    service needs it, add it to `sandbox_daemon_list.h`.
* **Architectures.** x86_64 and arm64 (aarch64). Elsewhere the option
  makes phantom-mirage exit with "cannot install seccomp filter".
* On start-up the daemon logs `sandbox-daemon: seccomp allowlist active
  (<n> syscalls)`.
* **Under systemd** (`debian/phantom-mirage.service`): **on by default.**
  The unit sets `SANDBOX="--sandbox-daemon --sandbox-scripts"` (see
  "systemd defaults" below). The unit
  sets no `SystemCallFilter`, so this allowlist is the only syscall
  filter. It does not conflict with the unit's other settings:
  * `NoNewPrivileges=yes`: `--sandbox-daemon` sets no_new_privs anyway,
    which an unprivileged seccomp filter requires.
  * `ProtectSystem=strict` with only `/var/log/phantom-mirage` and `/run`
    writable: the allowlist is about syscalls, not paths. A write
    elsewhere fails with `EROFS` as usual, with no SIGSYS.
  * `RestrictAddressFamilies=` and `LockPersonality=` are seccomp
    filters systemd installs itself. They stack with ours, and the
    stricter answer wins.
  * The capability bounding set (`CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID
    CAP_SETGID`) covers what phantom-mirage does before the filter. The filter
    is installed after the drop.

  CI runs `ci/sandbox_daemon.sh` a second time under `setpriv
  --no-new-privs` with the unit's bounding set and state under `/run`.
  The read-only root (`ProtectSystem=strict`) was checked by hand in a
  user and mount namespace with `/` remounted read-only. The CI
  container refuses mounts.

### Landlock for the daemon

With `--sandbox-daemon`, phantom-mirage also puts *itself* under Landlock, just
before the seccomp filter (so after the privilege drop, the UI socket
bind and the status page start). Children inherit the ruleset.

* **Read-only** (read, list, execute): `/usr`, `/bin`, `/sbin`, `/lib*`,
  `/etc`, `/opt`, `/proc`, `/dev/{urandom,random,zero}`, the data dir
  (`/usr/share/phantom-mirage` or `PHANTOM_MIRAGE_DATADIR`) and the lib dir (`/usr/lib/phantom-mirage`), the
  directories of the config file and of `-p -x -a -0 -m`, the working
  directory, the webserver root, every `PYTHONPATH` entry, and every
  absolute path in a script port or subsystem command line.
* **Writable** (create, write, truncate, unlink; no device nodes, no
  cross-directory renames): the directories of `-l`, `-s`,
  `--json-log` and the DHCP dump file, the control socket dir
  (`/run/phantom-mirage`), `<webserver-root>/graphs`, `/tmp` only when
  rrdtool is enabled, and any `--sandbox-allow-write` dir. `/dev/null`
  is writable. Everything else gets `EACCES`.
* **Network** (Landlock ABI 4, Linux 6.7+): TCP `bind` is denied (the
  daemon's listening sockets already exist) and TCP `connect` is
  limited to the ports of statically configured `proxy` actions. If a
  proxy target is dynamic (`proxy $ipsrc:23`), connect is left
  unrestricted. Below ABI 4 there are no network rules.
* **Degrading.** phantom-mirage logs one of:
  * `sandbox-daemon: Landlock ABI <n> active: <r> read-only, <w>
    writable paths; network: <...>`, or
  * `sandbox-daemon: Landlock unavailable (<errno>); the daemon is NOT
    filesystem-restricted (seccomp only)` (kernel older than 5.13,
    Landlock not in `lsm=`, or a container profile that blocks it).
    phantom-mirage then keeps running with seccomp only.
* **Caveats.** Rules are fixed at start-up: a SIGHUP reload that adds a
  script outside the allowed directories, or moves a log, gets
  `EACCES`, so restart instead. Scripts that write scratch files need
  `--sandbox-allow-write`. The pid file is emptied, not removed, on exit.

## systemd defaults

`debian/phantom-mirage.service` runs the daemon with
`--sandbox-daemon --sandbox-scripts` (`Environment=SANDBOX=…`, which
`/etc/default/phantom-mirage` may override) and with
`RestrictNamespaces=user mnt pid ipc uts net` instead of `yes`, so the
script launcher can create per-script namespaces.

> **The relaxed `RestrictNamespaces=` depends on `--sandbox-daemon`.**
> Its seccomp allowlist is what keeps `unshare`/`setns`/`clone`
> namespace flags away from the daemon itself. If you remove
> `--sandbox-daemon` (or `--sandbox-scripts`) from `SANDBOX`, also set
> `RestrictNamespaces=yes` back in a drop-in (`systemctl edit
> phantom-mirage`).

As a fail-safe, phantom-mirage started by systemd (`INVOCATION_ID` set)
without either flag logs, at `LOG_CRIT` and on stderr (so in the journal):
`WARNING: running under systemd WITHOUT --sandbox-daemon …: the daemon
and/or its scripts are NOT sandboxed …`. It still starts.

On Ubuntu 24.04 and later, unprivileged user namespaces are restricted
for unconfined programs (`kernel.apparmor_restrict_unprivileged_userns=1`).
There scripts fall back to no namespaces (logged) unless that sysctl is 0
or an AppArmor profile grants `userns`. Debian 13 allows them.

CI (**systemd** jobs, Ubuntu 24.04 amd64 and arm64, directly on the
runner with systemd as PID 1, via `ci/systemd_unit.sh`) builds and
installs the .deb and runs the unit with its defaults:
* `ProtectSystem=strict` is in effect.
* The daemon runs as `phantom-mirage` with `NoNewPrivs: 1` and
  `Seccomp: 2`, and the journal reports the allowlist, Landlock and the
  script namespaces.
* A script port reports pid 1, its own hostname, a downed `lo` only and
  a private `/tmp`.
* The pid file matches `MainPID` (root 0644) and is rewritten on restart.
  The socket is root 0600 in a root 0700 dir, and `/run/phantom-mirage`
  is gone after stop.
* `systemctl reload` works, and nothing is denied.
* A drop-in with `SANDBOX=` gives the warning.

## Known gaps (why this is opt-in)

* **Deny-list, not allowlist.** Service scripts are arbitrary programs
  (sh, Perl, Python), so a strict seccomp allowlist would break many of
  them. The deny-list removes the kernel attack surface that matters most
  for an escaped script.
* **No network restriction.** Scripts get their connection on
  stdin/stdout, but they can still open sockets. Landlock ABI 4+ can
  restrict TCP bind/connect, but proxy-style scripts need outbound
  connections. This is not done yet.
* **Namespaces need unprivileged user namespaces.** Without them (see
  "Degrading" above) scripts share the host's network, PID and IPC
  namespaces and have no `/tmp`. Subsystems never get namespaces,
  because they need the daemon's sockets.
* **Python services run in-process.** These are scripts started through
  the embedded interpreter (`cmd_python`), so they are not sandboxed
  beyond the daemon's own hardening.
* **No /tmp without namespaces.** In the fallback, scripts that write
  scratch files must be given a directory with `--sandbox-allow-write`.
* **The daemon's allowlist is broad.** `--sandbox-daemon` gives it
  Landlock and a seccomp allowlist, but that list has to be broad (sockets, file I/O,
  `execve`) because the daemon reopens logs and configs on
  SIGHUP/SIGUSR1, loads plugins with `dlopen`, and its children
  inherit the filter. Scripts or plugins that use calls outside the
  list are killed (SIGSYS, logged), which is why this is opt-in. There
  is no argument filtering yet (for example `socket` families or
  `ioctl` requests).

## CI

* The **ASan + UBSan** job (`Privilege hardening + script sandbox`)
  runs phantom-mirage twice: with defaults, and with `--sandbox-scripts
  --sandbox-allow-write=…`.
  * `ci/check_sandbox.py` checks `/proc/<pid>/status` for the daemon and
    for a live script child: all four Uid/Gid fields 65534, all
    capability sets 0, `NoNewPrivs: 1`, and in sandbox mode exactly
    one seccomp filter more than the daemon (CI containers already run
    under Docker's default seccomp profile).
  * It also checks what the probe script (`ci/sandbox_probe.sh`) could
    do: write, read, list, `/proc` and `unshare`.
  * SIGHUP and SIGUSR1 must leave the daemon running, and the subsystem
    must keep answering before and after the reload.
* The same job then runs `ci/sandbox_daemon.sh` and the whole
  `regress/` suite (including `nmap.py`) with `--sandbox-daemon`:
  subsystem, shell script, Python 3 service, status page, phantom-mirage-ctl,
  SIGHUP/SIGUSR1, with and without `--sandbox-scripts`. Any
  `denied syscall` or `killed by SIGSYS` line fails the step, and a
  negative check (a `mount` call through phantom-mirage-ctl `!`) must be logged
  and must kill the daemon. Through phantom-mirage-ctl `!`, the daemon must also
  get `EACCES` writing outside its writable dirs, succeed in its log dir,
  and (ABI 4+) get `EACCES` on a TCP connect. `HD_LANDLOCK=require`
  makes that job and the arm64 job fail if Landlock isn't active.
* `ci/script_ns.sh` runs a probe script on two ports, with and without
  `--sandbox-daemon`. The isolated one must report pid 1, hostname
  `phantom-mirage-script`, only a downed `lo`, and a private `/tmp`; the
  `--sandbox-script-net` one must see the host's interfaces. The
  **script-ns** jobs (Ubuntu 24.04 amd64 and arm64, directly on the
  runner with `HD_NS=require`) run it, then again with
  `user.max_user_namespaces=0` to check the logged fallback. The ASan
  and arm64 container jobs run it too, and get the fallback.
* The **Docker** job checks the same `/proc/1/status` fields in the
  image (the bounding set is exempt: no `CAP_SETPCAP`), and that
  `--sandbox-scripts` starts.

## arm64

The allowlist is validated on a native arm64 runner (`ubuntu-24.04-arm`,
CI job "Debian 13 / arm64 --sandbox-daemon"). QEMU user-mode emulation
cannot be used, because it does not implement a guest's `PR_SET_SECCOMP`.
aarch64 has no legacy `open`, `poll`, `select`, `stat` or `fork`; the
`#ifdef __NR_x` guards drop those, and glibc uses `openat`, `ppoll`,
`pselect6`, `newfstatat` and `clone3` instead. `ci/syscall_audit.sh`
compares the compiled per-arch list against strace output from the
learn-mode and regress runs, and fails the job on any missing call.
