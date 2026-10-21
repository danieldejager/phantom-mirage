# Privilege hardening and script sandboxing

honeyd needs root only to open its raw sockets and pcap handles. After
that it drops to `nobody` (or `-u`/`-g`). Every script and subsystem it
starts is forked, dropped to the template's uid/gid, and exec'd. This page
describes what happens at those points on Linux (#16).

## Always on (Linux)

These apply whenever `cmd_droppriv()` runs: in the daemon after start-up,
and in every script or subsystem child before `exec`.

| Measure | Effect |
|---|---|
| `setgroups(1, {gid})` → `setresgid(g,g,g)` → `setresuid(u,u,u)` | Supplementary groups, then real, effective **and saved** gid, then uid. The order matters: the gid can't be changed once the uid is gone. |
| `getresuid`/`getresgid` check, plus the existing `setuid(0)` test | honeyd exits unless all three IDs equal the target and root cannot be regained. |
| Bounding set emptied (`PR_CAPBSET_DROP`), ambient set cleared | Nothing exec'd later can pick up capabilities from file caps. Skipped with a notice if honeyd lacks `CAP_SETPCAP`, e.g. under `docker --cap-drop ALL`. |
| Inheritable, permitted and effective sets cleared (`capset`), then read back | honeyd exits if any capability remains. |
| `PR_SET_NO_NEW_PRIVS` | setuid/setgid binaries and file capabilities can't raise privileges for honeyd or anything it execs. A script that relies on a setuid helper, such as an old `ping`, will no longer get root through it. |

Expected `/proc/<pid>/status` for the daemon and any script:

```
Uid:  65534 65534 65534 65534
Gid:  65534 65534 65534 65534
Groups: 65534
CapInh/CapPrm/CapEff/CapAmb: 0000000000000000
CapBnd: 0000000000000000        (non-zero only without CAP_SETPCAP)
NoNewPrivs: 1
```

When honeyd itself has to keep root, it logs "Running with root
privileges". This happens when templates use different uids or gids. Only
the children are hardened in that case.

## Opt-in: `--sandbox-scripts`

```
honeyd ... --sandbox-scripts [--sandbox-allow-write=/var/lib/honeyd/scripts ...]
```

Each script or subsystem child is restricted just before `exec`, after
the privilege drop above:

* **Landlock** (kernel 5.13+, best ABI available) builds a filesystem
  allowlist.
  * Read and execute only: `/usr /bin /sbin /lib* /etc /opt`, honeyd's
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

Tested on Debian 13 (kernel 6.12, Landlock ABI 6) and in the GitHub
Actions container. In the Docker image the option starts and the
privilege checks are verified, but the image's example config has no
script ports, so CI does not run the script sandbox checks there.
Raspberry Pi OS uses Debian's userland. Whether Landlock is active
depends on the Raspberry Pi kernel's `lsm=` list
(`cat /sys/kernel/security/lsm`); seccomp is available there.

## Known gaps (why this is opt-in)

* **Deny-list, not allowlist.** Service scripts are arbitrary programs
  (sh, Perl, Python), so a strict seccomp allowlist would break many of
  them. The deny-list removes the kernel attack surface that matters most
  for an escaped script.
* **No network restriction.** Scripts get their connection on
  stdin/stdout, but they can still open sockets. Landlock ABI 4+ can
  restrict TCP bind/connect, but proxy-style scripts need outbound
  connections. This is not done yet.
* **No namespaces.** Scripts see the host's network, PID and IPC
  namespaces; `/proc` is hidden by Landlock, not unshared. A per-script
  user and mount namespace (or a separate container per service) would
  close this, but unprivileged user namespaces are blocked by Docker's
  default seccomp profile and disabled on some distributions.
* **Python services run in-process.** These are scripts started through
  the embedded interpreter (`cmd_python`), so they are not sandboxed
  beyond the daemon's own hardening.
* **Read-only /tmp.** Scripts that write scratch files must be given a
  directory with `--sandbox-allow-write`.
* **The daemon itself** gets the always-on hardening but no
  seccomp/Landlock. It loads plugins with `dlopen` and reopens logs on
  SIGHUP/SIGUSR1, which makes a tight policy fragile.

## CI

* The **ASan + UBSan** job (`Privilege hardening + script sandbox`)
  runs honeyd twice: with defaults, and with `--sandbox-scripts
  --sandbox-allow-write=…`.
  * `ci/check_sandbox.py` checks `/proc/<pid>/status` for the daemon and
    for a live script child: all four Uid/Gid fields 65534, all
    capability sets 0, `NoNewPrivs: 1`, and `Seccomp: 2` in sandbox
    mode.
  * It also checks what the probe script (`ci/sandbox_probe.sh`) could
    do: write, read, list, `/proc` and `unshare`.
  * SIGHUP and SIGUSR1 must leave the daemon running, and the subsystem
    must keep answering before and after the reload.
* The **Docker** job checks the same `/proc/1/status` fields in the
  image (the bounding set is exempt: no `CAP_SETPCAP`), and that
  `--sandbox-scripts` starts.
