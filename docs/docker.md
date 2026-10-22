# Running phantom-mirage in Docker

The repository builds a multi-arch image (`linux/amd64`, `linux/arm64`, e.g. Raspberry Pi 4/5) from the top-level `Dockerfile`:

- **Build stage** (`debian:13-slim`): autotools build. A plain `make install DESTDIR=/out` (no Python needed since #36), minus headers and man pages: the binaries (`phantom-mirage`, `phantom-mirage-ctl`, `phantom-mirage-stats`, `phantom-mirage-sniff`), the `libphantom-mirage.so` preload shim, the data files (`nmap-os-db`, `xprobe2.conf`, `nmap.assoc`, `pf.os`, `nmap-mac-prefixes`, ...), `scripts/` and the `webserver/` files. The image builds phantom-mirage without embedded Python, so the status page and in-process Python services are off there; build `--with-python` to get them.
- **Runtime stage** (`debian:13-slim`): just the shared libraries phantom-mirage needs (libpcap, libevent, libdumbnet, zlib, libedit).

## Build

```sh
docker build -t phantom-mirage:local .
# both architectures (needs buildx + QEMU/binfmt for the foreign one)
docker buildx build --platform linux/amd64,linux/arm64 -t phantom-mirage:local .
```

## Entry point

`docker/entrypoint.sh` first runs `phantom-mirage --verify-config` with the same arguments, then `exec`s `phantom-mirage -d` (foreground) so Docker sees the real process and its exit status. If the config doesn't verify, the container stops with that error.

| Variable | Default | Meaning |
|---|---|---|
| `PHANTOM_MIRAGE_CONFIG` | `/etc/phantom-mirage/phantom-mirage.conf` | config file (mount your own read-only) |
| `PHANTOM_MIRAGE_INTERFACES` | `eth0` | space-separated capture interfaces (one per macvlan network) |
| `PHANTOM_MIRAGE_NET` | *(empty)* | optional address/range phantom-mirage answers for |
| `PHANTOM_MIRAGE_JSON_LOG` | *(empty)* | `stdout` to write JSON Lines events to the container's stdout for a log shipper ([json-log.md](json-log.md)); any other value is a file path writable by `nobody` |
| `PHANTOM_MIRAGE_SENSOR_ID` | *(container hostname)* | `sensor_id` in every JSON event (`--sensor-id`). The default is the container ID unless you set `hostname:`, so set this for stable names |
| `PHANTOM_MIRAGE_HEARTBEAT` | *(off)* | seconds between JSON `heartbeat` events (`--heartbeat`) |
| `PHANTOM_MIRAGE_UI_GROUP` | *(empty)* | group allowed on the control socket (see #14) |

Extra container arguments are appended to the phantom-mirage command line. `--version`/`--help` run phantom-mirage directly. Adding `--verify-config` only checks the config and exits.

## Required capabilities (no `--privileged`)

Run with `--cap-drop ALL` and add only:

| Capability | Why |
|---|---|
| `NET_RAW` | pcap capture and raw packet replies |
| `NET_ADMIN` | interface flags / promiscuous mode on the capture interface |
| `SETUID`, `SETGID` | phantom-mirage starts as root in the container, creates `/run/phantom-mirage` (root 0700, control socket 0600, pid file `phantom-mirage.pid` 0644) and then drops to `nobody` |

Also recommended: `--read-only`, `--security-opt no-new-privileges`, and tmpfs mounts for `/run`, `/tmp` and `/root/.config`. Mount the config read-only.

The pid file is `/run/phantom-mirage/phantom-mirage.pid`. After dropping to `nobody` the daemon can't remove it from the root-only directory, so on exit it empties it instead. An empty or stale pid file (a dead pid, which is normal with a persistent `/run` and pid 1 in a container) is replaced at the next start; only a live phantom-mirage with that pid makes a second instance refuse to start. With a tmpfs `/run` it disappears with the container anyway.

```sh
docker run --rm --network decoy-vlan10 \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --cap-add SETUID --cap-add SETGID \
  --read-only --tmpfs /run --tmpfs /tmp --tmpfs /root/.config \
  --security-opt no-new-privileges \
  -v "$PWD/site.conf:/etc/phantom-mirage/phantom-mirage.conf:ro" phantom-mirage:local
```

## Sandboxing in the container (`--sandbox-daemon`, `--sandbox-scripts`)

**The default `docker run` keeps Docker's `docker-default` AppArmor profile
and its default seccomp profile on.** With those, `--sandbox-daemon`
(seccomp allowlist + Landlock) works fully, and `--sandbox-scripts` runs
scripts **without namespaces**: the launcher's probe can't create a user
namespace, the daemon logs

    sandbox: unprivileged user namespaces unavailable (...); scripts run WITHOUT namespaces, ...

and keeps serving; scripts still run under Landlock and the launcher's
seccomp filters (no outbound connects; no TCP bind on Landlock ABI 4+),
but share the container's root filesystem, PID space and network. CI
checks this default run (`ci/docker_sandbox.sh`, `HD_NS=fallback`).

### Opt-in: per-script namespaces (recommended setup)

Per-script user/pid/mount/net/uts namespaces with a read-only minimal root
are **opt-in**. The recommended way keeps AppArmor enforcing with a
custom profile that differs from `docker-default` only in the mounts the
launcher needs:

```sh
sudo apparmor_parser -r -W docker/apparmor-phantom-mirage   # on the host, once per boot
docker run --rm --network decoy-vlan10 \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --cap-add SETUID --cap-add SETGID \
  --read-only --tmpfs /run --tmpfs /tmp --tmpfs /root/.config \
  --security-opt no-new-privileges \
  --security-opt apparmor=phantom-mirage-docker \
  --security-opt seccomp=docker/seccomp-sandbox-scripts.json \
  -v "$PWD/site.conf:/etc/phantom-mirage/phantom-mirage.conf:ro" \
  phantom-mirage:local --sandbox-daemon --sandbox-scripts
```

| Option | Why |
|---|---|
| `--security-opt apparmor=phantom-mirage-docker` | `docker/apparmor-phantom-mirage`: `docker-default` (moby/profiles), with `deny mount` replaced by only the launcher's mounts, all with targets under `/tmp` where the script root is built (see below); `umount` narrowed to the old-root detach; one `pivot_root`; `userns` (needs AppArmor 4 / ABI 4.0, e.g. Ubuntu 24.04, Debian 13). Every other mount stays denied. No host sysctl change is needed. |
| `--security-opt seccomp=docker/seccomp-sandbox-scripts.json` | the moby default seccomp profile plus `unshare`, `mount`, `umount2`, `pivot_root`, `sethostname`, which the default only allows with `CAP_SYS_ADMIN`. No capability is added; the kernel only grants them inside the script's new user namespace. |

The profile allows exactly:

| Rule | Launcher step |
|---|---|
| `mount options=(rw, rprivate) -> /` | private propagation in the new mount namespace |
| `mount fstype=tmpfs options=(rw, nosuid, nodev) tmpfs -> /tmp/` | the namespace probe and the new root (a tmpfs) |
| `mount options=(rw, rbind) -> /tmp/**` | binding `/usr/bin`, `/usr/lib*`, the data dir, script dirs, the working dir and `--sandbox-allow-write` dirs into the new root |
| `mount options in (ro, remount, bind, nosuid, nodev, noexec) -> /tmp/**` | making those binds read-only (`--sandbox-allow-write` ones stay writable) |
| `mount options=(rw, bind) /dev/{null,zero,random,urandom} -> /tmp/dev/...` | the four device nodes |
| `mount fstype=tmpfs ... tmpfs -> /tmp/tmp/` | the script's private `/tmp` |
| `mount fstype=proc options=(rw, nosuid, nodev, noexec) proc -> /tmp/proc/` | its own `/proc` |
| `mount options=(ro, remount, nosuid, nodev) -> /tmp/` | the new root read-only |
| `pivot_root oldroot=/tmp/ /tmp/`, `umount /` | switch root, detach the old one |

If a host can't load the profile and you use only the seccomp profile, the
probe's mount is refused by `docker-default` and the daemon falls back as
above (logged); it never runs a script half-isolated: if namespaces come
up but the read-only root can't be built, that script is not run.

### Last resort: `apparmor=unconfined` (not recommended)

`--security-opt apparmor=unconfined` (plus, on Ubuntu 23.10+, host
`kernel.apparmor_restrict_unprivileged_userns=0`) also makes namespaces
work, but turns off **all** AppArmor confinement of the container, not
just the mount rules, and the sysctl weakens the whole host. It is an
opt-in trade-off for hosts without AppArmor 4 where per-script
namespaces matter more than container confinement; prefer the custom
profile, or the default run with its logged fallback.

### CI

`ci/docker_sandbox.sh` (the `docker` job for amd64, `docker-arm64` on a
native arm64 runner; QEMU can't run seccomp filters) builds
`ci/Dockerfile.sandbox-test` on top of the built image (adds only python3,
iproute2, procps and the ci/ scripts; local, never pushed) and, with the
image's own binaries, runs:

1. `ci/sandbox_daemon.sh` under default AppArmor/seccomp;
2. `ci/script_ns.sh` with `HD_NS=require` under `phantom-mirage-docker` +
   the seccomp profile (namespaces, read-only root, no network);
3. `ci/script_ns.sh` with `HD_NS=fallback` in a plain default run
   (`docker-default`, default seccomp): the fallback must be logged and
   the scripts must still run.

The test harness adds `CHOWN` and `KILL` (it chowns the graphs dir and
signals the daemon after it dropped to `nobody`) and an exec `/tmp` for
its test subsystem; production doesn't need those. The image has no
embedded Python, so the Python service, status page and the
off-list-syscall probe are covered by the source-build jobs only.

## Networking

Use **macvlan** (or ipvlan L2) on the decoy VLAN, not the default bridge. phantom-mirage has to see raw frames and answer ARP for every decoy address. `docker/docker-compose.yml` is an example with placeholder values: parent `eth0.10` (VLAN 10 on a trunk port), subnet `192.0.2.0/24`. For several VLANs, attach one macvlan network per VLAN and list every interface in `PHANTOM_MIRAGE_INTERFACES`.

The Docker host can't reach its own macvlan containers through the same parent interface. Test from another machine on the VLAN.

## Control socket

`phantom-mirage-ctl` works inside the container as root:

```sh
docker exec -it <container> phantom-mirage-ctl
```

## Published images (GHCR, private)

`.github/workflows/publish.yml` publishes
`ghcr.io/danieldejager/phantom-mirage` as a **private** package.

* **When it pushes:** on pushes to `master` and on `v*` tags only. On pull
  requests it only builds, for both architectures, and never logs in or
  pushes. Nothing is pushed from a developer machine.
* **Auth:** only the workflow's own `GITHUB_TOKEN`, with
  `packages: write`; no personal access token, and no `id-token`
  permission (it is only needed for keyless signing, which isn't used).
* **Tags:**
  * `sha-<short>`: always.
  * `edge`: on `master`.
  * `X.Y.Z`, `X.Y` and `X` (no `0`): on `vX.Y.Z` tags.
* **Labels:** `org.opencontainers.image.source` points to the repository,
  so the package links to the private repo and its permissions.
* **SBOM and provenance:** buildx `sbom: true` and `provenance: mode=max`.
  They are stored as attestation manifests in the image index, in the same
  private registry, and are not sent to Sigstore or Rekor. CI checks they
  are there (`docker buildx imagetools inspect`).
* **Visibility check:** right after every push (the first one too, which
  creates the package) the job reads the package's visibility through the
  API. It fails loudly if the visibility is not `private` or can't be
  read.

### Signing (cosign, private key)

Images are signed by digest (`--recursive`: the index and every platform
manifest) with a cosign key pair, with `--tlog-upload=false`.
* **What is recorded:** nothing goes to the public Rekor transparency log.
  The signature lives next to the image in GHCR.
* **CI checks:**
  * It verifies the signature with the public half of the key
    (`--insecure-ignore-tlog=true`, since there is no log entry by
    design).
  * It checks that the signature carries no transparency-log bundle.
* **No key, no image:** if the key secrets are missing, the job fails
  before anything is pushed (`No signing key`).

Repository secrets to create (Settings → Secrets and variables →
Actions):

| Secret | Contents |
|---|---|
| `COSIGN_PRIVATE_KEY` | the encrypted private key (the whole `cosign.key` PEM) |
| `COSIGN_PASSWORD` | its password |

Create the key pair on your own machine, never in CI or on a shared
host:

```sh
cosign generate-key-pair        # asks for the password; writes cosign.key and cosign.pub
gh secret set COSIGN_PRIVATE_KEY -R danieldejager/phantom-mirage < cosign.key
gh secret set COSIGN_PASSWORD   -R danieldejager/phantom-mirage   # paste the password
```

Keep `cosign.key` offline (or delete it once the secret is set). Verify an
image with the public key:

```sh
cosign verify --key cosign.pub --insecure-ignore-tlog=true ghcr.io/danieldejager/phantom-mirage:edge
docker buildx imagetools inspect ghcr.io/danieldejager/phantom-mirage:edge --format '{{ json .Provenance }}'
```

### Option: keyless signing

`cosign sign` without `--key` uses the workflow's OIDC identity
and Fulcio, which needs `id-token: write` added to the job. It needs no key secret, but **it records
the signing certificate in Sigstore's public Rekor log**. That certificate
contains the repository name, workflow path and ref. Because this repo and
its packages are private, keyless is not the default. To switch, drop
`--key`/`--tlog-upload=false` from the sign step and verify with
`--certificate-identity-regexp` and `--certificate-oidc-issuer
https://token.actions.githubusercontent.com`.

GitHub artifact attestations (`actions/attest-build-provenance`) would use
GitHub's own Sigstore instance for private repositories, not the public
one. They are not used here: on a personal account they aren't available
for private repositories.

## Not done yet

- Python extensions and the web UI (#36).
