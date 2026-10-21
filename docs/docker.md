# Running honeyd in Docker

The repository builds a multi-arch image (`linux/amd64`, `linux/arm64`, e.g. Raspberry Pi 4/5) from the top-level `Dockerfile`:

- **Build stage** (`debian:13-slim`): autotools build. A plain `make install DESTDIR=/out` (no Python needed since #36), minus headers and man pages: the binaries (`honeyd`, `honeydctl`, `honeydstats`, `hsniff`), the `libhoneyd.so` preload shim, the data files (`nmap-os-db`, `xprobe2.conf`, `nmap.assoc`, `pf.os`, `nmap-mac-prefixes`, ...), `scripts/` and the (currently unused) `webserver/` files. honeyd is built without embedded Python, so the web UI and in-process Python services stay off until the rest of #36.
- **Runtime stage** (`debian:13-slim`): just the shared libraries honeyd needs (libpcap, libevent, libdumbnet, zlib, libedit).

## Build

```sh
docker build -t honeyd:local .
# both architectures (needs buildx + QEMU/binfmt for the foreign one)
docker buildx build --platform linux/amd64,linux/arm64 -t honeyd:local .
```

## Entry point

`docker/entrypoint.sh` first runs `honeyd --verify-config` with the same arguments, then `exec`s `honeyd -d` (foreground) so Docker sees the real process and its exit status. If the config doesn't verify, the container stops with that error.

| Variable | Default | Meaning |
|---|---|---|
| `HONEYD_CONFIG` | `/etc/honeyd/honeyd.conf` | config file (mount your own read-only) |
| `HONEYD_INTERFACES` | `eth0` | space-separated capture interfaces (one per macvlan network) |
| `HONEYD_NET` | *(empty)* | optional address/range honeyd answers for |
| `HONEYD_JSON_LOG` | *(empty)* | `stdout` to write JSON Lines events to the container's stdout for a log shipper ([json-log.md](json-log.md)); any other value is a file path writable by `nobody` |
| `HONEYD_UI_GROUP` | *(empty)* | group allowed on the control socket (see #14) |

Extra container arguments are appended to the honeyd command line. `--version`/`--help` run honeyd directly. Adding `--verify-config` only checks the config and exits.

## Required capabilities (no `--privileged`)

Run with `--cap-drop ALL` and add only:

| Capability | Why |
|---|---|
| `NET_RAW` | pcap capture and raw packet replies |
| `NET_ADMIN` | interface flags / promiscuous mode on the capture interface |
| `SETUID`, `SETGID` | honeyd starts as root in the container, creates `/run/honeyd` (root 0700, control socket 0600) and then drops to `nobody` |

Also recommended: `--read-only`, `--security-opt no-new-privileges`, and tmpfs mounts for `/run`, `/tmp` and `/root/.config`. Mount the config read-only.

```sh
docker run --rm --network decoy-vlan10 \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --cap-add SETUID --cap-add SETGID \
  --read-only --tmpfs /run --tmpfs /tmp --tmpfs /root/.config \
  --security-opt no-new-privileges \
  -v "$PWD/site.conf:/etc/honeyd/honeyd.conf:ro" honeyd:local
```

## Networking

Use **macvlan** (or ipvlan L2) on the decoy VLAN, not the default bridge. honeyd has to see raw frames and answer ARP for every decoy address. `docker/docker-compose.yml` is an example with placeholder values: parent `eth0.10` (VLAN 10 on a trunk port), subnet `192.0.2.0/24`. For several VLANs, attach one macvlan network per VLAN and list every interface in `HONEYD_INTERFACES`.

The Docker host can't reach its own macvlan containers through the same parent interface. Test from another machine on the VLAN.

## Control socket

`honeydctl` works inside the container as root:

```sh
docker exec -it <container> honeydctl
```

## Not done yet

- Image signing and publishing to a private registry. CI builds both architectures but doesn't push anywhere.
- Python extensions and the web UI (#36).
