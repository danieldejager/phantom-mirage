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
| `SETUID`, `SETGID` | phantom-mirage starts as root in the container, creates `/run/phantom-mirage` (root 0700, control socket 0600) and then drops to `nobody` |

Also recommended: `--read-only`, `--security-opt no-new-privileges`, and tmpfs mounts for `/run`, `/tmp` and `/root/.config`. Mount the config read-only.

```sh
docker run --rm --network decoy-vlan10 \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --cap-add SETUID --cap-add SETGID \
  --read-only --tmpfs /run --tmpfs /tmp --tmpfs /root/.config \
  --security-opt no-new-privileges \
  -v "$PWD/site.conf:/etc/phantom-mirage/phantom-mirage.conf:ro" phantom-mirage:local
```

## Networking

Use **macvlan** (or ipvlan L2) on the decoy VLAN, not the default bridge. phantom-mirage has to see raw frames and answer ARP for every decoy address. `docker/docker-compose.yml` is an example with placeholder values: parent `eth0.10` (VLAN 10 on a trunk port), subnet `192.0.2.0/24`. For several VLANs, attach one macvlan network per VLAN and list every interface in `PHANTOM_MIRAGE_INTERFACES`.

The Docker host can't reach its own macvlan containers through the same parent interface. Test from another machine on the VLAN.

## Control socket

`phantom-mirage-ctl` works inside the container as root:

```sh
docker exec -it <container> phantom-mirage-ctl
```

## Not done yet

- Image signing and publishing to a private registry. CI builds both architectures but doesn't push anywhere.
- Python extensions and the web UI (#36).
