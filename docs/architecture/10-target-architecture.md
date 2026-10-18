# 10 – Target deployment architecture (proposal)

This is the proposed way to deploy Honeyd at DP World Oceania, as discussed on 19 Oct 2026. It's a **recommendation, not the current state**. Dashed boxes are planned features that depend on open issues. Issue numbers are shown in brackets.

![Target architecture](images/10-target-architecture.png)

## The design in short

1. **Hardware sensor.** Each site gets a Raspberry Pi 4 or 5 (2 GB+ RAM, PoE HAT) on a switch trunk port. One Pi can sit on several decoy VLANs at once using 802.1Q tags.
2. **Container on the Pi.** Honeyd runs in one Docker container (#20), attached to each decoy VLAN through macvlan so it sees raw traffic and answers ARP. The container gets only the network capabilities it needs, a read-only filesystem and a locked control socket (#14).
3. **One container per Honeyd, not per fake host.** A single Honeyd process simulates every decoy on every attached VLAN.
4. **High-interaction decoys as sidecars.** Honeyd proxies selected ports to purpose-built containers: Cowrie for SSH (#33) and Conpot for Modbus and S7 (#34). Honeyd fakes everything else.
5. **Visibility.** Honeyd writes JSON events (#24). A log shipper sends them, together with a heartbeat (#30), to Microsoft Sentinel over an outbound-only management VLAN.
6. **Response.** Any decoy hit is a high-fidelity alert (#26), and a missing heartbeat means a sensor is down. Alerts go to Oceania Cyber. ConnectWise tickets are raised manually because there's no integration.
7. **Supply chain.** CI builds a signed multi-arch image (x86_64 + arm64) from `master` with sanitizers (#18, #38). Sensors pull the image and their site config, so updating the fleet doesn't need reflashing.

## Constraints and assumptions

- Nothing has been built on ARM yet; that's untested.
- A Pi on an OT network needs DP World change control and sign-off from the OT owner first.
- Decoy VLANs must use IP ranges that are genuinely unused.
- The Pi's management interface reaches only Sentinel, the registry and the config repo, and never accepts inbound connections.
- No secrets are stored on the device, because a Pi in a comms room can be stolen or opened.
- Sensors refuse to run any image whose signature doesn't verify.
- Cowrie and Conpot sit on an internal Docker network that only Honeyd can reach, and have no direct presence on the decoy VLANs.
- The log shipper buffers events on disk while Sentinel is unreachable, and the Pi keeps time with NTP over the management VLAN so alert timestamps line up.

## Diagram source

```mermaid
flowchart TB
    %% ---------- Build and supply chain ----------
    subgraph BUILD["1. Build and supply chain (GitHub, private)"]
        direction LR
        repo["danieldejager/honeyd<br/>private repo, master"]
        ci["GitHub Actions CI<br/>build x86_64 + arm64<br/>ASan/UBSan, fuzz (#38)<br/>no compiler workarounds (#18)"]
        reg[("Private container registry<br/>signed multi-arch image")]
        cfgrepo[("Sensor config repo<br/>templates, scripts,<br/>per-site honeyd.conf")]
        repo --> ci --> reg
    end

    %% ---------- Site ----------
    subgraph SITE["2. Site (terminal, warehouse or office), one per segment group"]
        direction TB
        subgraph NET["Site switch"]
            direction TB
            trunk["Trunk port<br/>802.1Q tagged VLANs + PoE"]
            vcorp["Corporate decoy VLAN<br/>unused IP range"]
            vsrv["Server decoy VLAN<br/>unused IP range"]
            vot["OT decoy VLAN<br/>unused IP range"]
            vmgmt["Sensor management VLAN<br/>outbound only"]
        end

        subgraph PI["Raspberry Pi 4/5 sensor, 2 GB+ RAM, PoE HAT"]
            direction TB
            os["Raspberry Pi OS 64-bit, hardened<br/>read-only root, encrypted storage<br/>no console, SSH off, no secrets on device<br/>NTP over management VLAN"]
            subgraph DOCKER["Docker engine"]
                direction TB
                hc["Honeyd container (#20)<br/>caps: NET_RAW, NET_ADMIN, SETUID, SETGID<br/>read-only rootfs, tmpfs /var/run<br/>control socket 0600 (#14)"]
                subgraph HD["honeyd daemon"]
                    direction TB
                    tpl["Templates: Windows, Linux,<br/>printers, PLCs, HMIs<br/>refreshed fingerprints (#31)"]
                    eng["Packet engine<br/>ARP, routing sim, personality"]
                    scr["Service scripts<br/>sandboxed (#16)"]
                    jlog["JSON event log (#24)"]
                end
                cowrie["Cowrie container<br/>high-interaction SSH (#33)<br/>internal Docker network only"]
                conpot["Conpot container<br/>Modbus / S7 decoy (#34)<br/>internal Docker network only"]
                ship["Log shipper container<br/>Fluent Bit / AMA<br/>on-disk buffer if Sentinel unreachable"]
                agent["Health agent<br/>heartbeat, image version (#30)"]
            end
        end

        trunk --- vcorp & vsrv & vot & vmgmt
        vcorp -- "macvlan" --> eng
        vsrv -- "macvlan" --> eng
        vot -- "macvlan" --> eng
        eng --> tpl
        tpl --> scr
        tpl -. "proxy tcp/22" .-> cowrie
        tpl -. "proxy tcp/502, tcp/102" .-> conpot
        scr --> jlog
        eng --> jlog
        jlog --> ship
        cowrie --> ship
        conpot --> ship
        hc --- HD
    end

    %% ---------- Threat ----------
    atk1(["Attacker or worm<br/>on corporate network"])
    atk2(["Attacker on OT network<br/>scanning PLCs"])
    atk1 -- "scan / connect to decoy IPs" --> vcorp
    atk1 --> vsrv
    atk2 -- "Modbus / S7 / scan" --> vot

    %% ---------- Central ----------
    subgraph CENTRAL["3. Central monitoring and response (DP World Oceania Cyber)"]
        direction LR
        sentinel[("Microsoft Sentinel<br/>Log Analytics workspace")]
        rule["Analytics rule: any decoy hit = high-fidelity alert (#26)<br/>Heartbeat-missing rule: sensor down"]
        notify["Notification<br/>email / Teams to Oceania Cyber"]
        team["Analysts: Amos Winter, Ravi Paramanathan"]
        cw["ConnectWise ticket<br/>raised manually (no integration)"]
        fleet["Fleet update<br/>sensors pull image + config<br/>refuse unless signature verifies"]
        sentinel --> rule --> notify --> team --> cw
    end

    vmgmt -. "HTTPS outbound only" .-> sentinel
    ship -- "events over HTTPS<br/>via management VLAN" --> sentinel
    agent -- "heartbeat" --> sentinel
    reg -- "image pull" --> fleet
    cfgrepo -- "config pull" --> fleet
    fleet -- "outbound pull<br/>via management VLAN" --> PI

    classDef planned stroke-dasharray: 5 5,stroke:#b8860b,stroke-width:2px;
    classDef threat fill:#fde2e2,stroke:#c0392b,color:#000;
    classDef central fill:#e3f2fd,stroke:#1565c0,color:#000;
    classDef build fill:#e8f5e9,stroke:#2e7d32,color:#000;
    class cowrie,conpot,agent,jlog planned;
    class atk1,atk2 threat;
    class sentinel,rule,notify,team,cw,fleet central;
    class repo,ci,reg,cfgrepo build;
```
