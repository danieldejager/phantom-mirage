"""Private-target checks. No public Internet probing.

Allowed targets, exactly:
  IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC1918), 127.0.0.0/8
  IPv6: fc00::/7 (RFC4193 ULA), ::1
Everything else (link-local, 0/8, documentation, benchmark, CGNAT, multicast,
unspecified, public, IPv4-mapped IPv6, ...) is refused. Hostnames are refused
outright (literal IPs only; no DNS lookup is ever made).
"""

from __future__ import annotations

import ipaddress

_ALLOWED_V4 = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
)
_ALLOWED_V6 = (ipaddress.ip_network("fc00::/7"), ipaddress.ip_network("::1/128"))


def is_private_target(ip: str) -> bool:
    """Return True only for RFC1918 / IPv4 loopback / ULA / ::1."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = _ALLOWED_V4 if addr.version == 4 else _ALLOWED_V6
    return any(addr in n for n in nets)


def assert_allowed_targets(targets: list[str], *, i_own_flag: bool) -> None:
    """Refuse anything outside the allow-list; require ownership flag."""
    if not i_own_flag:
        raise SystemExit(
            "Refusing to probe: pass --i-own-these-hosts to confirm you own "
            "every target listed on the command line (lab / host-only VMs only)."
        )
    bad = [t for t in targets if not is_private_target(t)]
    if bad:
        raise SystemExit(
            "Refusing non-RFC1918/ULA targets (public Internet probing is "
            f"forbidden): {', '.join(bad)}"
        )
