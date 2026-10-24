"""RFC1918 (and RFC4193 ULA) target checks. No public Internet probing."""

from __future__ import annotations

import ipaddress


def is_private_target(ip: str) -> bool:
    """Return True if *ip* is RFC1918 IPv4 or RFC4193 ULA IPv6 (or loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Explicitly allow loopback for offline/lab dry-runs on the same host.
    if addr.is_loopback:
        return True
    if addr.version == 4:
        return addr.is_private  # RFC1918 + link-local; we further restrict below
    # IPv6: unique-local only (fd00::/8); not global unicast.
    return addr.is_private and not addr.is_link_local


def assert_allowed_targets(targets: list[str], *, i_own_flag: bool) -> None:
    """Refuse anything outside RFC1918/ULA/loopback; require ownership flag."""
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
