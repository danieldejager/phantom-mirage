import pytest
from rfc1918 import is_private_target, assert_allowed_targets

ACCEPT = ["10.0.0.21", "10.255.255.255", "172.16.0.1", "172.31.255.254",
          "192.168.1.241", "127.0.0.1", "127.8.9.10", "fd00::1", "fc00::5", "::1"]
REJECT = {
    "link-local v4": "169.254.1.1", "this-network": "0.0.0.0", "zero/8": "0.1.2.3",
    "doc TEST-NET-1": "192.0.2.1", "doc TEST-NET-2": "198.51.100.1",
    "doc TEST-NET-3": "203.0.113.1", "benchmark": "198.18.0.1",
    "cgnat": "100.64.0.1", "ietf": "192.0.0.1", "multicast v4": "224.0.0.1",
    "broadcast": "255.255.255.255", "reserved": "240.0.0.1",
    "outside 172.16/12": "172.32.0.1", "public v4": "8.8.8.8",
    "unspecified v6": "::", "link-local v6": "fe80::1", "multicast v6": "ff02::1",
    "doc v6": "2001:db8::1", "public v6": "2606:4700::1",
    "v4-mapped": "::ffff:10.0.0.1", "garbage": "not-an-ip",
}

@pytest.mark.parametrize("ip", ACCEPT)
def test_accepts(ip):
    assert is_private_target(ip)

@pytest.mark.parametrize("ip", list(REJECT.values()), ids=list(REJECT))
def test_rejects(ip):
    assert not is_private_target(ip)
    with pytest.raises(SystemExit):
        assert_allowed_targets([ip], i_own_flag=True)

def test_flag_required_even_for_private():
    with pytest.raises(SystemExit):
        assert_allowed_targets(["10.0.0.21"], i_own_flag=False)

@pytest.mark.parametrize("ip", ["::ffff:8.8.8.8", "::ffff:10.0.0.1", "::ffff:127.0.0.1"])
def test_ipv4_mapped_refused(ip):
    assert not is_private_target(ip)

@pytest.mark.parametrize("name", ["localhost", "pm-t-ubuntu2404", "lab.example"])
def test_hostnames_refused_without_dns(monkeypatch, name):
    import socket
    def boom(*a, **k):
        raise AssertionError("DNS must never be queried")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    assert not is_private_target(name)
    with pytest.raises(SystemExit):
        assert_allowed_targets([name], i_own_flag=True)

def test_probe_main_refuses_hostname_before_any_lookup(monkeypatch):
    import socket, probe
    def boom(*a, **k):
        raise AssertionError("DNS must never be queried")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(SystemExit):
        probe.main(["--i-own-these-hosts", "--dry-run", "--open-tcp", "22",
                    "--closed-tcp", "1", "--closed-udp", "40000", "lab.example"])
