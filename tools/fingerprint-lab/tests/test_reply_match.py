"""Reply matching (probe 0.3.2): RST replies to no-ACK-flag probes.

Defect (issue #146): scapy's TCP.answers() rejects a RST+ACK with seq 0 when
our probe carries a non-zero ack field without the ACK flag, so T2, T3 and T7
replies were recorded as timeouts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402

from probe import build_send_plan, match_replies, reply_matches  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "capture" / "ubuntu2404-run-40266292707-t2-t3-t7.pcap"
TARGET = "10.0.0.21"
SRC = "10.0.0.10"


def _plan():
    return {p["name"]: p["packet"] for p in build_send_plan(
        target=TARGET, open_tcp=22, closed_tcp=1, closed_udp=40000, src_ip=SRC)}


def _rst_ack_seq0(probe):
    return IP(src=probe[IP].dst, dst=probe[IP].src) / TCP(
        sport=probe[TCP].dport, dport=probe[TCP].sport, flags="RA", seq=0,
        ack=(probe[TCP].seq + 1) & 0xFFFFFFFF, window=0)


@pytest.mark.parametrize("name", ["T2", "T3", "T7"])
def test_rst_ack_seq0_to_no_ack_probe_is_matched_and_recorded(name):
    probe = _plan()[name]
    assert not int(probe[TCP].flags) & 0x10 and probe[TCP].ack != 0
    reply = IP(bytes(_rst_ack_seq0(probe)))
    if not int(probe[TCP].flags) & 0x02:
        # scapy skips its seq/ack check only when the probe has SYN (T3 is
        # FSPU), so T2 and T7 are the ones it dropped.
        assert not reply.answers(probe)
    assert reply_matches(probe, reply)
    reply.time = 1.0
    assert match_replies([(probe, 0.5)], [reply]) == [reply]


def test_rst_from_wrong_port_or_host_is_not_matched():
    probe = _plan()["T7"]
    r = _rst_ack_seq0(probe)
    r[TCP].sport += 1
    assert not reply_matches(probe, IP(bytes(r)))
    r = _rst_ack_seq0(probe)
    r[IP].src = "10.0.0.22"
    assert not reply_matches(probe, IP(bytes(r)))


def test_non_rst_reply_still_uses_scapy_checks():
    probe = _plan()["SEQ1"]
    good = IP(src=TARGET, dst=SRC) / TCP(sport=probe[TCP].dport, dport=probe[TCP].sport,
                                         flags="SA", seq=1234, ack=probe[TCP].seq + 1)
    assert reply_matches(probe, IP(bytes(good)))
    bad = good.copy()
    bad[TCP].ack = probe[TCP].seq + 1000
    assert not reply_matches(probe, IP(bytes(bad)))


def test_icmp_and_udp_matching_unchanged():
    plan = _plan()
    u1 = plan["U1"]
    unreach = IP(src=TARGET, dst=SRC) / ICMP(type=3, code=3) / bytes(u1)
    assert reply_matches(u1, IP(bytes(unreach))) == bool(IP(bytes(unreach)).answers(u1))
    ie = plan["IE1"]
    echo = IP(src=TARGET, dst=SRC) / ICMP(type=0, id=ie[ICMP].id, seq=ie[ICMP].seq)
    assert reply_matches(ie, IP(bytes(echo)))
    assert UDP in u1


def test_pcap_replay_records_t7_reply():
    """Ubuntu 24.04, lab run 40266292707 (probe 0.3.1, 3 runs): our T2/T3/T7
    probes and the VM's replies. The VM answered every T7 with RST+ACK seq 0
    about 0.9 ms later; 0.3.1 recorded timeout. T2/T3 hit the open port and
    got no reply on Linux, which must stay a timeout."""
    pkts = [p for p in scapy.rdpcap(str(FIXTURE)) if IP in p and TCP in p]
    probes = [p for p in pkts if p[IP].src == SRC]
    replies = [p for p in pkts if p[IP].src == TARGET]
    assert len(probes) == 9 and len(replies) == 3
    for r in replies:
        r[IP].time = r.time
    sent = [(p[IP], float(p.time)) for p in probes]
    got = match_replies(sent, [r[IP] for r in replies])
    by_flags = {}
    for (p, _t), r in zip(sent, got):
        by_flags.setdefault(str(p[TCP].flags), []).append(r)
    t7 = by_flags["FPU"]
    assert len(t7) == 3 and all(r is not None for r in t7)
    for r in t7:
        assert r[TCP].flags == "RA" and r[TCP].seq == 0
    assert all(r is None for k, v in by_flags.items() if k != "FPU" for r in v)
    # scapy alone would have dropped every T7 reply
    t7_probes = [p for p, _ in sent if p[TCP].flags == "FPU"]
    assert not any(r.answers(p) for p, r in zip(t7_probes, t7))


# ---- send-time choice (review on #158) ------------------------------------

import probe as probe_mod  # noqa: E402


class _FakeSock:
    def __init__(self, log):
        self.log = log

    def send(self, p):
        self.log.append(("send", p))

    def close(self):
        pass


class _FakeSniffer:
    """Captures what the fake socket sent (at a chosen 'wire' time) plus
    scripted replies."""

    def __init__(self, log, wire_times, replies, drop_outgoing=()):
        self.log, self.wire_times, self.replies, self.drop = log, wire_times, replies, set(drop_outgoing)

    def start(self):
        pass

    def stop(self):
        out = []
        sends = [p for k, p in self.log if k == "send"]
        for i, p in enumerate(sends):
            if i in self.drop:
                continue
            c = IP(bytes(p))
            c.time = self.wire_times[i]
            out.append(c)
        out.extend(self.replies)
        return sorted(out, key=lambda c: c.time)


def _run_fake(pkts, wire_times, post_times, replies, drop=()):
    log = []
    clock = iter(post_times)
    return probe_mod._exchange(
        pkts, 0.1, 2.0,
        sniffer_factory=lambda lf: _FakeSniffer(log, wire_times, replies, drop),
        socket_factory=lambda: _FakeSock(log),
        clock=lambda: next(clock),
        sleep=lambda s: None,
    )


def _reply_at(probe, t):
    r = IP(bytes(_rst_ack_seq0(probe)))
    r.time = t
    return r


def test_send_time_is_outgoing_capture_timestamp():
    plan = _plan()
    pkts = [plan["T2"], plan["T7"]]
    wire = [100.000, 100.100]
    post = [100.0013, 100.1011]  # post-send clock trails the wire
    res = _run_fake(pkts, wire, post, [_reply_at(pkts[1], 100.1009)])
    assert [t for t, _ in res] == wire
    assert res[0][1] is None and res[1][1] is not None


def test_send_time_falls_back_to_post_send_when_not_captured():
    plan = _plan()
    pkts = [plan["T2"], plan["T7"]]
    res = _run_fake(pkts, [100.0, 100.1], [100.0013, 100.1011],
                    [_reply_at(pkts[1], 100.1020)], drop={1})
    assert [t for t, _ in res] == [100.0, 100.1011]
    assert res[1][1] is not None


def test_pairing_uses_probe_windows():
    plan = _plan()
    pkts = [plan["T5"], plan["T6"], plan["T7"]]
    # T5's reply arrives before T6 is sent; a reply to T5 2.5 s late is
    # outside T5's window and must not be claimed by anyone.
    r5 = _reply_at(pkts[0], 100.0009)
    late = _reply_at(pkts[0], 102.6)
    r7 = _reply_at(pkts[2], 100.2009)
    res = _run_fake(pkts, [100.0, 100.1, 100.2], [100.001, 100.101, 100.201], [r5, late, r7])
    assert res[0][1] is r5 or res[0][1].time == 100.0009
    assert res[1][1] is None
    assert res[2][1].time == 100.2009
    # a reply stamped before its probe's wire time is not paired with it
    res = _run_fake([pkts[2]], [100.2], [100.201], [_reply_at(pkts[2], 100.1999)])
    assert res[0][1] is None


# ---- exact-bytes outgoing match (review on #158) ---------------------------

def _cap(pkt, t):
    c = IP(bytes(pkt))
    c.time = t
    return c


def test_wire_send_time_exact_match():
    plan = _plan()
    pkts = [plan["T2"], plan["T7"]]
    caps = [_cap(pkts[1], 5.1), _cap(pkts[0], 5.0)]
    assert probe_mod.wire_send_times(pkts, [9.0, 9.1], caps) == [5.0, 5.1]


def test_wire_send_time_ignores_offloaded_l4_checksum_and_padding():
    probe = _plan()["T7"]
    raw = bytearray(bytes(probe))
    raw[20 + 16:20 + 18] = b"\x00\x00"  # unfilled TCP checksum (offload)
    c = IP(bytes(raw) + b"\x00" * 6)  # plus Ethernet padding
    c.time = 7.0
    assert probe_mod.wire_send_times([probe], [9.0], [c]) == [7.0]


@pytest.mark.parametrize("mutate", ["flags", "payload", "window"])
def test_wire_send_time_near_miss_uses_fallback(mutate):
    probe = _plan()["T7"]
    near = IP(bytes(probe))  # same id/addrs/ports/seq/ack (first 8+ bytes)
    if mutate == "flags":
        near[TCP].flags = "FPUA"
    elif mutate == "payload":
        near = near / b"x"
        near[IP].len = None
    else:
        near[TCP].window = (near[TCP].window + 1) & 0xFFFF
    near[TCP].chksum = None
    near[IP].chksum = None
    near = _cap(near, 7.0)
    nb, pb = bytes(near), bytes(IP(bytes(probe)))
    for lo, hi in ((4, 6), (9, 10), (12, 20), (20, 28)):  # id, proto, addrs, first 8 L4
        assert nb[lo:hi] == pb[lo:hi]
    assert probe_mod.wire_send_times([probe], [9.0], [near]) == [9.0]


def test_wire_send_time_duplicate_frames_first_copy_wins_once():
    plan = _plan()
    a, b = plan["T6"], plan["T7"]
    caps = [_cap(a, 1.0), _cap(a, 1.00002), _cap(b, 1.1), _cap(b, 1.10002)]
    assert probe_mod.wire_send_times([a, b], [9.0, 9.1], caps) == [1.0, 1.1]
    # the same probe sent twice consumes both copies in order
    assert probe_mod.wire_send_times([a, a, a], [9.0, 9.1, 9.2], caps) == [1.0, 1.00002, 9.2]
