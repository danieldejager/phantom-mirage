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
