"""Minimal stand-in for the Python 2 `dnet` (libdnet) bindings the
regression tests used, built on the standard library (#36)."""
import socket

ip_aton = socket.inet_aton
ip_ntoa = socket.inet_ntoa

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
