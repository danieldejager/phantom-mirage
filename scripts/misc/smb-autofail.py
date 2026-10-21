#!/usr/bin/env python3
#
# SMB honeypot that negotiates NT LM 0.12, accepts any session setup and
# then refuses every tree connect (access denied). Network I/O is bytes on
# stdin/stdout; a short, truncated or malformed request ends the session.
#
# argv[2] is a config file with lines like "NATIVE_OS Windows 5.1".

import struct
import sys

native_os = b""
primary_domain = b""
time_zone = 0
lan_manager = b""

stdin = sys.stdin.buffer
stdout = sys.stdout.buffer


class Truncated(Exception):
    pass


def read(n):
    data = stdin.read(n)
    if len(data) != n:
        raise Truncated()
    return data


def send(smb):
    """Writes an SMB message with its NetBIOS session service header."""
    stdout.write(b"\x00" + struct.pack(">I", len(smb))[1:] + smb)
    stdout.flush()


def header(command, status, flags2, pid, mid):
    return (b"\xffSMB" + command + status +
            b"\x88" +                   # Flags 1
            flags2 +                    # Flags 2
            b"\x00\x00" +               # PID high
            b"\x00" * 8 +               # Signature
            b"\x00\x00" +               # Reserved
            b"\x00\x00" +               # Tree ID
            pid +
            b"\x00\x00" +               # User id
            mid)


def read_words_and_bytes():
    word_count = read(1)[0]
    read(word_count * 2)
    byte_count = struct.unpack("<H", read(2))[0]
    return read(byte_count)


def GetRequest():
    read(4)                             # NetBIOS session service header
    if read(4) != b"\xffSMB":
        return False
    smb_command = read(1)
    read(4)                             # NT status
    read(1)                             # Flags 1
    read(2)                             # Flags 2
    read(2)                             # PID high
    read(8)                             # Signature
    read(2)                             # Reserved
    read(2)                             # Tree ID
    pid = read(2)
    read(2)                             # User id
    mid = read(2)

    if smb_command == b"\x72":
        return HandleNegotiateProtocolRequest(pid, mid)
    if smb_command == b"\x73":
        return HandleSessionSetupRequest(pid, mid)
    if smb_command == b"\x75":
        return HandleTreeConnectRequest(pid, mid)
    if smb_command == b"\x71":
        return HandleDisconnectRequest(pid, mid)

    SendError(b"\x72", b"\x00\x00\x00\x00", pid, mid)
    return True


def HandleNegotiateProtocolRequest(pid, mid):
    read(1)                             # Word count
    byte_count = struct.unpack("<H", read(2))[0]
    dialects = read(byte_count).split(b"\x00")
    chosen_dialect = -1
    for i in range(0, len(dialects) - 1):
        # The first byte is the buffer format
        if dialects[i][1:] == b"NT LM 0.12":
            chosen_dialect = i
            break

    if chosen_dialect == -1:
        SendError(b"\x72", b"\x00\x00\x00\x00", pid, mid)
        return True

    response = header(b"\x72", b"\x00\x00\x00\x00", b"\xc8\x41", pid, mid)
    response += b"\x11"                 # word count 17
    response += struct.pack("<H", chosen_dialect)
    response += b"\x08"                 # most security off
    response += b"\x32\x00"
    response += b"\x01\x00"
    response += b"\x04\x41\x00\x00"
    response += b"\x00\x00\x01\x00"
    response += b"\x00\x00\x00\x00"
    response += b"\xf9\xf3\x01\x00"     # capabilities (no extra security)
    response += b"\xa9\xbb\x01\x95\x73\x56\xce\x01"   # TODO system time
    response += struct.pack("<H", time_zone % 65536)
    response += b"\x00"
    response += struct.pack("<H", len(primary_domain) + 1)
    response += primary_domain + b"\x00"
    send(response)
    return True


def HandleSessionSetupRequest(pid, mid):
    read_words_and_bytes()
    response = header(b"\x73", b"\x00\x00\x00\x00", b"\xc8\x41", pid, mid)
    response += b"\x03"                 # word count 3
    response += b"\xff"                 # no further commands
    response += b"\x00"                 # reserved
    response += b"\xc7\x00"             # AndXOffset
    response += b"\x00\x00"             # Action: not logged in as guest
    info = (native_os + b"\x00" + lan_manager + b"\x00" +
            primary_domain + b"\x00")
    response += struct.pack("<H", len(info)) + info
    send(response)
    return True


def HandleTreeConnectRequest(pid, mid):
    read_words_and_bytes()
    # STATUS_ACCESS_DENIED
    send(header(b"\x75", b"\x22\x00\x00\xc0", b"\xc8\x41", pid, mid) +
         b"\x00\x00\x00")
    return True


def HandleDisconnectRequest(pid, mid):
    read_words_and_bytes()
    send(header(b"\x71", b"\x00\x00\x00\x00", b"\xc8\x01", pid, mid) +
         b"\x00\x00\x00")
    return True


def SendError(command, status, pid, mid):
    send(header(command, status, b"\xc8\x41", pid, mid) + b"\x00\x00\x00")
    return True


def read_config(path):
    global native_os, primary_domain, time_zone, lan_manager
    with open(path, "rb") as f:
        for line in f:
            key, _, value = line.partition(b" ")
            value = value.rstrip()
            if key == b"NATIVE_OS":
                native_os = value
            elif key == b"PRIMARY_DOMAIN":
                primary_domain = value
            elif key == b"TIME_ZONE":
                time_zone = int(value)
            elif key == b"LAN_MANAGER":
                lan_manager = value


def main():
    if len(sys.argv) > 2:
        read_config(sys.argv[2])
    try:
        while GetRequest():
            pass
    except (Truncated, BrokenPipeError):
        pass


if __name__ == "__main__":
    main()
