#!/usr/bin/env python3
#
# MSSQL (TDS) honeypot: answers the pre-login handshake with encryption
# off, then rejects any login with error 18456 "Login failed for user."
# Network I/O is bytes on stdin/stdout; a truncated or malformed packet
# ends the session.

import os
import shutil
import struct
import subprocess
import sys

stdin = sys.stdin.buffer
stdout = sys.stdout.buffer


class Truncated(Exception):
    pass


def read(n):
    data = stdin.read(n)
    if len(data) != n:
        raise Truncated()
    return data


class PreLoginToken:
    def __init__(self):
        self.tokenPosition = 0
        self.type = 0
        self.position = 0
        self.length = 0


class TDSPacket:
    def __init__(self):
        self.type = 12
        self.tokens = []
        self.payload = b""
        self.tokenOffset = 0

    def writePacket(self):
        ret = struct.pack("!BBHHBB", self.type, self.status, self.length,
                          self.chan, self.packet, self.window)
        for token in self.tokens:
            ret += struct.pack("!B", token.type)
            if token.type != 255:
                ret += struct.pack("!HH", token.position, token.length)
        return ret + self.payload

    def readPacket(self):
        (self.type, self.status, self.length, self.chan, self.packet,
         self.window) = struct.unpack("!BBHHBB", read(8))
        if self.length < 8:
            raise Truncated()
        bytesRead = 8
        if self.type == 18:
            while bytesRead < self.length:
                token = PreLoginToken()
                token.tokenPosition = bytesRead
                token.type = read(1)[0]
                bytesRead += 1
                if token.type == 255:
                    self.tokens.append(token)
                    break
                token.position, token.length = struct.unpack("!HH", read(4))
                bytesRead += 4
                if token.type == 0:
                    self.tokenOffset = token.position
                self.tokens.append(token)
        if bytesRead < self.length:
            self.payload = read(self.length - bytesRead)


class LoginError:
    """Generic login error response."""

    def __init__(self):
        self.errorMsg = "Login failed for user."
        self.serverName = os.getenv("PHANTOM_MIRAGE_IP_DST", os.getenv("HONEYD_IP_DST", ""))[:255]

    def writePacket(self):
        msg = self.errorMsg.encode("utf-16-le")
        server = self.serverName.encode("utf-16-le")
        length = 14 + len(server) + len(msg)
        tlength = 38 + len(server) + len(msg)
        ret = struct.pack("!BBHHBB", 4, 1, tlength, 51, 1, 0)
        ret += struct.pack("<BH", 0xaa, length)         # ERROR token
        ret += struct.pack("<IBB", 18456, 1, 14)        # number, state, class
        ret += struct.pack("<H", len(self.errorMsg)) + msg
        ret += struct.pack("<B", len(self.serverName)) + server
        ret += struct.pack("<B", 0)                     # process name
        ret += struct.pack("<H", 1)                     # line number
        ret += b"\x00\x00"
        ret += struct.pack("<BH", 0xfd, 2)              # DONE token, status
        ret += struct.pack("!HI", 0, 0)                 # op, rows
        ret += struct.pack("!I", 0)
        return ret


def alert():
    """Optional hook kept from the Nova integration; run only if present."""
    tool = shutil.which("createNovaScriptAlert.py")
    if tool:
        subprocess.call([tool, os.getenv("PHANTOM_MIRAGE_IP_SRC", os.getenv("HONEYD_IP_SRC", "")),
                         os.getenv("PHANTOM_MIRAGE_INTERFACE", os.getenv("HONEYD_INTERFACE", "")), "mssql",
                         "Mssql database login attempt"])


def main():
    while True:
        tds = TDSPacket()
        tds.readPacket()
        if tds.type == 18:              # pre-login handshake
            tds.type = 4
            payload = bytearray(tds.payload)
            for token in tds.tokens:
                off = token.position - tds.tokenOffset
                if token.type == 1 and 0 <= off < len(payload):
                    payload[off] = 2                    # encryption off
                if token.type == 3 and 0 <= off <= len(payload) - 4:
                    payload[off:off + 4] = b"\x00" * 4  # zero thread ID
            tds.payload = bytes(payload)
            stdout.write(tds.writePacket())
            stdout.flush()
        elif tds.type in (16, 23):      # login attempts
            stdout.write(LoginError().writePacket())
            stdout.flush()
            alert()
            return


if __name__ == "__main__":
    try:
        main()
    except (Truncated, BrokenPipeError):
        pass
