#!/usr/bin/env python3
# ============================================================================
#  Name        : mysql.py
#  Copyright   : DataSoft Corporation 2011-2013
# 	Nova is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Nova is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Nova.  If not, see <http://www.gnu.org/licenses/>.
#  Description : Trivial mysql script for honeyd: greets every client with
#                error 1130 (host not allowed). Ignores its input.
# ============================================================================

import struct
import sys


class ErrorGreeting:
    def __init__(self):
        self.packetNumber = 0
        self.errorCode = 1130
        self.message = b"Host is not allowed to connect to this MySQL server"

    def packedString(self):
        body = b"\xff" + struct.pack("<H", self.errorCode) + self.message
        # 3-byte little-endian length, then the packet number
        return (struct.pack("<I", len(body))[:3] +
                struct.pack("B", self.packetNumber) + body)


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(ErrorGreeting().packedString())
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        pass
