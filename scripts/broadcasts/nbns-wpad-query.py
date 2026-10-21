#!/usr/bin/env python3
# ============================================================================
#  Name        : nbns-wpad-query.py
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
#  Description : Simple broadcast script that does a WPAD nbns query
# ============================================================================

import random
import struct
import sys


def query(transaction_id):
    pkt = struct.pack(">HHHHHH", transaction_id,
                      0x0110,           # flags: name query, broadcast
                      1, 0, 0, 0)       # 1 question
    # WPAD<00> (workstation/redirector), first-level encoded
    pkt += b" FHFAEBEECACACACACACACACACACACAAA" + b"\x00"
    pkt += struct.pack(">HH", 0x0020, 1)   # type NB, class IN
    return pkt


if __name__ == "__main__":
    sys.stdout.buffer.write(query(random.randint(0, 65535)))
    sys.stdout.buffer.flush()
