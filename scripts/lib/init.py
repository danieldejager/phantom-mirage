#!/usr/bin/env python3
"""Optional: pre-create the names database used by the NetBIOS/mDNS
service scripts (scripts/win32/nbns.py, scripts/linux/mdns/mdns.py).

Not run by `make install` any more (#36): those scripts create the
database on first use. Run it as the user honeyd's scripts run as if you
want the file to exist up front.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from names import InitializeDB

home = os.path.expanduser("~")
InitializeDB(home + "/.config/honeyd/names").close()

for path, mode in ((home + "/.config/honeyd/names", 0o666),
                   (home + "/.config/honeyd", 0o777)):
    try:
        os.chmod(path, mode)
    except OSError:
        pass
