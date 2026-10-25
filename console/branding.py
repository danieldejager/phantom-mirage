"""Product name, legal name and copyright line for the console (#141).

The values live in branding.conf next to this file (the single source of
truth, also sourced by phantom-mirage-setup). See the rule in that file:
no company suffix until the company registration is confirmed.
"""
import os
import re

PATH = os.environ.get("PM_BRANDING",
                      os.path.join(os.path.dirname(os.path.abspath(__file__)), "branding.conf"))
_LINE = re.compile(r'^(PM_[A-Z_]+)="([^"$`\\]*(?:\$\{PM_[A-Z_]+\}[^"$`\\]*)*)"\s*$')


def load(path=None):
    vals = {}
    with open(path or PATH, encoding="utf-8") as f:
        for line in f:
            m = _LINE.match(line.rstrip("\n"))
            if m:
                vals[m.group(1)] = re.sub(r'\$\{(PM_[A-Z_]+)\}',
                                          lambda v: vals.get(v.group(1), ""), m.group(2))
    return vals


_V = load()
PRODUCT = _V["PM_PRODUCT"]
LEGAL_NAME = _V["PM_LEGAL_NAME"]
COPYRIGHT = _V["PM_COPYRIGHT"]
