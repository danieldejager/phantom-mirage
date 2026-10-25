"""Product name, legal name and copyright line for the console (#141).

The values live in branding.conf next to this file (the single source of
truth, also parsed (never sourced) by phantom-mirage-setup). See the rule in that file:
no company suffix until the company registration is confirmed.
"""
import os
import re

DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "branding.conf")
# PM_BRANDING is a test-only override, honoured only with PM_TESTING=1
PATH = (os.environ.get("PM_BRANDING") or DEFAULT) if os.environ.get("PM_TESTING") == "1" else DEFAULT
KEYS = ("PM_PRODUCT", "PM_LEGAL_NAME", "PM_COPYRIGHT")
# plain KEY="value" only: no $, backtick, backslash or quote inside the value,
# except the one documented ${PM_LEGAL_NAME} reference in PM_COPYRIGHT
_LINE = re.compile(r'^(PM_[A-Z_]+)="([^"$`\\]*)"$')
_CTRL = re.compile(r'[\x00-\x1f\x7f-\x9f]')


def load(path=None):
    """Parse branding.conf; raise ValueError on anything unexpected."""
    vals = {}
    with open(path or PATH, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            ref = False
            if "\0" not in line and line.startswith('PM_COPYRIGHT="'):
                ref = "${PM_LEGAL_NAME}" in line
                line = line.replace("${PM_LEGAL_NAME}", "\0")
            m = _LINE.match(line)
            if not m or m.group(1) not in KEYS or m.group(1) in vals:
                raise ValueError("branding.conf: rejected line: %r" % line[:80])
            v = m.group(2)
            if ref:
                v = v.replace("\0", vals.get("PM_LEGAL_NAME", ""))
            vals[m.group(1)] = _CTRL.sub("", v)
    if set(vals) != set(KEYS):
        raise ValueError("branding.conf: missing keys")
    return vals


_V = load()
PRODUCT = _V["PM_PRODUCT"]
LEGAL_NAME = _V["PM_LEGAL_NAME"]
COPYRIGHT = _V["PM_COPYRIGHT"]
