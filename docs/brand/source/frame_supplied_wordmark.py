#!/usr/bin/env python3
"""Frame the supplied company artwork for the console header.

Reads docs/assets/phantom-technologies-original.svg and writes
docs/assets/phantom-technologies-wordmark.svg. The only change is the root
viewBox, width and height, so empty canvas is trimmed. Paths, colours and
the background rect are copied unchanged. Run from the repo root.
"""
import hashlib
import os

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
ORIG = os.path.join(ROOT, "docs", "assets", "phantom-technologies-original.svg")
OUT = os.path.join(ROOT, "docs", "assets", "phantom-technologies-wordmark.svg")
SHA256 = "d34024a284e3c1dfa5c62e64dc4ee9c889e806c2f75a1b660303dade4648664b"
# 16 user units of padding around the glyph hull, clamped to the original canvas.
OPEN_OLD = 'viewBox="0 0 1400 200" width="1400" height="200"'
OPEN_NEW = (
    'viewBox="14.130397727272726 44.54545454545455 456.87180397727275 121.62357954545455" '
    'width="456.87180397727275" height="121.62357954545455"'
)


def frame(data):
    """Return the framed SVG bytes. Raises ValueError if the source is unexpected."""
    if hashlib.sha256(data).hexdigest() != SHA256 or len(data) != 14082:
        raise ValueError("supplied artwork bytes do not match the recorded original")
    if data.count(OPEN_OLD.encode("utf-8")) != 1:
        raise ValueError("original root size attributes were not found once")
    out = data.replace(OPEN_OLD.encode("utf-8"), OPEN_NEW.encode("utf-8"), 1)
    # everything after the opening svg tag must be identical
    def body(blob):
        i = blob.index(b">", blob.index(b"<svg"))
        return blob[i:]
    if body(out) != body(data):
        raise ValueError("framing changed more than the root canvas")
    return out


def main():
    with open(ORIG, "rb") as f:
        data = f.read()
    out = frame(data)
    with open(OUT, "wb") as f:
        f.write(out)
    print("wrote %s (%d bytes)" % (OUT, len(out)))


if __name__ == "__main__":
    main()
