#!/usr/bin/env python3
"""Pre-render the Mirage I logo as Unicode half-block terminal art.

Development tool only (needs Pillow); the outputs are committed text files
under debian/brand/ so phantom-mirage-setup needs no image tooling at run
time. Source: docs/assets/phantom-mirage-logo-light.png (891 px, the highest
resolution copy of the approved logo), toned to the dark variant used by
docs/assets/phantom-mirage-logo-dark.png and the splash (front P #EEF0F3,
back P and lettering #8A909A, docs/brand/README.md) and drawn on the brand
background #0B0C0F so it reads the same on light and dark terminals.

Each cell is U+2580 (upper half block): foreground = top pixel, background
= bottom pixel, so one cell carries two vertical pixels.

usage: tools/render-term-logo.py [--cols N] [--preview out.png]
"""
import argparse
import os

from PIL import Image

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "docs", "assets", "phantom-mirage-logo-light.png")
OUT = os.path.join(REPO, "debian", "brand")
BG = (11, 12, 15)          # #0B0C0F, brand dark background
FRONT = (238, 240, 243)    # #EEF0F3, front P (dark variant)
BACK = (138, 144, 154)     # #8A909A, back P and lettering (dark variant)
SRC_FRONT, SRC_BACK = 52, 91   # grey levels of the two tones in SRC
HALF = "\u2580"


def render(cols, pad_x=2, pad_y=1):
    im = Image.open(SRC).convert("RGBA")
    im = im.crop(im.getbbox())
    # retone: the logo is two flat greys, so map grey level to the dark pair
    px = im.load()
    for y in range(im.height):
        for x in range(im.width):
            r, g, b, a = px[x, y]
            t = min(1.0, max(0.0, ((r + g + b) / 3 - SRC_FRONT) / (SRC_BACK - SRC_FRONT)))
            px[x, y] = tuple(round(f + (k - f) * t) for f, k in zip(FRONT, BACK)) + (a,)
    inner = cols - 2 * pad_x
    rows_px = round(im.height * inner / im.width)
    rows_px += rows_px % 2
    small = im.resize((inner, rows_px), Image.LANCZOS)
    canvas = Image.new("RGBA", (cols, rows_px + 4 * pad_y), BG + (255,))
    canvas.alpha_composite(small, (pad_x, 2 * pad_y))
    out = canvas.convert("RGB")
    # snap resampling haze to the flat background (fewer escape codes)
    px = out.load()
    for y in range(out.height):
        for x in range(out.width):
            if sum(abs(a - b) for a, b in zip(px[x, y], BG)) < 18:
                px[x, y] = BG
    return out


_CUBE = (0, 95, 135, 175, 215, 255)


def to256(c):
    """nearest xterm-256 index (6x6x6 cube or grey ramp)"""
    best = None
    idx = [min(range(6), key=lambda i: abs(_CUBE[i] - v)) for v in c]
    cand = [(16 + 36 * idx[0] + 6 * idx[1] + idx[2], tuple(_CUBE[i] for i in idx))]
    g = max(0, min(23, round((sum(c) / 3 - 8) / 10)))
    cand.append((232 + g, (8 + 10 * g,) * 3))
    for n, rgb in cand:
        d = sum((a - b) ** 2 for a, b in zip(c, rgb))
        if best is None or d < best[0]:
            best = (d, n)
    return best[1]


def ansi(img, mode):
    w, h = img.size
    px = img.load()
    lines = []
    for y in range(0, h, 2):
        out, last = [], None
        for x in range(w):
            t, b = px[x, y], px[x, y + 1]
            if mode == "24bit":
                code = "\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dm" % (t + b)
            else:
                code = "\x1b[38;5;%d;48;5;%dm" % (to256(t), to256(b))
            if code != last:
                out.append(code)
                last = code
            out.append(HALF)
        lines.append("".join(out) + "\x1b[0m")
    return "\n".join(lines) + "\n"


def preview(img, path, scale=8):
    """what a terminal shows: each pixel as a scale x scale block"""
    img.resize((img.width * scale, img.height * scale), Image.NEAREST).save(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cols", type=int, default=60)
    ap.add_argument("--preview")
    a = ap.parse_args()
    img = render(a.cols)
    os.makedirs(OUT, exist_ok=True)
    for mode in ("24bit", "256"):
        with open(os.path.join(OUT, "logo-%s.ans" % mode), "w", encoding="utf-8", newline="\n") as f:
            f.write(ansi(img, mode))
    if a.preview:
        preview(img, a.preview)
    print("%d columns x %d rows" % (img.width, img.height // 2))


if __name__ == "__main__":
    main()
