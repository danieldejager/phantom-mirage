#!/usr/bin/env python3
"""Rebuild docs/assets/phantom-technologies-wordmark.svg.

Original squared lettering for the console: a wide low PHANTOM line and a
smaller, tracked TECHNOLOGIES line. Paths only. No font is read, embedded
or requested. Run from the repo root.
"""
import math
import os

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
OUT = os.path.join(ROOT, "docs", "assets", "phantom-technologies-wordmark.svg")

CAP = 100.0
SW = 18.0
ANG = 5.5          # terminal shear: visible up close, quiet at header size
GAP = 14.0
TECH_SCALE = 0.54
LINE_GAP = 18.0


def r(n):
    return round(n, 1)


def vstem(x, y, h, sw=SW, ang=ANG, top=False, bot=False):
    """Vertical stem. A free end is a shallow parallelogram cut."""
    y1 = y + h
    return [
        (x, y + (ang if top else 0)),
        (x + sw, y),
        (x + sw, y1 - (ang if bot else 0)),
        (x, y1),
    ]


def hstem(x, y, w, sw=SW, ang=ANG, left=False, right=False):
    """Horizontal stem. A free end uses the same cut direction."""
    return [
        (x + (ang if left else 0), y),
        (x + w, y),
        (x + w - (ang if right else 0), y + sw),
        (x, y + sw),
    ]


def thick(x0, y0, x1, y1, sw):
    """A solid bar along the segment. Winding matches the stems (positive area)."""
    dx, dy = x1 - x0, y1 - y0
    length = math.hypot(dx, dy) or 1.0
    ox, oy = -dy / length * sw / 2.0, dx / length * sw / 2.0
    return [(x0 - ox, y0 - oy), (x1 - ox, y1 - oy), (x1 + ox, y1 + oy), (x0 + ox, y0 + oy)]


def clip_rect(poly, x0, y0, x1, y1):
    """Clip a convex polygon to a rectangle so diagonals do not spike past the letter."""
    def lerp(a, b, t):
        return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)

    def cut(pts, inside, cross):
        if not pts:
            return []
        out = []
        prev = pts[-1]
        pin = inside(prev)
        for cur in pts:
            cin = inside(cur)
            if cin:
                if not pin:
                    out.append(cross(prev, cur))
                out.append(cur)
            elif pin:
                out.append(cross(prev, cur))
            prev, pin = cur, cin
        return out

    def cross_x(a, b, x):
        dx = b[0] - a[0]
        t = 0.0 if abs(dx) < 1e-9 else (x - a[0]) / dx
        return lerp(a, b, max(0.0, min(1.0, t)))

    def cross_y(a, b, y):
        dy = b[1] - a[1]
        t = 0.0 if abs(dy) < 1e-9 else (y - a[1]) / dy
        return lerp(a, b, max(0.0, min(1.0, t)))

    pts = poly
    pts = cut(pts, lambda p: p[0] >= x0, lambda a, b: cross_x(a, b, x0))
    pts = cut(pts, lambda p: p[0] <= x1, lambda a, b: cross_x(a, b, x1))
    pts = cut(pts, lambda p: p[1] >= y0, lambda a, b: cross_y(a, b, y0))
    pts = cut(pts, lambda p: p[1] <= y1, lambda a, b: cross_y(a, b, y1))
    return pts


def chamfer_box(x, y, w, h, c):
    c = max(0.0, min(c, w / 2.0 - 0.1, h / 2.0 - 0.1))
    return [
        (x + c, y), (x + w - c, y), (x + w, y + c), (x + w, y + h - c),
        (x + w - c, y + h), (x + c, y + h), (x, y + h - c), (x, y + c),
    ]


def letter_p():
    w = 86.0
    bowl = 60.0
    return w, [
        vstem(0, 0, CAP, bot=True),
        hstem(0, 0, w),
        vstem(w - SW, 0, bowl, bot=True),
        hstem(0, bowl - SW, w),
    ]


def letter_h():
    w = 78.0
    return w, [vstem(0, 0, CAP, top=True, bot=True), vstem(w - SW, 0, CAP, top=True, bot=True),
               hstem(0, (CAP - SW) / 2.0, w)]


def _area(poly):
    a = 0.0
    for i, (x, y) in enumerate(poly):
        x2, y2 = poly[(i + 1) % len(poly)]
        a += x * y2 - x2 * y
    return a / 2.0


def _leg(cx, foot_x, stroke):
    """One open-A stroke from the apex centre to a foot, cut flat at cap and baseline."""
    dx, dy = foot_x - cx, CAP
    length = math.hypot(dx, dy)
    px, py = -dy / length, dx / length
    half = stroke / 2.0

    def edge(side):
        ox, oy = side * px * half, side * py * half
        x0, y0 = cx + ox, oy
        x1, y1 = foot_x + ox, CAP + oy
        span = y1 - y0

        def at(y):
            return x0 + (y - y0) / span * (x1 - x0)
        return at(0.0), at(CAP)

    a_top, a_bot = edge(-1.0)
    b_top, b_bot = edge(1.0)
    top = sorted((a_top, b_top))
    bot = sorted((a_bot, b_bot))
    return [(top[0], 0.0), (top[1], 0.0), (bot[1], CAP), (bot[0], CAP)]


def letter_a():
    """Open triangular A matched to the MIRAGE wordmark.

    Two strokes meet at a flat apex, with no crossbar and no base, so the
    bottom stays open. The lean and the stroke-to-height ratio are taken from
    the traced MIRAGE A (about 26.5 degrees off vertical, stroke about 0.208
    of the cap). Neighbouring letters keep the wordmark stroke.
    """
    stroke = CAP * 0.208  # MIRAGE A perpendicular stroke / cap, from the traced wordmark
    foot_dx = CAP * math.tan(math.radians(26.5))
    half = (stroke / 2.0) / math.cos(math.radians(26.5))
    w = 2.0 * (foot_dx + half)
    cx = w / 2.0
    return w, [_leg(cx, cx - foot_dx, stroke), _leg(cx, cx + foot_dx, stroke)]


def letter_n():
    w = 86.0
    diag = clip_rect(thick(SW * 0.35, ANG, w - SW * 0.35, CAP - ANG, SW + 2), 0, 0, w, CAP)
    return w, [vstem(0, 0, CAP, top=True, bot=True), vstem(w - SW, 0, CAP, top=True, bot=True), diag]


def letter_t():
    w = 74.0
    return w, [hstem(0, 0, w, left=True, right=True), vstem((w - SW) / 2.0, 0, CAP, bot=True)]


def letter_o():
    w = 90.0
    c = 8.0
    outer = chamfer_box(0, 0, w, CAP, c)
    inner = list(reversed(chamfer_box(SW, SW, w - 2 * SW, CAP - 2 * SW, c * 0.55)))
    return w, [outer, inner]


def letter_m():
    w = 120.0
    cx, cy = w / 2.0, CAP - 0.5
    left = clip_rect(thick(SW * 0.25, ANG, cx, cy, SW + 1), 0, 0, w, CAP)
    right = clip_rect(thick(w - SW * 0.25, ANG, cx, cy, SW + 1), 0, 0, w, CAP)
    return w, [vstem(0, 0, CAP, top=True, bot=True), vstem(w - SW, 0, CAP, top=True, bot=True), left, right]


def letter_e():
    w = 68.0
    mid_w = 52.0
    return w, [
        vstem(0, 0, CAP),
        hstem(0, 0, w, right=True),
        hstem(0, (CAP - SW) / 2.0, mid_w, right=True),
        hstem(0, CAP - SW, w, right=True),
    ]


def letter_c():
    w = 74.0
    arm = w - 10.0
    return w, [
        vstem(0, 0, CAP),
        hstem(0, 0, arm, right=True),
        hstem(0, CAP - SW, arm, right=True),
    ]


def letter_l():
    w = 62.0
    return w, [vstem(0, 0, CAP, top=True), hstem(0, CAP - SW, w, right=True)]


def letter_g():
    w = 78.0
    spur_y = 46.0
    return w, [
        vstem(0, 0, CAP),
        hstem(0, 0, w - 14.0, right=True),
        hstem(0, CAP - SW, w),
        vstem(w - SW, spur_y, CAP - spur_y, top=True),
        hstem(w - 36.0, spur_y, 36.0, left=True),
    ]


def letter_i():
    return SW, [vstem(0, 0, CAP, top=True, bot=True)]


def letter_s():
    w = 70.0
    mid_y = (CAP - SW) / 2.0
    return w, [
        vstem(0, 0, mid_y + SW),
        hstem(0, 0, w, right=True),
        hstem(0, mid_y, w),
        vstem(w - SW, mid_y, CAP - mid_y),
        hstem(0, CAP - SW, w, left=True),
    ]


PHANTOM = {
    "P": letter_p, "H": letter_h, "A": letter_a, "N": letter_n,
    "T": letter_t, "O": letter_o, "M": letter_m,
}
TECH = {
    "T": letter_t, "E": letter_e, "C": letter_c, "H": letter_h, "N": letter_n,
    "O": letter_o, "L": letter_l, "G": letter_g, "I": letter_i, "S": letter_s,
}


def shift(poly, dx, dy):
    return [(x + dx, y + dy) for x, y in poly]


def scale_poly(poly, k):
    return [(x * k, y * k) for x, y in poly]


def layout(word, table, scale=1.0, tracking=0.0, y=0.0):
    """Place letters. tracking is extra space added between them, after scale."""
    paths = []
    x = 0.0
    advances = []
    for i, ch in enumerate(word):
        width, polys = table[ch]()
        width *= scale
        advances.append(width)
        for poly in polys:
            paths.append(shift(scale_poly(poly, scale), x, y))
        x += width
        if i != len(word) - 1:
            x += GAP * scale + tracking
    return paths, x, advances


def path_d(polys):
    parts = []
    for poly in polys:
        cmd = ["M %.1f %.1f" % (r(poly[0][0]), r(poly[0][1]))]
        cmd.extend("L %.1f %.1f" % (r(x), r(y)) for x, y in poly[1:])
        cmd.append("Z")
        parts.append(" ".join(cmd))
    return "".join(parts)


def ink_width(word, table, scale):
    widths = [table[ch]()[0] * scale for ch in word]
    return sum(widths) + GAP * scale * (len(word) - 1)


def build():
    phantom, p_width, _ = layout("PHANTOM", PHANTOM, 1.0, 0.0, 0.0)
    natural = ink_width("TECHNOLOGIES", TECH, TECH_SCALE)
    extra = p_width - natural
    tracking = extra / (len("TECHNOLOGIES") - 1)
    if tracking < 0:
        raise SystemExit("TECHNOLOGIES is wider than PHANTOM; reduce TECH_SCALE")
    tech_y = CAP + LINE_GAP
    tech, t_width, _ = layout("TECHNOLOGIES", TECH, TECH_SCALE, tracking, tech_y)
    height = tech_y + CAP * TECH_SCALE
    # centre the tracked line on the PHANTOM ink
    dx = (p_width - t_width) / 2.0
    tech = [shift(p, dx, 0) for p in tech]
    return phantom, tech, p_width, height, tracking


def main():
    phantom, tech, width, height, tracking = build()
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %.1f %.1f" '
        'fill="currentColor" role="img" aria-label="Phantom Technologies">'
        "<title>Phantom Technologies</title>"
        "<!-- Original squared lettering as filled paths: wide PHANTOM with an open triangular A "
        "matched to the MIRAGE A, smaller tracked TECHNOLOGIES. Nothing is loaded at runtime. -->"
        '<path id="phantom" d="%s"/>'
        '<path id="technologies" d="%s"/>'
        "</svg>\n"
    ) % (r(width), r(height), path_d(phantom), path_d(tech))
    # the word "font" must not appear: the mark is geometry, and the console
    # test rejects that substring in this file
    if "font" in svg.lower():
        raise SystemExit("svg contains a forbidden substring")
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(svg)
    print("wrote %s" % OUT)
    print("viewBox 0 0 %.1f %.1f aspect %.4f tracking %.2f" % (width, height, width / height, tracking))


if __name__ == "__main__":
    main()
