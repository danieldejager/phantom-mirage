"""Generate docs/assets/phantom-mirage-logo-dark.png (#141) from the traced
masks in logo_masks.npz (same approach as splash2.py logo_rgba): front P
#EEF0F3, back P and lettering #8A909A, transparent background (shown on
#0B0C0F). The masks are 6x the 313 px reference, so the output (2x native)
is a LANCZOS downsample; nothing is redrawn. Run from the repo root."""
import numpy as np
from PIL import Image

m = np.load("docs/brand/source/logo_masks.npz")
shape, dark = m["shape"], m["dark"]
ys, xs = np.where(shape > 0.5)
y0, y1, x0, x1 = ys.min() - 6, ys.max() + 6, xs.min() - 6, xs.max() + 6
shape, dark = shape[y0:y1, x0:x1], dark[y0:y1, x0:x1]


def hx(c):
    return np.array([int(c[i:i + 2], 16) for i in (1, 3, 5)], float)


col = hx("#8A909A") * (1 - dark[..., None]) + hx("#EEF0F3") * dark[..., None]
w, h = round(shape.shape[1] / 3), round(shape.shape[0] / 3)
rgb = Image.fromarray(col.astype("uint8")).resize((w, h), Image.LANCZOS)
rgb.putalpha(Image.fromarray((shape * 255).astype("uint8")).resize((w, h), Image.LANCZOS))
rgb.save("docs/assets/phantom-mirage-logo-dark.png", optimize=True)
print(w, h)
