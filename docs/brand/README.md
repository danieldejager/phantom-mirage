# Mirage I brand reference

Design references only, not shipped in the product.

- `source/logo_reference_from_daniel.png`: the approved logo (P mark and MIRAGE I lettering). The logo must be reproduced identically, not redrawn. Tones: front P about #2E2E32, back P and lettering about #5C5C60 on light grey.
- `splash/splash_dark_boot.png`, `splash_dark_shutdown.png`: the chosen direction (dark). Logo shapes unchanged, tones lightened (front P #EEF0F3, back P and lettering #8A909A) on near-black #0B0C0F. Spinner is a radial tick spinner like the stock Ubuntu one.
- `splash/splash_light_*.png`: light variant in the original logo colours.
- `mirage_ui_layout_mockup.png`: console theme mock-up (dark Afterburner, light Mach Light).
- `source/splash2.py`, `logo_extract.py`, `logo_masks.npz`: how the mock-ups were produced (logo traced from the reference at 6x).

Notes: "Pty Ltd" appears in the mock-ups only; do not ship it until the company is registered. Status wording in the mock-ups ("integrity check passed") is placeholder and must only appear if the sensor really performs that check. Supporting text uses the Aldrich font as the closest match; the exact font of the logo lettering is unknown.

Terminal logo: `debian/brand/logo-24bit.ans` and `logo-256.ans` are the logo pre-rendered as Unicode half-block art (60 columns) by `tools/render-term-logo.py` (needs Pillow, development only). phantom-mirage-setup prints them on a UTF-8 colour terminal and falls back to a plain wordmark otherwise. Rerun the tool after any change to `docs/assets/phantom-mirage-logo-light.png`.
