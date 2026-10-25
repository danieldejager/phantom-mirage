"""Branding (#141): one source of truth, splash content, no external URLs,
CSP unchanged, setup banner colour rules, and the company-suffix guard."""
import glob
import importlib.util
import os
import pty
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
REPO = os.path.normpath(os.path.join(ROOT, ".."))
STATIC = os.path.join(ROOT, "static")
SETUP = os.path.join(REPO, "debian", "scripts", "phantom-mirage-setup")
CONF = os.path.join(ROOT, "branding.conf")
sys.path.insert(0, ROOT)
import branding  # noqa: E402

os.environ.setdefault("PM_CONSOLE_STATE", tempfile.mkdtemp())
spec = importlib.util.spec_from_file_location("pmconsole_b", os.path.join(ROOT, "pm-console.py"))
pmc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pmc)
ESC = "\x1b"


def login_page():
    with open(os.path.join(STATIC, "index.html"), "rb") as f:
        return pmc.brand_html(f.read()).decode("utf-8")


def run_setup(env_extra, tty=False):
    env = dict(os.environ, PM_BRANDING=CONF, PM_LIBDIR=tempfile.mkdtemp(), LC_ALL="C.UTF-8", TERM="xterm")
    env.pop("NO_COLOR", None)
    env.update(env_extra)
    args = ["sh", SETUP, "--console", "--dry-run"]
    if not tty:
        return subprocess.run(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, timeout=30).stdout.decode("utf-8", "replace")
    m, s = pty.openpty()
    p = subprocess.Popen(args, env=env, stdout=s, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    os.close(s)
    out = b""
    while True:
        try:
            d = os.read(m, 4096)
        except OSError:
            break
        if not d:
            break
        out += d
    p.wait(timeout=30)
    os.close(m)
    return out.decode("utf-8", "replace")


class TestBrandingSource(unittest.TestCase):
    def test_values(self):
        self.assertEqual(branding.PRODUCT, "Mirage I")
        self.assertEqual(branding.LEGAL_NAME, "Phantom Technologies")
        self.assertEqual(branding.COPYRIGHT, "\u00a9 2026 Phantom Technologies. All rights reserved.")

    def test_shell_reads_the_same_values(self):
        out = subprocess.run(["sh", "-c", '. "$1"; printf "%s\\n" "$PM_PRODUCT" "$PM_LEGAL_NAME" "$PM_COPYRIGHT"',
                              "sh", CONF], capture_output=True, check=True).stdout.decode("utf-8")
        self.assertEqual(out.splitlines(), [branding.PRODUCT, branding.LEGAL_NAME, branding.COPYRIGHT])

    def test_copyright_follows_legal_name(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, encoding="utf-8") as f:
            f.write(open(CONF, encoding="utf-8").read().replace(
                'PM_LEGAL_NAME="Phantom Technologies"', 'PM_LEGAL_NAME="Example Co"'))
        v = branding.load(f.name)
        os.unlink(f.name)
        self.assertEqual(v["PM_COPYRIGHT"], "\u00a9 2026 Example Co. All rights reserved.")


class TestLoginPage(unittest.TestCase):
    def test_splash_content(self):
        t = login_page()
        self.assertNotIn("{{", t)
        self.assertIn('src="/static/phantom-mirage-mark.png"', t)
        self.assertIn('<h1 class="sname">Mirage I</h1>', t)
        self.assertIn('<p class="slegal">Phantom Technologies</p>', t)
        self.assertIn("\u00a9 2026 Phantom Technologies. All rights reserved.", t)
        self.assertIn("<title>Mirage I console</title>", t)

    def test_no_inline_script_or_style(self):
        t = login_page()
        self.assertNotRegex(t, r'<script(?![^>]*\bsrc=)')
        self.assertNotRegex(t, r'<style|\sstyle=|\son[a-z]+=')

    def test_no_external_urls(self):
        for fp in glob.glob(os.path.join(STATIC, "*")) + [os.path.join(REPO, "docs", "assets", "phantom-mirage-mark.svg")]:
            if fp.endswith(".png"):
                continue
            t = open(fp, encoding="utf-8").read()
            t = t.replace("http://www.w3.org/2000/svg", "")   # SVG namespace, not a request
            bad = [u for u in re.findall(r'(?i)\bhttps?://[^\s"\'`<>)]*', t)
                   if not re.match(r'(?i)https?://(127\.0\.0\.1|localhost)[:/]', u)]   # loopback text only
            bad += re.findall(r'(?i)(?:src|href)\s*=\s*["\']?//[^\s"\']*|@import|url\(\s*["\']?(?:https?:)?//', t)
            self.assertEqual(bad, [], fp)

    def test_assets_served_and_packaged(self):
        rules = open(os.path.join(REPO, "debian", "rules"), encoding="utf-8").read()
        for ref in re.findall(r'/static/([A-Za-z0-9_.-]+)', login_page()):
            self.assertIn(os.path.splitext(ref)[1], pmc.TYPES)
            self.assertIn(ref, rules)
        self.assertIn("console/branding.py console/branding.conf", rules)

    def test_csp_unchanged(self):
        self.assertEqual(pmc.CSP, "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                         "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

    def test_themes(self):
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        for c in ("#07061A", "#15123A", "#7B61FF", "#F3F0FF"):     # Afterburner
            self.assertIn(c, css)
        light = css[css.index("prefers-color-scheme:light"):]
        for c in ("#F5F4FB", "#FFFFFF", "#5B45D6", "#14102E"):     # Mach Light
            self.assertIn(c, light)


class TestSetupBanner(unittest.TestCase):
    def test_banner_plain_when_not_a_tty(self):
        out = run_setup({})
        self.assertIn("Mirage I", out)
        self.assertIn("Phantom Technologies. All rights reserved.", out)
        self.assertNotIn(ESC, out)

    def test_banner_colour_on_tty_only_without_no_color(self):
        self.assertIn(ESC, run_setup({}, tty=True))
        out = run_setup({"NO_COLOR": "1"}, tty=True)
        self.assertIn("Mirage I", out)
        self.assertNotIn(ESC, out)

    def test_ascii_fallback(self):
        out = run_setup({"LC_ALL": "C"})
        self.assertIn("(c) 2026 Phantom Technologies", out)
        self.assertTrue(all(ord(ch) < 128 for ch in out), out)


class TestNoCompanySuffix(unittest.TestCase):
    """The company is not registered yet (#141): the suffix must not ship.
    Remove this guard only together with the branding.conf change once
    registration is confirmed."""
    SUFFIX = "Pty" + " Ltd"

    def test_not_in_shipped_files(self):
        files = (glob.glob(os.path.join(ROOT, "*.py")) + glob.glob(os.path.join(ROOT, "branding.conf"))
                 + [os.path.join(ROOT, "pm-firewall")] + glob.glob(os.path.join(STATIC, "*"))
                 + glob.glob(os.path.join(REPO, "debian", "scripts", "*"))
                 + glob.glob(os.path.join(REPO, "docs", "assets", "*.svg")))
        self.assertTrue(files)
        for fp in files:
            with open(fp, "rb") as f:
                data = f.read()
            self.assertNotIn(self.SUFFIX.encode(), data, fp)
            self.assertNotIn(self.SUFFIX.upper().encode(), data, fp)
        for s in (branding.PRODUCT, branding.LEGAL_NAME, branding.COPYRIGHT, login_page()):
            self.assertNotIn(self.SUFFIX.lower(), s.lower())


if __name__ == "__main__":
    unittest.main()
