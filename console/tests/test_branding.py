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
LOGODIR = os.path.join(REPO, "debian", "brand")
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
    env = dict(os.environ, PM_TESTING="1", PM_BRANDING=CONF, PM_LIBDIR=tempfile.mkdtemp(), PM_LOGODIR=LOGODIR, LC_ALL="C.UTF-8", TERM="xterm")
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


def conf(text):
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False, encoding="utf-8") as f:
        f.write(text)
    return f.name


GOOD = 'PM_PRODUCT="P1"\nPM_LEGAL_NAME="L1"\nPM_COPYRIGHT="(c) ${PM_LEGAL_NAME} x"\n'
PWNED = os.path.join(tempfile.mkdtemp(), "pwned")
EVIL = [
    'PM_PRODUCT="$(touch %s)"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\n' % PWNED,
    'PM_PRODUCT="`touch %s`"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\n' % PWNED,
    'PM_PRODUCT="P"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\nPM_EXTRA="x"\n',
    'PM_PRODUCT="P"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\ntouch %s\n' % PWNED,
    'PM_PRODUCT="P"; touch %s\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\n' % PWNED,
    'PM_PRODUCT="${HOME}"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\n',
    'PM_PRODUCT="P"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="${PM_LEGAL_NAME}$(touch %s)"\n' % PWNED,
    'PM_PRODUCT="P"\nPM_PRODUCT="Q"\nPM_LEGAL_NAME="L"\nPM_COPYRIGHT="C"\n',
    'PM_PRODUCT="P"\nPM_LEGAL_NAME="L"\n',
]


class TestBrandingParser(unittest.TestCase):
    """branding.conf is data, never code (#141 review): setup runs as root."""

    def test_rejected_by_python_and_shell(self):
        for text in EVIL:
            f = conf(text)
            with self.assertRaises(ValueError, msg=text):
                branding.load(f)
            out = run_setup({"PM_BRANDING": f})
            self.assertNotIn("Mirage I", out)
            self.assertNotIn("P1", out)
            self.assertFalse(os.path.exists(PWNED), text)
            os.unlink(f)

    def test_good_file_parsed_by_both(self):
        f = conf(GOOD)
        self.assertEqual(branding.load(f), {"PM_PRODUCT": "P1", "PM_LEGAL_NAME": "L1", "PM_COPYRIGHT": "(c) L1 x"})
        out = run_setup({"PM_BRANDING": f})
        os.unlink(f)
        self.assertIn("P1", out)
        self.assertIn("(c) L1 x", out)

    def test_override_ignored_without_test_switch(self):
        f = conf(GOOD)
        lib = tempfile.mkdtemp()
        os.makedirs(os.path.join(lib, "console"))
        with open(os.path.join(lib, "console", "branding.conf"), "w", encoding="utf-8") as o:
            o.write(open(CONF, encoding="utf-8").read())
        env = {"PM_BRANDING": f, "PM_TESTING": "", "PM_LIBDIR": lib}
        out = run_setup(env)
        self.assertIn("Mirage I", out)
        self.assertNotIn("P1", out)
        code = "import branding,sys;print(branding.PATH);print(branding.PRODUCT)"
        for testing, want in (("", "Mirage I"), ("1", "P1")):
            r = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=True,
                               env=dict(os.environ, PM_BRANDING=f, PM_TESTING=testing))
            self.assertEqual(r.stdout.splitlines()[1], want)
        os.unlink(f)

    def test_shell_never_sources_the_file(self):
        t = open(SETUP, encoding="utf-8").read()
        self.assertNotRegex(t, r'(?m)^\s*\.\s+"?\$BRANDING')
        self.assertNotIn("eval", t[t.index("load_branding()"):t.index("banner()")])

    def test_hostile_values_escaped(self):
        f = conf('PM_PRODUCT="<script>alert(1)</script>\x1b[31mX\x07\u009b2J"\n'
                 'PM_LEGAL_NAME="<b>L&</b>\x1b]0;t\x07"\nPM_COPYRIGHT="c ${PM_LEGAL_NAME} \x1b[2J"\n')
        r = subprocess.run([sys.executable, "-c",
                            "import importlib.util,os,sys;sys.path.insert(0,'.');"
                            "s=importlib.util.spec_from_file_location('m','pm-console.py');"
                            "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                            "sys.stdout.write(m.brand_html(open('static/index.html','rb').read()).decode())"],
                           cwd=ROOT, capture_output=True, text=True, check=True,
                           env=dict(os.environ, PM_BRANDING=f, PM_TESTING="1", PM_CONSOLE_STATE=tempfile.mkdtemp()))
        page = r.stdout
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("&lt;b&gt;L&amp;&lt;/b&gt;", page)
        self.assertNotIn(ESC, page)
        for env in ({}, {"LC_ALL": "C"}):
            out = run_setup(dict(env, PM_BRANDING=f))
            self.assertIn("<script>alert(1)</script>", out)
            self.assertNotRegex(out, r'[\x00-\x09\x0b-\x1f\x7f-\x9f]', env)
        out = run_setup({"PM_BRANDING": f, "NO_COLOR": "1"}, tty=True)
        self.assertIn("alert(1)", out)
        self.assertNotIn(ESC, out)
        os.unlink(f)


class TestBrandingSource(unittest.TestCase):
    def test_values(self):
        self.assertEqual(branding.PRODUCT, "Mirage I")
        self.assertEqual(branding.LEGAL_NAME, "Phantom Technologies")
        self.assertEqual(branding.COPYRIGHT, "\u00a9 2026 Phantom Technologies. All rights reserved.")

    def test_shell_reads_the_same_values(self):
        out = run_setup({})
        for v in (branding.PRODUCT, branding.LEGAL_NAME, branding.COPYRIGHT):
            self.assertIn(v, out)

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
        login = t[t.index('<div id="login">'):t.index("<header>")]
        brand = login[:login.index('<div class="card">')]
        self.assertIn('<span class="mwm swm" role="img" aria-label="Mirage"></span>', brand)
        self.assertIn('<h1 class="sname">Mirage I</h1>', brand)
        self.assertNotIn("ptile", brand)
        self.assertNotIn("ptw", brand)
        self.assertNotIn("phantom-mirage-mark", brand)
        self.assertNotIn("Phantom Technologies", brand)
        self.assertIn("\u00a9 2026 Phantom Technologies. All rights reserved.", login)
        self.assertIn("sudo phantom-mirage-setup --reset-admin", login)
        self.assertIn("<title>Mirage I console</title>", t)

    def test_no_inline_script_or_style(self):
        t = login_page()
        self.assertNotRegex(t, r'<script(?![^>]*\bsrc=)')
        self.assertNotRegex(t, r'<style|\sstyle=|\son[a-z]+=')

    def test_no_external_urls(self):
        files = [fp for fp in glob.glob(os.path.join(STATIC, "**", "*"), recursive=True) if os.path.isfile(fp)]
        files.append(os.path.join(REPO, "docs", "assets", "phantom-mirage-mark.svg"))
        files.append(os.path.join(REPO, "docs", "assets", "mirage-wordmark.svg"))
        for fp in files:
            if fp.endswith((".png", ".woff2")) or fp.endswith("Aldrich-OFL.txt"):   # binary / licence text, never fetched
                continue
            t = open(fp, encoding="utf-8").read()
            t = t.replace("http://www.w3.org/2000/svg", "")   # SVG namespace, not a request
            bad = [u for u in re.findall(r'(?i)\bhttps?://[^\s"\'`<>)]*', t)
                   if not re.match(r'(?i)https?://(127\.0\.0\.1|localhost)[:/]', u)]   # loopback text only
            bad += re.findall(r'(?i)(?:src|href)\s*=\s*["\']?//[^\s"\']*|@import|url\(\s*["\']?(?:https?:)?//', t)
            self.assertEqual(bad, [], fp)

    def test_font_same_origin(self):
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        urls = re.findall(r'url\(\s*["\']?([^"\')]+)', css)
        self.assertEqual(urls, ["/static/fonts/Aldrich-Regular.woff2"] + ["/static/mirage-wordmark.svg"] * 2 + ["/static/phantom-technologies-wordmark.svg"] * 2)
        self.assertIn("font-family:Aldrich", css)
        self.assertNotRegex(css, r'(?i)jetbrains|rajdhani')
        with open(os.path.join(STATIC, "fonts", "Aldrich-Regular.woff2"), "rb") as f:
            self.assertEqual(f.read(4), b"wOF2")

    def test_ofl_licence_shipped(self):
        lic = open(os.path.join(STATIC, "fonts", "Aldrich-OFL.txt"), encoding="utf-8").read()
        self.assertIn("SIL OPEN FONT LICENSE Version 1.1", lic)
        self.assertIn("Reserved Font Name Aldrich", lic)
        rules = open(os.path.join(REPO, "debian", "rules"), encoding="utf-8").read()
        for n in ("Aldrich-Regular.woff2", "Aldrich-OFL.txt"):
            self.assertIn("console/static/fonts/" + n, rules)
            self.assertIn("fonts/" + n, pmc.STATIC_FILES)
        self.assertIn("SIL Open Font License, Version 1.1", open(os.path.join(REPO, "debian", "copyright"), encoding="utf-8").read())
        self.assertIn(".woff2", pmc.TYPES)

    def test_dark_logo_asset(self):
        from_png = os.path.join(REPO, "docs", "assets", "phantom-mirage-logo-dark.png")
        with open(from_png, "rb") as f:
            head = f.read(24)
        self.assertEqual(head[:8], b"\x89PNG\r\n\x1a\n")
        w, h = int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")
        self.assertEqual((w, h), (496, 202))
        self.assertIn("phantom-mirage-logo-dark.png", pmc.STATIC_FILES)
        self.assertIn("static/phantom-mirage-logo-dark.png", open(os.path.join(REPO, ".github", "workflows", "build.yml")).read())
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        self.assertIn("--sbg:#0B0C0F", css)
        self.assertRegex(css, r'prefers-color-scheme:light\)\{:root:not\(\[data-theme=dark\]\) \.slogo \.lg-dark\{display:none\}')
        self.assertIn(":root[data-theme=light] .slogo .lg-dark{display:none}", css)

    def test_assets_served_and_packaged(self):
        rules = open(os.path.join(REPO, "debian", "rules"), encoding="utf-8").read()
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        refs = re.findall(r'/static/([A-Za-z0-9_./-]+)', login_page() + css)
        self.assertTrue(refs)
        for ref in refs:
            self.assertIn(ref, pmc.STATIC_FILES)
            self.assertIn(os.path.splitext(ref)[1], pmc.TYPES)
            self.assertIn(os.path.basename(ref), rules)
        self.assertIn("console/branding.py console/branding.conf", rules)

    def test_csp_only_adds_font_src(self):
        self.assertEqual(pmc.CSP, "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
                         "font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; "
                         "base-uri 'none'")

    def test_themes(self):
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        for c in ("--bg:#0B0D0F", "--p:#101417", "--a:#22D3EE", "--t:#E4EAEE"):     # carbon dark
            self.assertIn(c, css)
        light = css[css.index("prefers-color-scheme:light"):]
        for c in ("#ECEFF2", "#FFFFFF", "#0E7490", "#0F1519"):     # light
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

    RETIRED = ("123;97;255", "255;122;47", "176;79;214")   # violet, ember, haze

    def test_banner_uses_grey_256_colour_by_default(self):
        out = run_setup({"COLORTERM": ""}, tty=True)
        for r in self.RETIRED:
            self.assertNotIn(r, out)
        self.assertIn("\x1b[38;5;245m", out)     # lettering grey
        self.assertIn("48;5;", out)               # 256-colour half-block logo
        self.assertIn("\u2580", out)
        self.assertNotIn("38;2;", out)

    def test_banner_uses_grey_truecolor_when_advertised(self):
        out = run_setup({"COLORTERM": "truecolor"}, tty=True)
        for r in self.RETIRED:
            self.assertNotIn(r, out)
        self.assertIn("48;2;11;12;15", out)       # logo on brand #0B0C0F
        self.assertIn("\u2580", out)
        self.assertNotIn("38;5;", out)
        self.assertIn("\x1b[38;2;138;144;154m", out)     # #8A909A

    def test_no_escape_with_dumb_term_or_no_color(self):
        for env in ({"TERM": "dumb"}, {"NO_COLOR": "1"}, {"NO_COLOR": "1", "COLORTERM": "truecolor"}):
            out = run_setup(env, tty=True)
            self.assertIn("Mirage I", out)
            self.assertNotIn(ESC, out, env)

    def test_ascii_fallback_in_colour_is_grey(self):
        out = run_setup({"LC_ALL": "C"}, tty=True)
        self.assertIn("(c) 2026 Phantom Technologies", out)
        self.assertIn("\x1b[38;5;245m", out)
        self.assertTrue(all(ord(ch) < 128 for ch in out), out)

    def test_no_logo_art_without_tty_or_utf8(self):
        for env, tty in (({}, False), ({"NO_COLOR": "1"}, True), ({"TERM": "dumb"}, True),
                         ({"LC_ALL": "C"}, True)):
            self.assertNotIn("\u2580", run_setup(env, tty=tty), env)

    def test_missing_logo_falls_back_to_wordmark(self):
        out = run_setup({"PM_LOGODIR": tempfile.mkdtemp(), "COLORTERM": "truecolor"}, tty=True)
        self.assertIn("Mirage I", out)
        self.assertNotIn("\u2580", out)

    def test_logo_assets_shape(self):
        import re
        for name, pat in (("logo-24bit.ans", r"\x1b\[38;2;\d+;\d+;\d+;48;2;\d+;\d+;\d+m"),
                          ("logo-256.ans", r"\x1b\[38;5;\d+;48;5;\d+m")):
            with open(os.path.join(LOGODIR, name), encoding="utf-8") as f:
                lines = f.read().splitlines()
            self.assertTrue(8 <= len(lines) <= 20, name)
            widths = set()
            for ln in lines:
                self.assertTrue(ln.endswith("\x1b[0m"), name)
                bare = re.sub(pat, "", ln[:-4])
                self.assertEqual(set(bare), {"\u2580"}, name)
                widths.add(len(bare))
            self.assertEqual(len(widths), 1, name)
            self.assertTrue(40 <= widths.pop() <= 60, name)

    def test_script_has_no_retired_palette(self):
        with open(SETUP, encoding="utf-8") as f:
            t = f.read()
        for h in ("7B61FF", "FF7A2F", "B04FD6", "EEF0F3", "38;5;255", "238;240;243") + self.RETIRED:
            self.assertNotIn(h, t)


class TestNoCompanySuffix(unittest.TestCase):
    """The company is not registered yet (#141): the suffix must not ship.
    Remove this guard only together with the branding.conf change once
    registration is confirmed."""
    SUFFIX = "Pty" + " Ltd"

    def test_not_in_shipped_files(self):
        files = (glob.glob(os.path.join(ROOT, "*.py")) + glob.glob(os.path.join(ROOT, "branding.conf"))
                 + [os.path.join(ROOT, "pm-firewall")]
                 + [fp for fp in glob.glob(os.path.join(STATIC, "**", "*"), recursive=True) if os.path.isfile(fp)]
                 + glob.glob(os.path.join(REPO, "debian", "scripts", "*"))
                 + glob.glob(os.path.join(REPO, "docs", "assets", "*.svg")))
        self.assertTrue(files)
        # docs/brand/ holds design references that contain the suffix on purpose
        self.assertFalse([fp for fp in files if os.sep + os.path.join("docs", "brand") + os.sep in fp])
        for fp in files:
            with open(fp, "rb") as f:
                data = f.read()
            self.assertNotIn(self.SUFFIX.encode(), data, fp)
            self.assertNotIn(self.SUFFIX.upper().encode(), data, fp)
        for s in (branding.PRODUCT, branding.LEGAL_NAME, branding.COPYRIGHT, login_page()):
            self.assertNotIn(self.SUFFIX.lower(), s.lower())


def _subpath_boxes(d):
    boxes = []
    for part in re.findall(r"M[^Z]*Z", d):
        nums = [float(n) for n in re.findall(r"[-+]?\d*\.?\d+", part)]
        xs, ys = nums[0::2], nums[1::2]
        boxes.append((min(xs), min(ys), max(xs), max(ys)))
    return boxes


def _clusters(d, pad=1.0):
    """Group overlapping subpaths into letters, left to right."""
    groups = []
    for b in sorted(_subpath_boxes(d), key=lambda b: b[0]):
        if groups and b[0] <= groups[-1][2] + pad:
            g = groups[-1]
            groups[-1] = (min(g[0], b[0]), min(g[1], b[1]), max(g[2], b[2]), max(g[3], b[3]))
        else:
            groups.append(b)
    return groups


def _gap_ratio(groups):
    widths = sorted(g[2] - g[0] for g in groups)
    gaps = sorted(groups[i + 1][0] - groups[i][2] for i in range(len(groups) - 1))
    return gaps[len(gaps) // 2] / widths[len(widths) // 2]


class TestWordmark(unittest.TestCase):
    def test_header_and_sidebar(self):
        t = login_page()
        head = re.search(r'<header>.*?</header>', t, re.S).group(0)
        self.assertIn('<span class="ptile"><img src="/static/phantom-mirage-mark-dark.png" width="34" height="34"', head)
        self.assertIn('<span class="hlegal ptw" role="img" aria-label="Phantom Technologies"></span>', head)
        self.assertNotIn(">Phantom Technologies<", head)
        self.assertNotIn('class="wm"', head)
        self.assertNotIn("Mirage", head)
        self.assertNotIn("tabindex", head)
        self.assertNotIn("<button", head)
        self.assertIn('<div class="nbrand brand"><span class="mwm" role="img" aria-label="Mirage"></span></div>', t)
        login = t[t.index('<div id="login">'):t.index("<header>")]
        brand = login[:login.index('<div class="card">')]
        self.assertIn('<span class="mwm swm" role="img" aria-label="Mirage"></span>', brand)
        self.assertNotIn("ptw", brand)
        self.assertNotIn("ptile", brand)
        self.assertNotIn('class="slegal"', brand)

    def test_sidebar_wordmark_centred(self):
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        self.assertIn(".nbrand{justify-content:center}", css)

    def test_company_wordmark_svg(self):
        svg = open(os.path.join(REPO, "docs", "assets", "phantom-technologies-wordmark.svg"), encoding="utf-8").read()
        self.assertTrue(svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"'))
        self.assertIn('fill="currentColor"', svg)
        self.assertIn('aria-label="Phantom Technologies"', svg)
        self.assertIn("<title>Phantom Technologies</title>", svg)
        self.assertIn("Original squared lettering", svg)   # filled paths, nothing loaded at runtime
        self.assertNotIn("DejaVu", svg)
        self.assertNotRegex(svg, r'(?i)<script|<text|<image|href=|\bon[a-z]+=|font|gradient|filter=')
        w, h = map(float, re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg).groups())
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        ratio = float(re.search(r"\.ptw\{[^}]*aspect-ratio:([\d.]+)", css).group(1))
        self.assertAlmostEqual(w / h, ratio, delta=0.01)
        self.assertGreater(w / h, 3.2)    # wide and low, not the old single-line strip
        self.assertLess(w / h, 6.0)
        phantom = re.search(r'id="phantom" d="([^"]*)"', svg).group(1)
        tech = re.search(r'id="technologies" d="([^"]*)"', svg).group(1)
        pg, tg = _clusters(phantom), _clusters(tech)
        self.assertEqual(len(pg), 7)      # PHANTOM
        self.assertEqual(len(tg), 12)     # TECHNOLOGIES
        self.assertLess(max(g[3] for g in pg), min(g[1] for g in tg))   # second line sits below
        ph, th = max(g[3] for g in pg) - min(g[1] for g in pg), max(g[3] for g in tg) - min(g[1] for g in tg)
        self.assertLess(th, ph * 0.7)
        self.assertGreater(th, ph * 0.4)
        pw = max(g[2] for g in pg) - min(g[0] for g in pg)
        tw = max(g[2] for g in tg) - min(g[0] for g in tg)
        self.assertAlmostEqual(pw, tw, delta=pw * 0.04)   # tracked line matches the width
        self.assertGreater(_gap_ratio(tg), _gap_ratio(pg) + 0.25)   # TECHNOLOGIES is letter-spaced
        rule = re.search(r"(?<![\w.-])\.ptw\{[^}]*\}", css).group(0)
        self.assertIn("color:var(--t)", rule)
        self.assertNotIn("gradient", rule)
        self.assertIn(".ptw{display:inline-block;height:34px;", css)
        self.assertNotIn(".sptw{", css)
        self.assertIn(".swm{height:22px;", css)
        self.assertNotIn(".hlegal{display:none}", css)
        self.assertIn("@media(max-width:380px){.hlegal.ptw{height:26px}}", css)
        self.assertIn("mask:url(/static/phantom-technologies-wordmark.svg)", css)
        self.assertIn("phantom-technologies-wordmark.svg", pmc.STATIC_FILES)
        self.assertIn("docs/assets/phantom-technologies-wordmark.svg", open(os.path.join(REPO, "debian", "rules"), encoding="utf-8").read())
        self.assertIn("static/phantom-technologies-wordmark.svg", open(os.path.join(REPO, ".github", "workflows", "build.yml")).read())

    def test_svg_asset(self):
        svg = open(os.path.join(REPO, "docs", "assets", "mirage-wordmark.svg"), encoding="utf-8").read()
        self.assertTrue(svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"'))
        self.assertIn('fill="currentColor"', svg)
        self.assertNotRegex(svg, r'(?i)<script|<text|<image|href=|\bon[a-z]+=|font')
        self.assertIn("mirage-wordmark.svg", pmc.STATIC_FILES)
        self.assertIn("docs/assets/mirage-wordmark.svg", open(os.path.join(REPO, "debian", "rules"), encoding="utf-8").read())
        self.assertIn("static/mirage-wordmark.svg", open(os.path.join(REPO, ".github", "workflows", "build.yml")).read())

    def test_black_tile(self):
        css = open(os.path.join(STATIC, "console.css"), encoding="utf-8").read()
        self.assertIn(".ptile{display:inline-flex;background:#000;", css)
        self.assertNotRegex(css, r'\[data-theme=[a-z]+\][^{]*\.ptile')   # same black tile in both themes
        with open(os.path.join(REPO, "docs", "assets", "phantom-mirage-mark-dark.png"), "rb") as f:
            self.assertEqual(f.read(8), b"\x89PNG\r\n\x1a\n")
        rules = open(os.path.join(REPO, "debian", "rules"), encoding="utf-8").read()
        self.assertIn("docs/assets/phantom-mirage-mark-dark.png", rules)
        self.assertIn("static/phantom-mirage-mark-dark.png", open(os.path.join(REPO, ".github", "workflows", "build.yml")).read())


if __name__ == "__main__":
    unittest.main()
