#!/usr/bin/env python3
"""Assert a built dist/ is fit to publish. Run before every upload.

This exists because a build script that succeeds is not the same thing as a
build that produced a usable site. Every check here is something that has
either already gone wrong once or would ship silently broken.

    python verify.py dist

Exits non-zero with a list of failures. If this fails, do not deploy.
"""

import os
import re
import sys
import xml.etree.ElementTree as ET

# Per page, because the CVE page draws on four sources and the front page on
# eighteen. One shared threshold would either be meaningless on one page or
# impossible on the other.
PAGES = [
    {"slug": "index", "rss": "feed.xml",
     "min_bytes": 4000, "min_sections": 5, "min_headlines": 15},
    {"slug": "cve", "rss": "cve.xml",
     "min_bytes": 2000, "min_sections": 1, "min_headlines": 10},
]

# A real tag, as opposed to a bare "<" that is just a version range.
MARKUP = re.compile(r"<[/!]?[a-zA-Z][^>]*>")

REQUIRED = [
    "index.html",
    "index.txt",
    "feed.xml",
    "cve.html",
    "cve.txt",
    "cve.xml",
    "style.css",
    "prefs.js",
    ".htaccess",
    "robots.txt",
    ".well-known/security.txt",
    "favicon.svg",
    "favicon.ico",
]


class Checker:
    def __init__(self, root):
        self.root = root
        self.failures = []
        self.checks = 0

    def check(self, condition, message):
        self.checks += 1
        if not condition:
            self.failures.append(message)
        return bool(condition)

    def read(self, name):
        with open(os.path.join(self.root, name), encoding="utf-8") as f:
            return f.read()


def check_page(c, root, spec):
    """Everything that must be true of one rendered page."""
    slug = spec["slug"]
    name = f"{slug}.html"
    html = c.read(name)

    # Substance. An empty-but-valid page is the failure mode that looks fine.
    size = len(html.encode())
    c.check(size >= spec["min_bytes"],
            f"{name} is only {size} bytes; expected >= {spec['min_bytes']}")
    sections = html.count("<section>")
    c.check(sections >= spec["min_sections"],
            f"{name} has {sections} sections; expected >= {spec['min_sections']}")
    headlines = html.count("</li>")
    c.check(headlines >= spec["min_headlines"],
            f"{name} has {headlines} headlines; expected >= {spec['min_headlines']}")
    c.check("No items in this window." not in html,
            f"{name} rendered the empty-window placeholder")

    # Structure.
    c.check(html.startswith("<!DOCTYPE html>"), f"{name} has no doctype")
    c.check(html.rstrip().endswith("</html>"), f"{name} is truncated")
    c.check('<main id="feeds">' in html, f"{name} is missing the #feeds container")
    c.check("</main>" in html, f"{name} has an unclosed <main>")
    c.check(f'data-txt="{slug}"' in html,
            f"{name} does not declare its plain-text family")

    # Nothing unexpected executes.
    scripts = re.findall(r'<script(?:\s[^>]*)?>', html)
    c.check(len(scripts) <= 3, f"{name} has {len(scripts)} script tags; expected <= 3")
    c.check('src="prefs.js"' in html, f"{name} does not load prefs.js")
    c.check("plausible.io" not in html, f"{name} uses the public Plausible CDN")
    for pattern in ("onclick=", "onerror=", "onload=", "javascript:"):
        c.check(pattern not in html, f"{name} contains {pattern}")

    c.check('rel="icon"' in html, f"{name} does not reference the favicon")

    # Every plain-text window the page offers has to exist, or the link 404s.
    offered = set(re.findall(r'data-opt="hours" data-value="([^"]+)"', html))
    c.check(bool(offered), f"{name} rendered no window choices")
    for choice in offered:
        txt = f"{slug}.txt" if choice == "24" else (
            f"{slug}-all.txt" if choice == "all" else f"{slug}-{choice}h.txt")
        c.check(os.path.isfile(os.path.join(root, txt)),
                f"{name} offers window '{choice}' but {txt} was not written")

    # Feed has to parse, or every subscriber sees an error.
    try:
        root_el = ET.fromstring(c.read(spec["rss"]))
        items = root_el.findall("./channel/item")
        c.check(len(items) >= spec["min_headlines"],
                f"{spec['rss']} has only {len(items)} items")
    except ET.ParseError as exc:
        c.check(False, f"{spec['rss']} is not well-formed: {exc}")

    # Plain text must stay plain. A bare "<" is not evidence of that: CVE
    # headlines routinely carry version ranges like "N-central < 2026.3", and
    # rejecting those blocked every deploy for hours. Only a real tag means
    # the renderer leaked markup.
    txt = c.read(f"{slug}.txt")
    tags = MARKUP.findall(txt)
    c.check(not tags, f"{slug}.txt contains markup: {tags[:3]}")
    c.check(len(txt) > 200, f"{slug}.txt is suspiciously short")

    return html


def verify(root):
    c = Checker(root)

    for name in REQUIRED:
        if not c.check(os.path.isfile(os.path.join(root, name)),
                       f"missing required file: {name}"):
            return c

    pages = {spec["slug"]: check_page(c, root, spec) for spec in PAGES}
    html = pages["index"]

    # The two pages must actually link to each other, or one is orphaned.
    c.check('href="cve.html"' in pages["index"], "index.html does not link to /cve")
    c.check('href="index.html"' in pages["cve"], "cve.html does not link home")

    # Security headers.
    htaccess = c.read(".htaccess")
    for header in ("Content-Security-Policy", "Strict-Transport-Security",
                   "X-Content-Type-Options", "Referrer-Policy"):
        c.check(header in htaccess, f".htaccess is missing {header}")
    c.check("unsafe-inline" not in htaccess, "CSP contains unsafe-inline")
    c.check("unsafe-eval" not in htaccess, "CSP contains unsafe-eval")

    # The CSP hash has to match the inline script that actually shipped, or
    # the browser silently refuses to run it.
    inline = re.search(r"<script>(.*?)</script>", html, re.S)
    if c.check(inline is not None, "no inline analytics block found"):
        import base64
        import hashlib
        digest = hashlib.sha256(inline.group(1).encode()).digest()
        expected = "'sha256-" + base64.b64encode(digest).decode() + "'"
        c.check(expected in htaccess,
                f"CSP script hash does not match the shipped inline script ({expected})")

    security = c.read(".well-known/security.txt")
    c.check("Contact:" in security and "Expires:" in security,
            "security.txt is missing required fields")

    # A favicon that is a valid file but not a valid image still 404s in
    # spirit: the browser just shows nothing. Check the magic bytes.
    with open(os.path.join(root, "favicon.ico"), "rb") as f:
        ico = f.read()
    c.check(ico[:4] == b"\x00\x00\x01\x00", "favicon.ico is not an ICO container")
    c.check(b"\x89PNG\r\n\x1a\n" in ico[:32], "favicon.ico has no PNG payload")
    c.check(len(ico) > 100, "favicon.ico is suspiciously small")

    svg = c.read("favicon.svg")
    c.check(svg.startswith("<svg"), "favicon.svg is not an SVG")
    c.check("<script" not in svg, "favicon.svg contains a script")

    return c


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "dist"
    if not os.path.isdir(root):
        print(f"FAIL: {root} is not a directory", file=sys.stderr)
        return 1

    c = verify(root)
    for failure in c.failures:
        print(f"FAIL: {failure}", file=sys.stderr)

    if c.failures:
        print(f"\n{len(c.failures)} of {c.checks} checks failed. Do not deploy.",
              file=sys.stderr)
        return 1

    print(f"OK: {c.checks} checks passed on {root}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
