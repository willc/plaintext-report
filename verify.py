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

MIN_HTML_BYTES = 4000
MIN_SECTIONS = 5
MIN_HEADLINES = 15

REQUIRED = [
    "index.html",
    "index.txt",
    "feed.xml",
    "style.css",
    "prefs.js",
    ".htaccess",
    "robots.txt",
    ".well-known/security.txt",
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


def verify(root):
    c = Checker(root)

    for name in REQUIRED:
        if not c.check(os.path.isfile(os.path.join(root, name)),
                       f"missing required file: {name}"):
            return c

    html = c.read("index.html")

    # Substance. An empty-but-valid page is the failure mode that looks fine.
    c.check(len(html.encode()) >= MIN_HTML_BYTES,
            f"index.html is only {len(html.encode())} bytes; expected >= {MIN_HTML_BYTES}")
    sections = html.count("<section>")
    c.check(sections >= MIN_SECTIONS,
            f"only {sections} sections; expected >= {MIN_SECTIONS}")
    headlines = html.count("</li>")
    c.check(headlines >= MIN_HEADLINES,
            f"only {headlines} headlines; expected >= {MIN_HEADLINES}")
    c.check("No items in this window." not in html,
            "index.html rendered the empty-window placeholder")

    # Structure.
    c.check(html.startswith("<!DOCTYPE html>"), "index.html has no doctype")
    c.check(html.rstrip().endswith("</html>"), "index.html is truncated")
    c.check('<main id="feeds">' in html, "missing the #feeds container")
    c.check("</main>" in html, "unclosed <main>")

    # Nothing unexpected executes. The page is allowed exactly prefs.js plus
    # the Plausible pair, and no inline handlers at all.
    scripts = re.findall(r'<script(?:\s[^>]*)?>', html)
    c.check(len(scripts) <= 3, f"{len(scripts)} script tags; expected at most 3")
    c.check('src="prefs.js"' in html, "prefs.js is not loaded")
    c.check("plausible.io" not in html, "public Plausible CDN must never be used")
    for pattern in ("onclick=", "onerror=", "onload=", "javascript:"):
        c.check(pattern not in html, f"inline handler or javascript: URL found: {pattern}")

    # Every plain-text window the page offers has to exist, or the link 404s.
    offered = set(re.findall(r'data-opt="hours" data-value="([^"]+)"', html))
    c.check(bool(offered), "no window choices rendered")
    for choice in offered:
        name = "index.txt" if choice == "24" else (
            "index-all.txt" if choice == "all" else f"index-{choice}h.txt")
        c.check(os.path.isfile(os.path.join(root, name)),
                f"window '{choice}' is offered but {name} was not written")

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

    # Feed has to parse, or every subscriber sees an error.
    try:
        root_el = ET.fromstring(c.read("feed.xml"))
        items = root_el.findall("./channel/item")
        c.check(len(items) >= MIN_HEADLINES,
                f"feed.xml has only {len(items)} items")
    except ET.ParseError as exc:
        c.check(False, f"feed.xml is not well-formed: {exc}")

    # Plain text must stay plain.
    txt = c.read("index.txt")
    c.check("<" not in txt, "index.txt contains markup")
    c.check(len(txt) > 200, "index.txt is suspiciously short")

    security = c.read(".well-known/security.txt")
    c.check("Contact:" in security and "Expires:" in security,
            "security.txt is missing required fields")

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
