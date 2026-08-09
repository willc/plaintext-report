#!/usr/bin/env python3
"""
PLAINTEXT REPORT (plaintext.report)
A static security-news aggregator. No JS, no tracking, no ads. Just headlines.

    python plaintext.py --out-dir dist

Writes index.html, index.txt and feed.xml. Keeps a state file so a feed that
fails a run degrades to "stale" instead of silently vanishing from the page.
"""

import argparse
import base64
import calendar
import concurrent.futures
import datetime as dt
import hashlib
import html
import json
import os
import re
import socket
import sys
import time
from email.utils import format_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import feedparser

from feeds import FEEDS, SOURCE_LIMITS, USER_AGENT

SOCKET_TIMEOUT = 20
MAX_WORKERS = 6

# How much history to keep per feed in the state file. The window filter does
# the real work; this just has to outlast a plausible outage.
CACHE_MAX_ITEMS = 200
CACHE_MAX_AGE_DAYS = 14

# Tracking junk to strip before comparing URLs for duplicates.
TRACKING_PREFIXES = ("utm_", "mtm_", "pk_")
TRACKING_KEYS = {
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source", "src",
    "at_medium", "at_campaign", "__twitter_impression", "guccounter",
}


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def to_utc(struct_time):
    """feedparser returns UTC struct_times. calendar.timegm reads them as UTC;
    time.mktime would read them as local time and skew every timestamp by the
    host's offset."""
    if not struct_time:
        return None
    return dt.datetime.fromtimestamp(calendar.timegm(struct_time), tz=dt.timezone.utc)


def is_safe_link(url):
    """Only http(s) links get rendered.

    Escaping a href does not neutralize `javascript:` or `data:` URLs. Feeds
    are third-party input and some of these publishers have been compromised
    before, so the scheme is allow-listed rather than filtered.
    """
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return False
    return scheme in ("http", "https")


# SANS ISC appends its own date to every headline, e.g.
# "Linux Shell Forensics, (Fri, Aug 7th)". We already show an age, so the
# suffix is duplicate information that pushes real titles onto a second line.
TRAILING_DATE = re.compile(
    r",?\s*\((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+"
    r"\d{1,2}(?:st|nd|rd|th)?\)\s*$",
    re.IGNORECASE,
)


def clean_title(title):
    return TRAILING_DATE.sub("", title).strip().rstrip(",").strip()


def entry_items(parsed):
    out = []
    for e in parsed.entries:
        title = clean_title(html.unescape((e.get("title") or "").strip()))
        link = (e.get("link") or "").strip()
        if not title or not link or not is_safe_link(link):
            continue
        ts = to_utc(e.get("published_parsed") or e.get("updated_parsed"))
        out.append({
            "title": title,
            "link": link,
            "ts": ts.isoformat() if ts else None,
        })
    return out


RETRY_STATUSES = (429, 500, 502, 503, 504)
RETRY_BACKOFF = 8  # seconds


def fetch_one(name, url, cached):
    """Returns (name, payload). payload['status'] is one of:
    fresh (200 with content), unchanged (304), failed (anything else).
    """
    prev = cached or {}
    kwargs = {"agent": USER_AGENT}
    if prev.get("etag"):
        kwargs["etag"] = prev["etag"]
    if prev.get("modified"):
        kwargs["modified"] = prev["modified"]

    for attempt in range(2):
        try:
            parsed = feedparser.parse(url, **kwargs)
        except Exception as exc:  # noqa: BLE001 - one bad feed must not kill the run
            return name, {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
        # Reddit in particular throttles hard; one backed-off retry is worth it.
        if parsed.get("status") in RETRY_STATUSES and attempt == 0:
            time.sleep(RETRY_BACKOFF)
            continue
        break

    http_status = parsed.get("status")

    if http_status == 304:
        return name, {"status": "unchanged"}

    if http_status is not None and http_status >= 400:
        return name, {"status": "failed", "error": f"HTTP {http_status}"}

    items = entry_items(parsed)
    if not items:
        reason = str(parsed.get("bozo_exception") or "no usable entries")[:160]
        return name, {"status": "failed", "error": reason}

    return name, {
        "status": "fresh",
        "items": items,
        "etag": parsed.get("etag"),
        "modified": parsed.get("modified"),
        "final_url": parsed.get("href"),
    }


def fetch_all(feeds, state):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetch_one, name, url, state.get("feeds", {}).get(name)): name
            for name, url in feeds.items()
        }
        for fut in concurrent.futures.as_completed(futures):
            name, payload = fut.result()
            results[name] = payload
    return results


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        return {"feeds": {}}
    if not isinstance(state, dict) or "feeds" not in state:
        return {"feeds": {}}
    return state


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def merge_items(old, new, now):
    """Union of cached and freshly fetched items, keyed by link. Prevents a
    feed that truncates to 5 entries from wiping older items still inside the
    display window."""
    by_link = {}
    for item in list(old or []) + list(new or []):
        link = item.get("link")
        if link:
            by_link[link] = item

    horizon = now - dt.timedelta(days=CACHE_MAX_AGE_DAYS)
    kept = []
    for item in by_link.values():
        ts = parse_ts(item.get("ts"))
        if ts is None or ts >= horizon:
            kept.append(item)

    kept.sort(key=lambda i: parse_ts(i.get("ts")) or now, reverse=True)
    return kept[:CACHE_MAX_ITEMS]


def parse_ts(value):
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def apply_results(state, results, feeds, now):
    """Fold fetch results into state. Returns per-feed report dicts."""
    report = {}
    feed_state = state.setdefault("feeds", {})

    for name, url in feeds.items():
        payload = results.get(name, {"status": "failed", "error": "not fetched"})
        prev = feed_state.get(name, {})
        entry = dict(prev)
        entry["url"] = url

        if payload["status"] == "fresh":
            entry["items"] = merge_items(prev.get("items"), payload["items"], now)
            entry["etag"] = payload.get("etag")
            entry["modified"] = payload.get("modified")
            entry["last_success"] = now.isoformat()
            entry.pop("error", None)
        elif payload["status"] == "unchanged":
            entry["items"] = merge_items(prev.get("items"), [], now)
            entry["last_success"] = now.isoformat()
            entry.pop("error", None)
        else:
            entry["items"] = merge_items(prev.get("items"), [], now)
            entry["error"] = payload.get("error", "unknown")

        feed_state[name] = entry

        last_success = parse_ts(entry.get("last_success"))
        report[name] = {
            "status": payload["status"],
            "error": payload.get("error"),
            "cached": len(entry.get("items") or []),
            "stale_hours": (
                None if last_success is None
                else round((now - last_success).total_seconds() / 3600, 1)
            ),
            "never_succeeded": last_success is None,
        }

    # Drop feeds no longer in the roster so state doesn't grow forever.
    for name in list(feed_state):
        if name not in feeds:
            del feed_state[name]

    return report


# --------------------------------------------------------------------------
# selection
# --------------------------------------------------------------------------

def canonical_link(url):
    """Normalize for duplicate detection only. Never used for display."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    query = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith(TRACKING_PREFIXES) and k.lower() not in TRACKING_KEYS
    ]
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), host, path, urlencode(query), ""))


def select(state, feeds, hours, limit, now):
    """Build the display sections. Deduplicates by canonical URL across the
    whole page, first source in roster order wins.

    Deliberately does not merge near-identical headlines from different
    outlets: two sites covering one story independently is signal, not noise,
    and fuzzy title matching would suppress real coverage.
    """
    cutoff = now - dt.timedelta(hours=hours)
    seen = set()
    sections = []

    for name in feeds:
        entry = state.get("feeds", {}).get(name, {})
        fresh = []
        for item in entry.get("items") or []:
            ts = parse_ts(item.get("ts"))
            if ts is not None and ts < cutoff:
                continue
            key = canonical_link(item["link"])
            if key in seen:
                continue
            seen.add(key)
            # Also cleaned here, not just at ingest, so items already sitting
            # in the cache pick up the fix without waiting to be refetched.
            fresh.append({
                "title": clean_title(item["title"]),
                "link": item["link"],
                "ts": ts,
            })

        fresh.sort(key=lambda i: i["ts"] or now, reverse=True)
        fresh = fresh[:min(limit, SOURCE_LIMITS.get(name, limit))]
        if not fresh:
            continue

        last_success = parse_ts(entry.get("last_success"))
        stale_h = (
            None if last_success is None
            else (now - last_success).total_seconds() / 3600
        )
        sections.append({
            "name": name,
            "items": fresh,
            "stale": bool(entry.get("error")),
            "stale_hours": stale_h,
        })

    return sections


def age_label(ts, now):
    if ts is None:
        return ""
    seconds = (now - ts).total_seconds()
    if seconds < 0:
        return "now"
    hours = seconds / 3600
    if hours < 1:
        return f"{int(seconds // 60)}m"
    if hours < 24:
        return f"{int(hours)}h"
    return f"{int(hours // 24)}d"


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

CSS = """
:root {
  color-scheme: light dark;
  --fg: #111;
  --bg: #fff;
  --dim: #595959;
  --rule: #ccc;
}
/* System preference, only while the reader has not chosen explicitly. */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme]) {
    color-scheme: dark;
    --fg: #e6e6e6; --bg: #111; --dim: #9e9e9e; --rule: #444;
  }
}
/* An explicit choice always wins, in both directions. */
:root[data-theme="dark"] {
  color-scheme: dark;
  --fg: #e6e6e6; --bg: #111; --dim: #9e9e9e; --rule: #444;
}
:root[data-theme="light"] {
  color-scheme: light;
  --fg: #111; --bg: #fff; --dim: #595959; --rule: #ccc;
}
* { box-sizing: border-box; }
body {
  max-width: 1500px;
  margin: 2rem auto;
  padding: 0 1rem;
  background: var(--bg);
  color: var(--fg);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 15px;
  line-height: 1.5;
}
/* Prose stays at a readable measure even when the columns spread wide. */
header, footer { max-width: 62rem; }
header { margin-bottom: 2rem; }
h1 { font-size: 1.4rem; margin: 0 0 0.25rem 0; letter-spacing: 0.08em; }
.sub { color: var(--dim); font-size: 0.85rem; }
nav { margin-top: 0.75rem; font-size: 0.85rem; }
nav a { color: var(--dim); margin-right: 0.75rem; }
section { margin-bottom: 1.75rem; }
h2 {
  font-size: 0.95rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  border-bottom: 1px solid var(--rule);
  padding-bottom: 0.25rem;
  margin: 0 0 0.5rem 0;
}
ul { list-style: square; margin: 0; padding-left: 1.15rem; }
li { margin: 0.3rem 0; padding-left: 0.15rem; }
li::marker { color: var(--dim); }
a { color: inherit; text-decoration: none; }
a:hover, a:focus { text-decoration: underline; }
a:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
.age { color: var(--dim); font-size: 0.8rem; white-space: nowrap; }
.stale { color: var(--dim); font-size: 0.75rem; text-transform: none; letter-spacing: 0; }
footer { margin-top: 2.5rem; padding-top: 0.75rem; border-top: 1px solid var(--rule);
         color: var(--dim); font-size: 0.8rem; }
footer a { text-decoration: underline; }

/* Columns follow the window. A column-width rather than a column-count lets
   the browser decide how many fit, so there is nothing to configure and
   nothing to get wrong: one column on a phone, four on a wide desktop.
   Sections are kept whole rather than split across a column break. */
#feeds {
  columns: 26rem;
  column-gap: 2.5rem;
}
#feeds section { break-inside: avoid; page-break-inside: avoid; }

/* Controls are useless without scripting, so they stay hidden until the
   preferences script has run and proved it can act on them. */
.controls { display: none; }
.js .controls {
  display: flex;
  flex-wrap: wrap;
  /* Generous column gap: the groups have to read as separate menus, not as
     one run-on line where "dark" sits next to "6h". */
  gap: 0.6rem 3rem;
  align-items: center;
  margin-top: 0.9rem;
  padding: 0.6rem 0;
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
  font-size: 0.8rem;
  color: var(--dim);
}
.ctl { margin: 0; }
/* Inside a group, ordinary word spacing only: the single spaces already in
   the markup. All the separation lives in the gap between groups, so a group
   reads as one menu rather than as loose words. */
.ctl-label { color: var(--dim); }
.sep { color: var(--rule); }
/* Buttons, for the semantics, wearing plain text. */
.controls button {
  font: inherit;
  font-size: 0.8rem;
  color: var(--fg);
  background: none;
  border: 0;
  border-radius: 0;
  padding: 0;
  margin: 0;
  cursor: pointer;
  text-decoration: none;
}
.controls button:hover { text-decoration: underline; }
.controls button[aria-pressed="true"] {
  font-weight: 700;
  text-decoration: underline;
}
.controls button:focus-visible {
  outline: 2px solid currentColor;
  outline-offset: 2px;
}
#opt-reset { color: var(--dim); }
"""

SITE_NAME = "PLAINTEXT REPORT"
TAGLINE = "Security headlines. Nothing else."

# Self-hosted Plausible. Cookieless, no cross-site identifiers, and the stats
# box is Will's own, so no third party ever sees a request.
ANALYTICS_HOST = "https://stats.intergalacticstuff.com"
ANALYTICS_SRC = f"{ANALYTICS_HOST}/js/pa-u9cXdpYOH9-7ZkOlL7_kx.js"
ANALYTICS_INLINE = (
    "window.plausible=window.plausible||function(){(plausible.q=plausible.q||[])"
    ".push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};"
    "plausible.init()"
)


# Reader preferences. Same-origin file rather than an inline block, so the
# markup stays readable and the CSP needs no extra hash. Everything lives in
# localStorage: no cookies, nothing leaves the browser.
PREFS_JS_TEMPLATE = """/* PLAINTEXT reader preferences. No cookies, no network, no tracking.
   Choices are stored in this browser's localStorage and never transmitted. */
(function () {
  var root = document.documentElement;
  /* Column count is not in here on purpose: the stylesheet derives it from
     the window width, so there is no preference to store or restore. */
  var KEYS = { theme: 'pt-theme', limit: 'pt-limit', hours: 'pt-hours' };
  var DEFAULTS = { theme: 'auto', limit: '__LIMIT__', hours: '__HOURS__' };

  function get(name) {
    try {
      return localStorage.getItem(KEYS[name]) || DEFAULTS[name];
    } catch (e) {
      return DEFAULTS[name];
    }
  }

  function set(name, value) {
    try {
      if (value === DEFAULTS[name]) { localStorage.removeItem(KEYS[name]); }
      else { localStorage.setItem(KEYS[name], value); }
    } catch (e) { /* private mode; preferences just won't persist */ }
  }

  /* Theme is applied immediately, before first paint, to avoid a flash. */
  function applyTheme() {
    var value = get('theme');
    if (value === 'auto') { root.removeAttribute('data-theme'); }
    else { root.setAttribute('data-theme', value); }
  }
  applyTheme();

  function applyFilters() {
    var limit = get('limit');
    var hours = get('hours');
    var maxItems = limit === 'all' ? Infinity : parseInt(limit, 10);
    var maxAge = hours === 'all' ? Infinity : parseFloat(hours);
    var sections = document.querySelectorAll('#feeds section');
    var live = 0;

    for (var i = 0; i < sections.length; i++) {
      var items = sections[i].getElementsByTagName('li');
      var shown = 0;
      for (var j = 0; j < items.length; j++) {
        var age = parseFloat(items[j].getAttribute('data-age'));
        /* Items are rendered newest first, so a running count is the limit. */
        var visible = (isNaN(age) || age <= maxAge) && shown < maxItems;
        items[j].hidden = !visible;
        if (visible) { shown++; }
      }
      sections[i].hidden = shown === 0;
      if (shown > 0) { live++; }
    }

    var count = document.getElementById('shown-count');
    if (count) { count.textContent = String(live); }
  }

  /* The plain-text page is generated per window. Point at the file matching
     the reader's chosen window, so widening it here and then clicking through
     does not silently drop sources. */
  function applyTxtLinks() {
    var hours = get('hours');
    var href;
    if (hours === 'all') { href = 'index-all.txt'; }
    else if (hours === DEFAULTS.hours) { href = 'index.txt'; }
    else { href = 'index-' + hours + 'h.txt'; }
    var links = document.getElementsByClassName('txt-link');
    for (var i = 0; i < links.length; i++) {
      links[i].setAttribute('href', href);
    }
  }

  function markPressed() {
    var buttons = document.querySelectorAll('.controls button[data-opt]');
    for (var i = 0; i < buttons.length; i++) {
      var key = buttons[i].getAttribute('data-opt');
      var on = buttons[i].getAttribute('data-value') === get(key);
      buttons[i].setAttribute('aria-pressed', on ? 'true' : 'false');
    }
  }

  function apply() {
    applyTheme();
    applyFilters();
    applyTxtLinks();
    markPressed();
  }

  function wire() {
    root.className += ' js';

    var bar = document.querySelector('.controls');
    if (bar) {
      /* One delegated handler rather than one per button. */
      bar.addEventListener('click', function (event) {
        var button = event.target.closest ? event.target.closest('button') : null;
        if (!button) { return; }
        var key = button.getAttribute('data-opt');
        if (key) {
          set(key, button.getAttribute('data-value'));
          apply();
        }
      });
    }

    var reset = document.getElementById('opt-reset');
    if (reset) {
      reset.addEventListener('click', function () {
        for (var key in KEYS) {
          try { localStorage.removeItem(KEYS[key]); } catch (e) {}
        }
        apply();
      });
    }

    apply();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})();
"""


def inline_script_hash(source=ANALYTICS_INLINE):
    """CSP source expression for the inline init block.

    Derived from the script text at build time so the policy and the page can
    never drift apart. Hashing beats 'unsafe-inline': if the snippet is ever
    tampered with, the browser refuses to run it.
    """
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def content_security_policy():
    return "; ".join([
        "default-src 'none'",
        "style-src 'self'",
        f"script-src 'self' {ANALYTICS_HOST} {inline_script_hash()}",
        f"connect-src {ANALYTICS_HOST}",
        "img-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ])


def join_names(names):
    names = sorted(names)
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} and {names[1]}"
    return ", ".join(names[:-1]) + f", and {names[-1]}"


def cached_note(failed_names):
    """Phrased as routine housekeeping, not an alarm.

    A feed timing out is normal and the page is still complete, so this
    belongs in the footer with the other provenance notes rather than up top
    where it reads like an outage banner.
    """
    if not failed_names:
        return ""
    listed = html.escape(join_names(failed_names))
    return (f"Status: {listed} did not respond on the last run, so those "
            f"headlines come from the most recent successful fetch.")


def stale_note(section):
    if not section["stale"]:
        return ""
    if section["stale_hours"] is None:
        return "unreachable"
    h = section["stale_hours"]
    return f"stale, last reached {int(h)}h ago" if h >= 1 else "stale"


def window_choices(max_hours, default_hours=24):
    """Windows a reader may pick, never wider than what was actually rendered.
    The default is always offered, so a reader can get back to it."""
    windows = [h for h in (6, 12, 24, 48, 72) if h <= max_hours]
    for extra in (default_hours, max_hours):
        if extra <= max_hours and extra not in windows:
            windows.append(extra)
    return sorted(windows)


def render_prefs_js(default_hours, default_limit):
    """The script's defaults must match what the build actually produced, or
    the plain-text link points at a file that was never written."""
    return (PREFS_JS_TEMPLATE
            .replace("__HOURS__", str(default_hours))
            .replace("__LIMIT__", str(default_limit)))


def txt_filename(hours, default_hours):
    """Per-window plain-text files, so widening the window on the page and
    then clicking through does not drop sources. The default window keeps the
    plain `index.txt` name, since that is what no-JS readers land on."""
    if hours == "all":
        return "index-all.txt"
    if int(hours) == int(default_hours):
        return "index.txt"
    return f"index-{hours}h.txt"


def render_controls(max_hours, default_hours=24):
    """The preference bar: text choices separated by pipes.

    Buttons rather than links, because these act on the page instead of
    navigating, and a reader on a keyboard should get button semantics. They
    are styled to read as plain text. No <form> wraps them, so there is
    nothing to submit and form-action stays 'none'. CSS keeps the whole bar
    hidden until prefs.js adds .js to <html>, so a reader without scripting
    never sees a control that would do nothing.
    """
    def group(label, key, values, labels=None):
        parts = []
        for i, value in enumerate(values):
            text = labels[i] if labels else value
            parts.append(
                f'<button type="button" data-opt="{key}" data-value="{value}">'
                f'{text}</button>'
            )
        joined = ' <span class="sep">|</span> '.join(parts)
        return f'    <p class="ctl"><span class="ctl-label">{label}</span> {joined}</p>'

    windows = window_choices(max_hours, default_hours)
    lines = [
        '  <div class="controls">',
        group("theme", "theme", ["auto", "light", "dark"]),
        group("window", "hours",
              [str(h) for h in windows] + ["all"],
              [f"{h}h" for h in windows] + ["all"]),
        group("per source", "limit", ["5", "10", "15", "25", "all"]),
        '    <p class="ctl"><button type="button" id="opt-reset">reset</button></p>',
        '  </div>',
    ]
    return "\n".join(lines)


def render_html(sections, feeds, hours, now, failed_names, analytics=True,
                default_hours=24):
    """Emit indented, one-element-per-line HTML.

    The whole pitch of this site is that there is nothing hiding in it, so
    View Source has to back that up: no minification, no inline <style>, no
    scripts, one headline per line. The CSS lives in style.css so the markup
    a reader sees is content and nothing else.
    """
    out = []
    add = out.append

    add('<!DOCTYPE html>')
    add('<html lang="en">')
    add('<head>')
    add('<meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add(f'<title>{html.escape(SITE_NAME)}</title>')
    add(f'<meta name="description" content="{html.escape(TAGLINE, quote=True)} '
        f'An ad-free, tracker-free aggregator of {len(feeds)} security news sources.">')
    add('<link rel="icon" href="favicon.svg" type="image/svg+xml">')
    add('<link rel="alternate icon" href="favicon.ico" sizes="32x32">')
    add('<link rel="stylesheet" href="style.css">')
    add(f'<link rel="alternate" type="application/rss+xml" '
        f'title="{html.escape(SITE_NAME, quote=True)}" href="feed.xml">')
    add('<script src="prefs.js"></script>')
    add('</head>')
    add('')
    add('<body>')
    add('')
    add('<header>')
    add(f'  <h1>{html.escape(SITE_NAME)}</h1>')
    add(f'  <p class="sub">{html.escape(TAGLINE)} '
        f'Updated {now.strftime("%A, %B %d, %Y %H:%M UTC")}. '
        f'Everything published in the last {hours}h.</p>')
    add('  <p class="nav">'
        '[<a class="txt-link" href="index.txt">plain text</a>] '
        '[<a href="feed.xml">rss</a>]</p>')
    add(render_controls(hours, default_hours))
    add('</header>')

    if not sections:
        add('')
        add('<p>No items in this window.</p>')

    add('')
    add('<main id="feeds">')

    for s in sections:
        note = stale_note(s)
        heading = html.escape(s["name"])
        if note:
            heading += f' <span class="stale">({html.escape(note)})</span>'
        add('')
        add('<section>')
        add(f'  <h2>{heading}</h2>')
        add('  <ul>')
        for item in s["items"]:
            age = age_label(item["ts"], now)
            age_html = f' <span class="age">[{age}]</span>' if age else ""
            hours_old = "" if item["ts"] is None else \
                f' data-age="{(now - item["ts"]).total_seconds() / 3600:.2f}"'
            add(f'    <li{hours_old}><a href="{html.escape(item["link"], quote=True)}">'
                f'{html.escape(item["title"])}</a>{age_html}</li>')
        add('  </ul>')
        add('</section>')

    add('')
    add('</main>')

    add('')
    add('<footer>')
    add(f'  <p><span id="shown-count">{len(sections)}</span> of {len(feeds)} '
        f'sources have items to show.</p>')
    add('  <p>No ads, no cookies, no third-party requests, no personal data.')
    add('  Headlines link straight to the publisher.')
    add('  <a href="https://github.com/willc/plaintext-report">Source</a>.</p>')
    add('  <p>Your display choices are kept in this browser only, in localStorage,')
    add('  and are never sent anywhere.')
    if analytics:
        add('  Visit counts come from a self-hosted Plausible instance and are')
        add('  anonymous and cookieless.')
    add('  Want zero scripts at all? Read the')
    add('  <a class="txt-link" href="index.txt">plain-text edition</a>.</p>')
    note = cached_note(failed_names)
    if note:
        add(f'  <p>{note}</p>')
    add('  <p>Inspired by <a href="https://brutalist.report/">brutalist.report</a>,')
    add('  but for infosec news. Proud supporter of the small web.</p>')
    add('  <p>An <a href="https://intergalacticrobots.app/">Intergalactic Robots</a>')
    add('  production.</p>')
    add('</footer>')

    if analytics:
        add('')
        add('<!-- Privacy-friendly analytics, self-hosted Plausible. -->')
        add(f'<script async src="{html.escape(ANALYTICS_SRC, quote=True)}"></script>')
        add(f'<script>{ANALYTICS_INLINE}</script>')

    add('')
    add('</body>')
    add('</html>')

    return "\n".join(out) + "\n"


def render_txt(sections, hours, now):
    window = "everything cached" if hours == "all" else f"the last {hours}h"
    lines = [
        SITE_NAME,
        TAGLINE,
        f"Updated {now.strftime('%Y-%m-%d %H:%M UTC')}. Showing {window}.",
        "",
    ]
    lines.append("Inspired by brutalist.report, but for infosec news. "
                 "Proud supporter of the small web.")
    lines.append("An Intergalactic Robots production. "
                 "https://intergalacticrobots.app/")
    lines.append("")

    for s in sections:
        note = stale_note(s)
        heading = s["name"].upper() + (f"  ({note})" if note else "")
        lines.append(heading)
        lines.append("-" * len(heading))
        for item in s["items"]:
            age = age_label(item["ts"], now)
            lines.append(f"  * [{age or '?'}] {item['title']}")
            lines.append(f"        {item['link']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_rss(sections, now, site_url, max_items=100):
    flat = []
    for s in sections:
        for item in s["items"]:
            flat.append((item, s["name"]))
    flat.sort(key=lambda pair: pair[0]["ts"] or now, reverse=True)
    flat = flat[:max_items]

    entries = []
    for item, source in flat:
        pub = ""
        if item["ts"]:
            pub = f"<pubDate>{format_datetime(item['ts'])}</pubDate>"
        title = f"{source}: {item['title']}"
        entries.append(
            "<item>"
            f"<title>{html.escape(title)}</title>"
            f"<link>{html.escape(item['link'], quote=True)}</link>"
            f"<guid isPermaLink=\"true\">{html.escape(item['link'], quote=True)}</guid>"
            f"<source url=\"{html.escape(site_url, quote=True)}/feed.xml\">"
            f"{html.escape(source)}</source>"
            f"{pub}"
            "</item>"
        )

    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<rss version="2.0"><channel>'
        f"<title>{html.escape(SITE_NAME)}</title>"
        f"<link>{html.escape(site_url, quote=True)}/</link>"
        f"<description>{html.escape(TAGLINE)}</description>"
        "<language>en</language>"
        f"<lastBuildDate>{format_datetime(now)}</lastBuildDate>"
        + "".join(entries)
        + "</channel></rss>\n"
    )


# The mark is three bars: lines of text, shrinking on the last one. It has to
# survive being drawn at 16 pixels, so there is no lettering and no detail.
FAVICON_BARS = (
    # (x, y, width, height) on a 32x32 grid
    (5, 8, 22, 4),
    (5, 15, 22, 4),
    (5, 22, 13, 4),
)
FAVICON_INK = (0x11, 0x11, 0x11, 0xFF)
FAVICON_PAPER = (0xFF, 0xFF, 0xFF, 0xFF)


def render_favicon_svg():
    bars = "\n".join(
        f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#111"/>'
        for x, y, w, h in FAVICON_BARS
    )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">\n'
        '  <rect width="32" height="32" fill="#fff"/>\n'
        f"{bars}\n"
        "</svg>\n"
    )


def _png(width, height, pixels):
    """Minimal RGBA PNG encoder. Avoids a Pillow dependency for one 32px icon."""
    import struct
    import zlib

    def chunk(tag, data):
        body = tag + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    raw = b"".join(
        b"\x00" + pixels[row * width * 4:(row + 1) * width * 4]
        for row in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def render_favicon_ico(size=32):
    """PNG-in-ICO. Every browser that still asks for favicon.ico accepts it."""
    import struct

    scale = size / 32
    grid = bytearray()
    for y in range(size):
        for x in range(size):
            ink = any(
                bx * scale <= x < (bx + bw) * scale
                and by * scale <= y < (by + bh) * scale
                for bx, by, bw, bh in FAVICON_BARS
            )
            grid.extend(FAVICON_INK if ink else FAVICON_PAPER)

    png = _png(size, size, bytes(grid))
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack(
        "<BBBBHHII",
        size if size < 256 else 0, size if size < 256 else 0,
        0, 0, 1, 32, len(png), len(header) + 16,
    )
    return header + entry + png


def render_robots(site_url):
    return (
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        "# There is no tracking here and nothing behind a login. Please be\n"
        "# gentle: this is one small box serving static files.\n"
        "Crawl-delay: 10\n"
        f"\nSitemap: {site_url}/feed.xml\n"
    )


def render_security_txt(now, contact="mailto:will@willchatham.com"):
    """RFC 9116. Expires is stamped a year out on every build, and the build
    runs every 30 minutes, so it can never quietly lapse."""
    expires = (now + dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"Contact: {contact}\n"
        f"Expires: {expires}\n"
        "Preferred-Languages: en\n"
        "Canonical: https://plaintext.report/.well-known/security.txt\n"
        "\n"
        "# This site is a static aggregator of public RSS feeds. It stores no\n"
        "# user data, sets no cookies, and has no accounts or login.\n"
        "# Source: https://github.com/willc/plaintext-report\n"
    )


def render_htaccess(analytics=True):
    """Generated, not hand-written, so the CSP script hash always matches the
    inline block that actually shipped in index.html."""
    if analytics:
        csp = content_security_policy()
    else:
        csp = "; ".join([
            "default-src 'none'", "style-src 'self'", "img-src 'self'",
            "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
        ])
    return f"""# Generated by plaintext.py. Do not edit by hand.
# The script-src hash is derived from the inline analytics snippet at build
# time; editing either one without the other will break the page.

<IfModule mod_headers.c>
  Header always set Content-Security-Policy "{csp}"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "no-referrer"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), interest-cohort=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"
</IfModule>

<IfModule mod_mime.c>
  AddType text/plain .txt
  AddType application/rss+xml .xml
  AddType image/svg+xml .svg
  AddType image/x-icon .ico
</IfModule>

<IfModule mod_expires.c>
  ExpiresActive On
  # The page itself is regenerated every 30 minutes; do not let it go stale.
  ExpiresByType text/html "access plus 5 minutes"
  ExpiresByType text/css "access plus 7 days"
  ExpiresByType image/svg+xml "access plus 30 days"
  ExpiresByType image/x-icon "access plus 30 days"
  ExpiresByType text/plain "access plus 5 minutes"
  ExpiresByType application/rss+xml "access plus 15 minutes"
</IfModule>

ServerSignature Off
Options -Indexes
"""


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hours", type=int, default=24,
                    help="window the page shows before the reader changes it")
    ap.add_argument("--limit", type=int, default=15,
                    help="items per source the page shows by default")
    # index.html carries a wider set than it displays, because the reader can
    # widen the window client-side. These are the ceilings for that.
    ap.add_argument("--max-hours", type=int, default=72,
                    help="widest window a reader can select on the page")
    ap.add_argument("--max-limit", type=int, default=25,
                    help="most items per source a reader can select")
    ap.add_argument("--out-dir", default="dist")
    ap.add_argument("--state", default="state.json")
    ap.add_argument("--site-url", default="https://plaintext.report")
    ap.add_argument("--offline", action="store_true",
                    help="render from cached state without fetching")
    ap.add_argument("--max-failures", type=int, default=6,
                    help="exit non-zero if more than this many feeds fail")
    ap.add_argument("--no-analytics", action="store_true",
                    help="omit the Plausible snippet (local dev, tests)")
    args = ap.parse_args()

    socket.setdefaulttimeout(SOCKET_TIMEOUT)
    now = dt.datetime.now(dt.timezone.utc)

    state = load_state(args.state)
    results = {} if args.offline else fetch_all(FEEDS, state)
    if args.offline:
        results = {name: {"status": "unchanged"} for name in FEEDS}

    report = apply_results(state, results, FEEDS, now)
    save_state(args.state, state)

    page_sections = select(state, FEEDS, args.max_hours, args.max_limit, now)
    failed = [n for n, r in report.items() if r["status"] == "failed"]

    os.makedirs(args.out_dir, exist_ok=True)
    analytics = not args.no_analytics
    outputs = {
        "index.html": render_html(page_sections, FEEDS, args.max_hours, now,
                                  failed, analytics, args.hours),
        # RSS is deliberately generous: readers dedupe by guid, and a narrow
        # window means a subscriber who misses a poll loses those items.
        "feed.xml": render_rss(page_sections, now, args.site_url.rstrip("/")),
        "style.css": CSS.lstrip(),
        "prefs.js": render_prefs_js(args.hours, args.limit),
        ".htaccess": render_htaccess(analytics),
        "robots.txt": render_robots(args.site_url.rstrip("/")),
        ".well-known/security.txt": render_security_txt(now),
        "favicon.svg": render_favicon_svg(),
        "favicon.ico": render_favicon_ico(),
    }

    # One plain-text edition per selectable window, so the "plain text" link
    # always matches what the reader is looking at.
    for choice in window_choices(args.max_hours, args.hours) + ["all"]:
        window = args.max_hours if choice == "all" else choice
        txt_sections = select(state, FEEDS, window, args.max_limit, now)
        outputs[txt_filename(choice, args.hours)] = render_txt(
            txt_sections, "all" if choice == "all" else window, now)
    for filename, content in outputs.items():
        path = os.path.join(args.out_dir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(content, bytes):
            with open(path, "wb") as f:
                f.write(content)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

    total_items = sum(len(s["items"]) for s in page_sections)
    for name in FEEDS:
        r = report[name]
        flag = {"fresh": "ok", "unchanged": "304", "failed": "FAIL"}[r["status"]]
        detail = f"  {r['error']}" if r["error"] else ""
        print(f"{flag:5} {name:24.24} cached={r['cached']:3}{detail}", file=sys.stderr)
    txt_files = sorted(f for f in outputs
                       if f.startswith("index") and f.endswith(".txt"))
    print(
        f"\npage: {len(page_sections)}/{len(FEEDS)} sections, {total_items} items "
        f"(carries up to {args.max_hours}h and {args.max_limit} per source; "
        f"defaults to {args.hours}h and {args.limit})\n"
        f"plain text: {', '.join(txt_files)}\n"
        f"{len(failed)} feeds failed -> {args.out_dir}/",
        file=sys.stderr,
    )

    if len(failed) > args.max_failures:
        print(f"ERROR: {len(failed)} feeds failed (limit {args.max_failures})",
              file=sys.stderr)
        return 1
    if not page_sections:
        print("ERROR: no sections rendered", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
