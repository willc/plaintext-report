#!/usr/bin/env python3
"""Hit every feed in the roster and report what actually happens.

Phase 1 diagnostic. Serial, with a delay between requests, so we get an
honest read per feed instead of tripping rate limits and blaming the feed.

Usage:
    .venv/bin/python check_feeds.py
    .venv/bin/python check_feeds.py --json results.json
"""

import argparse
import calendar
import datetime as dt
import json
import socket
import sys
import time

import feedparser

from feeds import FEEDS, USER_AGENT

TIMEOUT = 20
DELAY = 1.5  # seconds between requests; politeness, and Reddit insists


def check(name, url):
    started = time.monotonic()
    row = {
        "name": name,
        "url": url,
        "status": None,
        "final_url": None,
        "redirected": False,
        "bozo": False,
        "bozo_reason": None,
        "entries": 0,
        "dated": 0,
        "with_link": 0,
        "newest_age_h": None,
        "elapsed_s": None,
        "verdict": "FAIL",
        "note": "",
    }

    try:
        parsed = feedparser.parse(url, agent=USER_AGENT)
    except Exception as exc:  # noqa: BLE001
        row["note"] = f"exception: {exc}"
        row["elapsed_s"] = round(time.monotonic() - started, 1)
        return row

    row["elapsed_s"] = round(time.monotonic() - started, 1)
    row["status"] = parsed.get("status")
    row["final_url"] = parsed.get("href")
    row["redirected"] = bool(row["final_url"] and row["final_url"] != url)
    row["bozo"] = bool(parsed.get("bozo"))
    if row["bozo"]:
        row["bozo_reason"] = str(parsed.get("bozo_exception"))[:120]

    now = dt.datetime.now(dt.timezone.utc)
    newest = None
    for e in parsed.entries:
        if e.get("title") and e.get("link"):
            row["with_link"] += 1
        st = e.get("published_parsed") or e.get("updated_parsed")
        if st:
            row["dated"] += 1
            # timegm, not mktime: feedparser hands back UTC struct_times, and
            # mktime reads them as local time. That silently skews every
            # timestamp by the host's UTC offset.
            ts = dt.datetime.fromtimestamp(calendar.timegm(st), tz=dt.timezone.utc)
            if newest is None or ts > newest:
                newest = ts
    row["entries"] = len(parsed.entries)

    if newest:
        row["newest_age_h"] = round((now - newest).total_seconds() / 3600, 1)

    # Verdict
    status = row["status"]
    if status is not None and status >= 400:
        row["verdict"] = "FAIL"
        row["note"] = f"HTTP {status}"
    elif row["with_link"] == 0:
        row["verdict"] = "FAIL"
        row["note"] = row["bozo_reason"] or "no usable entries"
    elif row["dated"] == 0:
        row["verdict"] = "WARN"
        row["note"] = "no parseable timestamps; items can't be windowed"
    elif row["newest_age_h"] is not None and row["newest_age_h"] > 24 * 30:
        row["verdict"] = "WARN"
        row["note"] = f"newest item is {row['newest_age_h'] / 24:.0f}d old; feed may be dormant"
    else:
        row["verdict"] = "OK"
        if row["redirected"]:
            row["note"] = "redirected; update the URL"
        elif row["bozo"]:
            row["note"] = f"parsed with warning: {row['bozo_reason']}"

    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=str, default=None, help="also write raw results here")
    args = ap.parse_args()

    socket.setdefaulttimeout(TIMEOUT)

    rows = []
    for i, (name, url) in enumerate(FEEDS.items()):
        if i:
            time.sleep(DELAY)
        row = check(name, url)
        rows.append(row)
        print(
            f"{row['verdict']:4}  {name:24.24}  "
            f"http={str(row['status']):4}  n={row['entries']:3}  "
            f"dated={row['dated']:3}  newest={str(row['newest_age_h']):>6}h  "
            f"{row['elapsed_s']}s  {row['note']}",
            flush=True,
        )

    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(
        f"\n{len(rows)} feeds: "
        + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    )

    for r in rows:
        if r["redirected"]:
            print(f"  redirect: {r['name']}\n    {r['url']}\n    -> {r['final_url']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)

    return 1 if counts.get("FAIL") else 0


if __name__ == "__main__":
    sys.exit(main())
