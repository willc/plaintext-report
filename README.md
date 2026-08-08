# PLAINTEXT REPORT

Security headlines. Nothing else. A static aggregator of security news RSS
feeds, inspired by [brutalist.report](https://brutalist.report/) but for
infosec. Live at **[plaintext.report](https://plaintext.report)**.

No ads, no cookies, no third-party requests, no personal data. Headlines link
straight to the publisher.

## What it does

Fetches ~17 security feeds, keeps the last 72 hours, and writes a static site:

| File | What it is |
| --- | --- |
| `index.html` | The page. Reader can change theme, window and per-source count. |
| `index.txt`, `index-*.txt` | Plain text, one file per selectable window. Zero scripts. |
| `feed.xml` | Aggregate RSS of everything in the window. |
| `style.css`, `prefs.js` | Same-origin assets. |
| `.htaccess` | Generated security headers, including a CSP whose script hash is derived from the page. |
| `robots.txt`, `.well-known/security.txt` | Housekeeping. |

## Running it

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python plaintext.py --out-dir dist
.venv/bin/python verify.py dist
```

Useful flags:

- `--hours N` window the page shows before the reader changes it (default 24)
- `--limit N` items per source shown by default (default 15)
- `--max-hours N` widest window the page carries and a reader can select (default 72)
- `--max-limit N` most items per source a reader can select (default 25)
- `--offline` render from cache without fetching
- `--no-analytics` omit the Plausible snippet

Check feed health separately:

```bash
.venv/bin/python check_feeds.py
```

## Design notes

Things that are the way they are on purpose.

**State is the point.** `state.json` holds each feed's ETag, Last-Modified,
last-success time, and up to 200 items or 14 days of history. When a fetch
fails, the source keeps its cached items and is marked stale rather than
disappearing from the page. A source silently vanishing is indistinguishable
from a source having a quiet day, which is the worse failure.

**Fresh items are merged, not replaced.** A feed that truncates to five entries
must not erase the rest of the day.

**A 200 with an empty body counts as a failure.** Otherwise a broken response
would wipe the cache.

**Timestamps use `calendar.timegm`, not `time.mktime`.** feedparser returns UTC
struct_times; `mktime` reads them as local time and skews everything by the
host's UTC offset. CI runners are UTC, so this bug hides in production and only
shows up locally. There is a test pinned to an exact datetime.

**Links are scheme-allowlisted to http/https.** Escaping an `href` does not
neutralize a `javascript:` URL, and feeds are third-party input.

**The page carries more than it displays.** It ships up to 72 hours so the
reader's window control can widen client-side without a refetch. The window
choices offered never exceed what was actually rendered, and every offered
window has a matching `.txt` file, both enforced by tests and by `verify.py`.

**Columns come from `column-width`, not a preference.** The browser picks how
many fit. One on a phone, three or four on a wide desktop, nothing to store.

**Preferences live in localStorage, never cookies.** Nothing is transmitted.

**`.htaccess` is generated, not hand-written.** The CSP includes a SHA-256 of
the inline analytics snippet, so hand-maintaining it would drift and silently
break the page.

## Deployment

GitHub Actions builds every 30 minutes and rsyncs to shared hosting. Nothing
uploads until `verify.py` passes, and the workflow then re-fetches the live URL
to confirm what is actually being served.

For manual deploys, put the server details in a local file that is never
committed:

```bash
cp scripts/config.example.sh scripts/config.local.sh
# fill it in, then
./scripts/deploy.sh
```

Server hostname, shell user and web root live there rather than in the scripts,
so publishing this repo does not also publish the exact target to attack.

Required repository secrets:

| Secret | Value |
| --- | --- |
| `SSH_KEY` | Private half of a deploy-only keypair |
| `SSH_HOST` | DreamHost server hostname |
| `SSH_USER` | The site's own shell user |
| `REMOTE_PATH` | Web root for plaintext.report |
| `KNOWN_HOSTS` | Output of `ssh-keyscan <host>` |

The deploy key is dedicated to this site and opens nothing else. Host keys are
pinned rather than blindly accepted.

## Tests

```bash
.venv/bin/python -m pytest -q
```

Covers the timestamp bug, cache degradation, dedupe, windowing, link safety,
escaping, the CSP hash matching the shipped script, and the plain-text editions
matching the offered windows.
