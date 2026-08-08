#!/usr/bin/env bash
# Manual deploy of PLAINTEXT to DreamHost.
#
# Builds, verifies the built tree, syncs it, then checks the LIVE url. The
# last step matters: a green build and a working site are different claims.
#
#   ./scripts/deploy.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Server details come from a gitignored local file, not from this script, so
# that a public repo does not hand out the exact user, host and path.
# shellcheck source=/dev/null
[ -f "$ROOT/scripts/config.local.sh" ] && . "$ROOT/scripts/config.local.sh"

ALIAS="${PLAINTEXT_SSH_ALIAS:-}"
REMOTE="${PLAINTEXT_REMOTE_PATH:-}"
SITE="${PLAINTEXT_SITE_URL:-https://plaintext.report}"
PY="${PYTHON:-$ROOT/.venv/bin/python}"

if [ -z "$ALIAS" ] || [ -z "$REMOTE" ]; then
  echo "ERROR: deployment target not configured." >&2
  echo "Copy scripts/config.example.sh to scripts/config.local.sh and fill it in." >&2
  exit 1
fi

say() { printf '\n==> %s\n' "$1"; }

say "Tests"
"$PY" -m pytest -q

say "Build"
"$PY" plaintext.py --out-dir dist

say "Verify built tree"
"$PY" verify.py dist

say "Check the remote path exists"
# rsync would happily create a wrong directory and leave the site untouched
# while reporting success. Confirm the target first.
if ! ssh "$ALIAS" "test -d '$REMOTE'"; then
  echo "ERROR: $REMOTE does not exist on $ALIAS." >&2
  echo "Check the web root in the DreamHost panel before deploying." >&2
  exit 1
fi

say "Sync to $ALIAS:$REMOTE"
# --delete is safe here only because verify.py already proved dist/ is a
# complete site. Never reorder these two steps.
# .dh-diag is DreamHost's own symlink into /dh/web/diag. It is not ours to
# delete, so it is excluded rather than swept up by --delete.
rsync -rlptz --delete --human-readable \
  --exclude '.DS_Store' \
  --exclude '.dh-diag' \
  dist/ "$ALIAS:$REMOTE/"

say "Confirm the live site"
sleep 3
body="$(curl -fsS --max-time 30 "$SITE/")"

if ! grep -q '<main id="feeds">' <<<"$body"; then
  echo "ERROR: live page is missing the feeds container." >&2
  exit 1
fi

count="$(grep -c '</li>' <<<"$body" || true)"
if [ "$count" -lt 15 ]; then
  echo "ERROR: live page has only $count headlines." >&2
  exit 1
fi

updated="$(grep -o 'Updated [^<]*' <<<"$body" | head -1)"
echo "Live: $count headlines. $updated"

for path in /index.txt /feed.xml /style.css /prefs.js /robots.txt /.well-known/security.txt; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$SITE$path")"
  printf '  %-32s %s\n' "$path" "$code"
  [ "$code" = "200" ] || { echo "ERROR: $path returned $code" >&2; exit 1; }
done

say "Deployed."
