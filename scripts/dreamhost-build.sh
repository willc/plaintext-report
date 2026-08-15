#!/usr/bin/env bash
# Build PLAINTEXT REPORT on the web host itself, from cron.
#
# GitHub's runners deploy from datacenter IPs, which DreamHost's firewall
# intermittently drops and which CISA answers with a 403. Building here
# removes both problems: no inbound SSH, and feed requests come from an IP
# publishers do not treat as hostile.
#
# Quiet on success, loud on failure. DreamHost's cron emails whatever a job
# writes to stdout/stderr, so a silent success means no mail and a failure
# arrives with the full log attached.
#
#   */30 * * * * /home/plaintext_report/plaintext-report/scripts/dreamhost-build.sh

set -euo pipefail

ROOT="${PLAINTEXT_ROOT:-$HOME/plaintext-report}"
WEB="${PLAINTEXT_WEB:-$HOME/plaintext.report}"
PY="$ROOT/.venv/bin/python"
STAGE="$ROOT/.stage"
LOG="$ROOT/build.log"
LOCK="$ROOT/.build.lock"

# A slow build must not overlap the next tick and race itself into the web
# root. Exiting 0 on a held lock keeps cron quiet about it.
exec 9>"$LOCK"
if ! flock -n 9; then
  exit 0
fi

# Everything is captured; it is only shown if something goes wrong.
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

fail() {
  echo "PLAINTEXT REPORT build FAILED at $(date -u '+%Y-%m-%d %H:%M UTC')" >&2
  echo "--- $1 ---" >&2
  cat "$out" >&2
  exit 1
}

cd "$ROOT"

# Pick up code changes pushed to GitHub. --ff-only so a dirty or diverged
# checkout stops the build rather than being silently reconciled.
git fetch --quiet origin main >"$out" 2>&1 || fail "git fetch"
git merge --ff-only --quiet origin/main >>"$out" 2>&1 || fail "git merge"

# Build into a staging directory, never straight into the web root: a
# half-written page must never be servable.
rm -rf "$STAGE"
"$PY" plaintext.py --out-dir "$STAGE" --state "$ROOT/state.json" >>"$out" 2>&1 \
  || fail "build"

"$PY" verify.py "$STAGE" >>"$out" 2>&1 || fail "verify"

# Only now is it allowed near the live site. .dh-diag is DreamHost's own
# symlink and is not ours to delete.
rsync -rlpt --delete --exclude '.dh-diag' "$STAGE/" "$WEB/" >>"$out" 2>&1 \
  || fail "rsync to web root"

# Confirm what is actually being served, not what we just built.
body="$(curl -fsS --max-time 30 https://plaintext.report/ 2>>"$out")" \
  || fail "live site fetch"
count="$(printf '%s' "$body" | grep -c '</li>' || true)"
if [ "$count" -lt 15 ]; then
  echo "live page has only $count headlines" >>"$out"
  fail "live site check"
fi

# Keep a short local history for debugging, without growing forever.
{
  echo "=== $(date -u '+%Y-%m-%d %H:%M UTC')  ok, $count headlines live ==="
  cat "$out"
} >> "$LOG"
tail -n 2000 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
