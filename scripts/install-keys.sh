#!/usr/bin/env bash
# One-time: install the two deploy public keys on the hosting account.
#
# DreamHost's panel has no field for pasting public keys on this account type,
# so this does it over SSH with password auth. You will be prompted for the
# account password ONCE. It is typed straight into ssh and is never stored,
# logged, or passed as an argument.
#
#   ./scripts/install-keys.sh
#
# Afterwards, password auth is no longer needed for deploys.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
[ -f "$ROOT/scripts/config.local.sh" ] && . "$ROOT/scripts/config.local.sh"

HOST="${PLAINTEXT_SSH_HOST:-}"
USER_NAME="${PLAINTEXT_SSH_USER:-}"

if [ -z "$HOST" ] || [ -z "$USER_NAME" ]; then
  echo "ERROR: server not configured." >&2
  echo "Copy scripts/config.example.sh to scripts/config.local.sh and fill it in." >&2
  exit 1
fi

PERSONAL_KEY="$HOME/.ssh/dreamhost_deploy.pub"
CI_KEY="$HOME/.ssh/plaintext_ci.pub"

for key in "$PERSONAL_KEY" "$CI_KEY"; do
  if [ ! -f "$key" ]; then
    echo "ERROR: missing public key: $key" >&2
    exit 1
  fi
done

echo "Installing 2 public keys on $USER_NAME@$HOST"
echo "  1. $(awk '{print $3}' "$PERSONAL_KEY")  (your manual deploys)"
echo "  2. $(awk '{print $3, $4, $5, $6}' "$CI_KEY")  (GitHub Actions only)"
echo
echo "You will be asked for the ${USER_NAME} account password."
echo

# Both keys go up in a single session, so you type the password once.
# PubkeyAuthentication=no stops ssh burning attempts on keys the server does
# not have yet, which is what would otherwise lock you out on max auth tries.
cat "$PERSONAL_KEY" "$CI_KEY" | ssh \
  -o PubkeyAuthentication=no \
  -o PreferredAuthentications=password \
  -o StrictHostKeyChecking=yes \
  "$USER_NAME@$HOST" \
  'umask 077 && mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
   touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && \
   cat >> ~/.ssh/authorized_keys && \
   sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys && \
   echo "authorized_keys now has $(wc -l < ~/.ssh/authorized_keys) keys" && \
   echo "web root candidates:" && ls -d ~/*/ 2>/dev/null'

echo
echo "==> Verifying key auth (no password should be requested)"

for pair in "dreamhost_deploy:your key" "plaintext_ci:CI key"; do
  keyfile="$HOME/.ssh/${pair%%:*}"
  label="${pair##*:}"
  if ssh -i "$keyfile" -o IdentitiesOnly=yes -o BatchMode=yes \
        -o ConnectTimeout=15 "$USER_NAME@$HOST" true 2>/dev/null; then
    echo "  OK   $label"
  else
    echo "  FAIL $label" >&2
    exit 1
  fi
done

echo
echo "Both keys work. Password auth is no longer needed for deploys."
