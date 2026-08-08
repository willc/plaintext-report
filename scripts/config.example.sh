# Copy to scripts/config.local.sh and fill in. That file is gitignored.
#
#   cp scripts/config.example.sh scripts/config.local.sh
#
# Deployment details live here rather than in the scripts so that publishing
# this repo does not also publish the exact SSH user, host and path to target.

# SSH host alias from ~/.ssh/config, or a full user@host.
PLAINTEXT_SSH_ALIAS="my-deploy-alias"

# Absolute path to the web root on the server.
PLAINTEXT_REMOTE_PATH="/home/USER/example.com"

# Used only by scripts/install-keys.sh, which runs once.
PLAINTEXT_SSH_HOST="server.example.com"
PLAINTEXT_SSH_USER="USER"

# Public site URL, used for the post-deploy live check.
PLAINTEXT_SITE_URL="https://plaintext.report"
