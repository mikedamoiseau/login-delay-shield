#!/usr/bin/env bash
#
# Build the packaged form of the plugin — the exact files that get
# committed to wordpress.org SVN trunk on a release. Output: a
# zip in the repo root + an unpacked directory at $1 (optional).
#
# Excludes dev-only files (tests, composer artifacts, CI config,
# planning folders) so plugin-check sees what real users get.
#
# Usage:
#   ./bin/package.sh                          # produces ./login-delay-shield.zip
#   ./bin/package.sh /tmp/staging             # also unpacks to /tmp/staging/login-delay-shield/

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_SLUG="login-delay-shield"
OUT_ZIP="$REPO_DIR/$PLUGIN_SLUG.zip"
STAGING_DIR="${1-}"

rm -f "$OUT_ZIP"

cd "$REPO_DIR"

# Files/dirs to keep — explicit allowlist so we never accidentally
# ship vendor/, tests/, or planning content.
zip -qr "$OUT_ZIP" \
    wp-login-delay.php \
    wldelay-async.php \
    wldelay-audit.php \
    wldelay-enumeration.php \
    wldelay-fail2ban.php \
    wldelay-features.php \
    wldelay-migration.php \
    wldelay-persistence.php \
    wldelay-privacy.php \
    wldelay-settings.php \
    wldelay-settings-view.php \
    admin.css \
    admin.js \
    README.md \
    readme.txt \
    languages/ \
    -x '*.DS_Store' \
    -x 'languages/.*'

if [ -n "$STAGING_DIR" ]; then
    mkdir -p "$STAGING_DIR/$PLUGIN_SLUG"
    unzip -qo "$OUT_ZIP" -d "$STAGING_DIR/$PLUGIN_SLUG"
fi

echo "Packaged: $OUT_ZIP"
