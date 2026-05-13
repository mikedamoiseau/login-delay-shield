#!/usr/bin/env bash
#
# Run `wp plugin check` against the *packaged* form of the plugin
# (what bin/package.sh produces and what gets committed to SVN
# trunk on release), inside the project's dev container.
#
# Why the packaged form, not the repo root?
#   The repo contains tests/, composer.json, .github/, etc. that
#   the shipped form excludes — checking those would surface
#   false positives that real users never see.
#
# Usage:
#   ./bin/plugin-check.sh
#   ./bin/plugin-check.sh --format=json    # forward args to wp plugin check

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="login-delay-shield-dev:latest"
PLUGIN_SLUG="login-delay-shield"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">>> Building $IMAGE (first run; ~3 min)..."
    docker build -t "$IMAGE" "$REPO_DIR"
fi

PACKAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$PACKAGE_DIR" "$REPO_DIR/$PLUGIN_SLUG.zip"' EXIT

echo ">>> Building plugin package via bin/package.sh..."
"$REPO_DIR/bin/package.sh" "$PACKAGE_DIR" >/dev/null

TTY_FLAG=""
if [ -t 0 ]; then
    TTY_FLAG="-t"
fi

docker run --rm -i $TTY_FLAG \
    -v "$PACKAGE_DIR/$PLUGIN_SLUG":/var/www/html/wp-content/plugins/"$PLUGIN_SLUG":ro \
    -w /var/www/html \
    "$IMAGE" \
    wp --allow-root plugin check "$PLUGIN_SLUG" "$@"
