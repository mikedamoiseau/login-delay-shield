#!/usr/bin/env bash
#
# Generate the wordpress.org listing screenshots automatically (F-5-5).
#
# Boots a disposable WordPress site from the project's dev image (the same
# one bin/test.sh builds), activates the plugin, seeds a week of demo
# attack data (tools/screenshots/seed.php), then drives a headless
# Chromium (Playwright container) through wp-admin to capture the four
# screenshots described in readme.txt "== Screenshots ==".
#
# Output: .wordpress-org/screenshot-{1..4}.png  (git mirror of SVN assets/)
# The SVN assets/ copy is NOT touched — review the PNGs, then copy them
# up manually (cp .wordpress-org/screenshot-*.png ../assets/) when happy.
#
# Usage:
#   ./bin/screenshots.sh
#
# Requires: Docker. No host PHP/Node needed.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_SLUG="wp-login-delay"
NETWORK="wldelay-screenshots"
WP_CONTAINER="wldelay-shot-wp"
PW_CONTAINER="wldelay-shot-pw"
# Pin the Playwright image; playwright-core installed in-container must match.
PW_VERSION="1.49.0"
PW_IMAGE="mcr.microsoft.com/playwright:v${PW_VERSION}-jammy"
OUTPUT_DIR="$REPO_DIR/.wordpress-org"

# Same lazily-built, Dockerfile-fingerprinted image as bin/test.sh.
if command -v sha256sum >/dev/null 2>&1; then
    DOCKERFILE_HASH="$(sha256sum "$REPO_DIR/Dockerfile" | cut -c1-12)"
else
    DOCKERFILE_HASH="$(shasum -a 256 "$REPO_DIR/Dockerfile" | cut -c1-12)"
fi
IMAGE="login-delay-shield-dev:${DOCKERFILE_HASH}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">>> Building $IMAGE (Dockerfile changed or first run; ~3 min)..."
    # Force BuildKit — the Dockerfile uses heredocs the legacy builder rejects.
    DOCKER_BUILDKIT=1 docker build -t "$IMAGE" "$REPO_DIR"
fi

cleanup() {
    docker rm -f "$WP_CONTAINER" "$PW_CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NETWORK" >/dev/null

echo ">>> Starting WordPress container..."
# The dev image's entrypoint starts MariaDB and waits for readiness.
# Mount the plugin read-only; seed script needs the tools/ dir too.
docker run -d --name "$WP_CONTAINER" --network "$NETWORK" --network-alias wp \
    -v "$REPO_DIR:/var/www/html/wp-content/plugins/$PLUGIN_SLUG:ro" \
    "$IMAGE" \
    bash -lc '
        set -e
        cd /var/www/html
        # Serve under the network alias so wp-admin redirects stay reachable
        # from the Playwright container.
        wp --allow-root option update home http://wp:8080
        wp --allow-root option update siteurl http://wp:8080
        wp --allow-root plugin activate '"$PLUGIN_SLUG"'
        wp --allow-root eval-file wp-content/plugins/'"$PLUGIN_SLUG"'/tools/screenshots/seed.php
        echo "WP_READY"
        exec wp --allow-root server --host=0.0.0.0 --port=8080
    '

echo ">>> Waiting for WordPress to come up..."
for i in $(seq 1 60); do
    if docker logs "$WP_CONTAINER" 2>&1 | grep -q "WP_READY"; then
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "WordPress container failed to become ready:" >&2
        docker logs "$WP_CONTAINER" >&2
        exit 1
    fi
    sleep 2
done
# Give `wp server` a moment to bind after the READY marker.
sleep 2

echo ">>> Capturing screenshots with Playwright ${PW_VERSION}..."
docker run --rm --name "$PW_CONTAINER" --network "$NETWORK" \
    -v "$REPO_DIR/tools/screenshots:/work:ro" \
    -v "$OUTPUT_DIR:/output" \
    -w /tmp/capture \
    -e WP_BASE_URL=http://wp:8080 \
    -e OUTPUT_DIR=/output \
    "$PW_IMAGE" \
    bash -lc "
        set -e
        npm init -y >/dev/null 2>&1
        npm install --no-audit --no-fund playwright-core@${PW_VERSION} >/dev/null 2>&1
        # Node resolves require() from the script's own directory, so the
        # script must sit next to node_modules — /work is a read-only mount.
        cp /work/capture.js .
        node capture.js
    "

echo ""
echo ">>> Done. Review the PNGs:"
ls -la "$OUTPUT_DIR"/screenshot-*.png
echo ""
echo "When happy, sync to the SVN assets dir:"
echo "  cp $OUTPUT_DIR/screenshot-*.png $REPO_DIR/../assets/"
