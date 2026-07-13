#!/usr/bin/env bash
#
# Run the PHPUnit test suite inside the project's dev container.
#
# The container is built lazily from ../Dockerfile on first run.
# Composer's cache is persisted in a named Docker volume so reruns
# only download new packages.
#
# Usage:
#   ./bin/test.sh                       # full suite: unit + integration
#   ./bin/test.sh --configuration phpunit-unit.xml   # unit tests only
#   ./bin/test.sh --filter Whitelist    # forward args to phpunit
#
# The unit and integration suites require different PHPUnit bootstraps
# (unit uses Brain Monkey with no WordPress; integration loads the WP test
# harness), so they cannot share a single phpunit config. With no args this
# script therefore runs both configs sequentially -- unit first, then
# integration -- and fails if either suite fails. Any arguments are
# forwarded verbatim to a single phpunit invocation, so passing an explicit
# --configuration / --testsuite / --filter runs exactly that.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSER_CACHE_VOLUME="login-delay-shield-composer-cache"

# Tag the dev image by a fingerprint of the Dockerfile content rather than a
# fixed ":latest". A Dockerfile change (e.g. F-4-7 adding the pcntl extension
# that PHPUnit's php-invoker needs to enforce defaultTimeLimit) produces a new
# tag, so an existing local image is NOT silently reused — the missing-tag
# check below rebuilds. Unchanged Dockerfile => same tag => no rebuild, no
# per-run `docker build` overhead.
if command -v sha256sum >/dev/null 2>&1; then
    DOCKERFILE_HASH="$(sha256sum "$REPO_DIR/Dockerfile" | cut -c1-12)"
else
    DOCKERFILE_HASH="$(shasum -a 256 "$REPO_DIR/Dockerfile" | cut -c1-12)"
fi
IMAGE="login-delay-shield-dev:${DOCKERFILE_HASH}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">>> Building $IMAGE (Dockerfile changed or first run; ~3 min)..."
    # Force BuildKit: the Dockerfile uses heredocs (COPY <<'EOF'), which the
    # legacy builder cannot parse. The `# syntax=` directive on line 1 of the
    # Dockerfile pulls a frontend that supports them on any BuildKit daemon.
    DOCKER_BUILDKIT=1 docker build -t "$IMAGE" "$REPO_DIR"
fi

TTY_FLAG=""
if [ -t 0 ]; then
    TTY_FLAG="-t"
fi

# With no args, run both suites (separate bootstraps -> separate configs).
# With args, forward them verbatim to a single phpunit invocation. The inner
# command text is a fixed literal; caller arguments are passed as positional
# parameters ("$@") so they are never reparsed as shell source.
if [ "$#" -eq 0 ]; then
    PHPUNIT_CMD='echo ">>> Unit suite" && vendor/bin/phpunit --configuration phpunit-unit.xml && echo ">>> Integration suite" && vendor/bin/phpunit --configuration phpunit.xml.dist'
else
    PHPUNIT_CMD='vendor/bin/phpunit "$@"'
fi

docker run --rm -i $TTY_FLAG \
    -v "$REPO_DIR":/app \
    -v "$COMPOSER_CACHE_VOLUME":/tmp/composer-cache \
    -e COMPOSER_CACHE_DIR=/tmp/composer-cache \
    -e WP_TESTS_DIR=/tmp/wordpress-tests-lib \
    -e WP_CORE_DIR=/tmp/wordpress \
    -w /app \
    "$IMAGE" \
    bash -c 'php -m | grep -qx pcntl || { echo "ERROR: pcntl extension missing — per-test timeouts (enforceTimeLimit) would silently no-op. Rebuild the image." >&2; exit 1; }; composer install --prefer-dist --no-interaction && ('"$PHPUNIT_CMD"')' bash "$@"
