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
IMAGE="login-delay-shield-dev:latest"
COMPOSER_CACHE_VOLUME="login-delay-shield-composer-cache"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo ">>> Building $IMAGE (first run; ~3 min)..."
    docker build -t "$IMAGE" "$REPO_DIR"
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
    bash -c "composer install --prefer-dist --no-interaction && ($PHPUNIT_CMD)" bash "$@"
