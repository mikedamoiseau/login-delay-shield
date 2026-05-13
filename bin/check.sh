#!/usr/bin/env bash
#
# Ship gate: run PHPUnit AND `wp plugin check`. Both must pass.
#
# Run this before committing to SVN trunk or tagging a release.
# CI does not run tests on this repo — this script is the only thing
# catching regressions before users on wordpress.org see them.
#
# Usage:
#   ./bin/check.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== 1/2  PHPUnit ==="
"$SCRIPT_DIR/test.sh"
echo

echo "=== 2/2  WP Plugin Check ==="
"$SCRIPT_DIR/plugin-check.sh"
echo

echo "All checks passed."
