#!/usr/bin/env bash
# Compile all maintained PHP sources without application bootstrap or php.ini.
set -euo pipefail
cd "$(dirname "$0")/.."
php tests/php_lint.php "$@"
