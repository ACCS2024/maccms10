#!/usr/bin/env bash
# 本地冒烟:对 application/ 与入口文件做 php -l 语法检查(与 .github/workflows/ci.yml 一致)。
# 用法:bash tests/lint.sh
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
while IFS= read -r -d '' f; do
  php -l "$f" >/dev/null || { echo "LINT FAIL: $f"; fail=1; }
done < <(find application -name '*.php' -print0)
for f in index.php api.php admin.php install.php security_check.php; do
  [ -f "$f" ] && { php -l "$f" >/dev/null || { echo "LINT FAIL: $f"; fail=1; }; }
done
if [ "$fail" = 0 ]; then echo "PHP lint OK"; else echo "lint failed"; exit 1; fi
