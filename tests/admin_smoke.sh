#!/usr/bin/env bash
#
# 后台 HTTP 冒烟:登录后断言后台关键页面非 5xx。
# 需配合一个已启动的后台入口(改名后的 admin 入口)。
#
# 用法: tests/admin_smoke.sh [base_url]
#   base_url 默认 http://127.0.0.1:8813
#   前置条件(由调用方/CI 准备):
#     - DB 已灌 schema + initdata,并种入可登录管理员 admin/admin888
#       (admin_pwd 可用 MD5('admin888'),mac_password_verify 兼容旧 md5)
#     - application/extra/maccms.php 的 admin_login_verify 置 '0'(关验证码)
#     - 最小内容已种(vod/art/actor/topic id=1),供编辑页 info?id=1 使用
#
set -uo pipefail

BASE="${1:-http://127.0.0.1:8813}"
CJ="$(mktemp)"
trap 'rm -f "$CJ"' EXIT

# 取登录页(种 session cookie)后提交登录
curl -s -c "$CJ" -o /dev/null "$BASE/index/login" || true
curl -s -b "$CJ" -c "$CJ" -X POST "$BASE/index/login" \
  --data "admin_name=admin&admin_pwd=admin888" -o /dev/null || true

# 覆盖列表 / 编辑 / 设置 / 仪表盘四类页面
routes=(
  index/index index/welcome
  vod/data "vod/info?id=1" art/data "art/info?id=1"
  actor/data "actor/info?id=1" topic/data type/index "type/info?id=6"
  user/data comment/data gbook/data link/index card/index
  order/index make/index collect/index group/index role/index
  system/config system/configuser system/configcollect system/configupload
  system/configapi system/configseo system/configpay system/configemail
  update/index
)

fail=0
for u in "${routes[@]}"; do
  code="$(curl -s -b "$CJ" -o /dev/null -w '%{http_code}' "$BASE/$u")"
  if [ "$code" -ge 500 ] || [ "$code" = "000" ]; then
    printf 'FAIL  %-26s -> %s\n' "$u" "$code"
    fail=1
  else
    printf 'ok    %-26s -> %s\n' "$u" "$code"
  fi
done

if [ "$fail" = 0 ]; then
  echo "All admin smoke OK"
else
  echo "Admin smoke FAILED"
fi
exit "$fail"
