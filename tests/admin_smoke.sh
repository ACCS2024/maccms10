#!/usr/bin/env bash
#
# 后台 HTTP 冒烟:登录后断言后台关键页面「真正可用」。
#
# 重要:不能只看 HTTP 状态码。后台存在两类「HTTP 200 实为错误」的情况,必须按
# 响应内容判定,否则会误判通过(历史教训:文件完整性守卫 exit 出错误信息但状态
# 仍为 200,曾掩盖鉴权绕过等严重缺陷):
#   - <title>系统发生错误</title>     —— TP8 异常页
#   - 系统核心功能异常               —— 文件完整性守卫
# 另:若某页 302 跳转到 index/login,说明会话/鉴权未生效(登录没保持),亦判失败。
#
# 用法: tests/admin_smoke.sh [base_url]
#   前置(由 CI/调用方准备):DB 灌库 + 种可登录管理员 admin/admin888、
#   关验证码(admin_login_verify=0)、种最小内容(vod/art/actor/topic id=1)。
#
set -uo pipefail

BASE="${1:-http://127.0.0.1:8813}"
CJ="$(mktemp)"
trap 'rm -f "$CJ"' EXIT

curl -s -c "$CJ" -o /dev/null "$BASE/index/login" || true
curl -s -b "$CJ" -c "$CJ" -H "X-Requested-With: XMLHttpRequest" -X POST "$BASE/index/login" \
  --data "admin_name=admin&admin_pwd=admin888" -o /dev/null || true

# 单页判定:输出 ok/FAIL,返回 0/1
probe() {
  local u="$1" body code loc meta tmpf
  tmpf="$(mktemp)"
  # 单次请求同时取 body+code+redirect,避免多次请求在模板冷编译期结果不一致而误报
  meta="$(curl -s -b "$CJ" -o "$tmpf" -w '%{http_code}|%{redirect_url}' "$BASE/$u")"
  code="${meta%%|*}"
  loc="${meta#*|}"
  body="$(cat "$tmpf")"
  rm -f "$tmpf"

  if [ "$code" -ge 500 ] || [ "$code" = "000" ]; then
    printf 'FAIL  %-26s -> %s (5xx)\n' "$u" "$code"; return 1
  fi
  case "$loc" in
    *index/login*) printf 'FAIL  %-26s -> %s (跳登录:会话/鉴权未生效)\n' "$u" "$code"; return 1 ;;
  esac
  # 精确判内容错误,避免误报(正常页的 JS 里也可能含告警字串):
  #  - TP8 异常页以 <title>系统发生错误</title> 为准(debug 开时)
  #  - 文件完整性守卫 exit 出的是「裸消息」(极短 body),按长度+消息判
  if printf '%s' "$body" | grep -q '<title>系统发生错误</title>'; then
    printf 'FAIL  %-26s -> %s (异常页)\n' "$u" "$code"; return 1
  fi
  if [ "${#body}" -lt 300 ] && printf '%s' "$body" | grep -q '系统核心功能异常'; then
    printf 'FAIL  %-26s -> %s (完整性守卫拦截)\n' "$u" "$code"; return 1
  fi
  printf 'ok    %-26s -> %s\n' "$u" "$code"; return 0
}

# 先确认登录确实生效(否则后续全是跳登录)
if ! probe "index/index" >/dev/null; then
  echo "FAIL: 登录未生效(index/index 异常),后台冒烟中止"
  probe "index/index" || true
  exit 1
fi

routes=(
  index/index index/welcome
  vod/data "vod/info?id=1" art/data "art/info?id=1"
  actor/data "actor/info?id=1" topic/data type/index "type/info?id=6"
  user/data comment/data gbook/data link/index card/index
  order/index collect/index group/index role/data
  system/config system/configuser system/configcollect system/configupload
  system/configapi system/configseo system/configpay system/configemail
  addon/index template/index update/index
)

fail=0
for u in "${routes[@]}"; do
  probe "$u" || fail=1
done

if [ "$fail" = 0 ]; then
  echo "All admin smoke OK"
else
  echo "Admin smoke FAILED"
fi
exit "$fail"
