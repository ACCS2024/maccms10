#!/usr/bin/env bash
# 番号站群封面图床域名迁移:备份 -> 登记替换助手 -> 改存量。
#
#   bash replace.sh <旧域名> <新域名>            # 预演,只报数不写
#   bash replace.sh <旧域名> <新域名> --apply    # 执行
#
# 在新机 85.149.233.11 上以 root 跑。三站共库,改一次三站都生效。
set -euo pipefail

OLD="${1:-}"; NEW="${2:-}"; APPLY=0
[ "${3:-}" = "--apply" ] && APPLY=1
if [ -z "$OLD" ] || [ -z "$NEW" ]; then
  echo "用法: bash replace.sh <旧域名> <新域名> [--apply]" >&2; exit 1
fi
# maccms Rep::checkExecutable 的下限:REPLACE 是无边界子串替换,太短会误伤正文
if [ "${#OLD}" -lt 4 ]; then echo "旧域名过短(<4 字符),拒绝执行" >&2; exit 1; fi
if [ "$OLD" = "$NEW" ]; then echo "新旧相同,无意义" >&2; exit 1; fi

DB=fhzy1_com
RP=$(sqlite3 /www/server/panel/data/default.db "select mysql_root from config limit 1;" 2>/dev/null)
[ -z "$RP" ] && { echo "取不到 MySQL root 口令" >&2; exit 1; }
Q="mysql -uroot -p$RP $DB -N -B"
QQ="mysql -uroot -p$RP $DB"

hit=$($Q -e "select count(*) from mac_vod where vod_pic like '%$OLD%';" 2>/dev/null)
echo "  mac_vod.vod_pic 命中 $hit 行"
[ "$hit" -eq 0 ] && { echo "  无需处理"; exit 0; }

# 其它字段/表兜底扫一眼(实测都是 0,但换个站/换个时间可能不同)
for f in vod_pic_thumb vod_pic_slide; do
  n=$($Q -e "select count(*) from mac_vod where \`$f\` like '%$OLD%';" 2>/dev/null || echo 0)
  [ "${n:-0}" -gt 0 ] && echo "  !! mac_vod.$f 也有 $n 行,本脚本不处理,请手工确认"
done
for f in art_pic art_content; do
  n=$($Q -e "select count(*) from mac_art where \`$f\` like '%$OLD%';" 2>/dev/null || echo 0)
  [ "${n:-0}" -gt 0 ] && echo "  !! mac_art.$f 也有 $n 行,本脚本不处理,请手工确认"
done

if [ "$APPLY" -eq 0 ]; then
  echo "  [预演] 未写入。确认无误后加 --apply"
  exit 0
fi

BK=/home/migrate-fanhao-20260828/imgrep-$(date +%Y%m%d-%H%M%S)
mkdir -p "$BK"
$Q -e "select vod_id, vod_pic from mac_vod where vod_pic like '%$OLD%';" > "$BK/vod_pic-before.tsv" 2>/dev/null
echo "  备份 $(wc -l < "$BK/vod_pic-before.tsv") 行 -> $BK/vod_pic-before.tsv"

{
  echo "-- 回滚:$NEW 改回 $OLD"
  echo "UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'$NEW','$OLD') WHERE vod_pic LIKE '%$NEW%';"
  echo "UPDATE mac_rep SET rep_status=0 WHERE rep_original='$OLD' AND rep_replacement='$NEW';"
} > "$BK/rollback.sql"

dup=$($Q -e "select count(*) from mac_rep where rep_original='$OLD' and rep_replacement='$NEW';" 2>/dev/null)
if [ "$dup" -eq 0 ]; then
  $QQ -e "INSERT INTO mac_rep (rep_type,rep_original,rep_replacement,rep_note,rep_status,rep_applied,rep_applied_time,rep_create_time)
          VALUES ('视频封面替换','$OLD','$NEW','封面图床域名迁移',1,1,UNIX_TIMESTAMP(),UNIX_TIMESTAMP());" 2>/dev/null
  echo "  mac_rep 已登记"
else
  echo "  mac_rep 已有同样记录,跳过"
fi

t0=$(date +%s)
$QQ -e "UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'$OLD','$NEW') WHERE vod_pic LIKE '%$OLD%';" 2>/dev/null
t1=$(date +%s)
left=$($Q -e "select count(*) from mac_vod where vod_pic like '%$OLD%';" 2>/dev/null)
now=$($Q -e "select count(*) from mac_vod where vod_pic like '%$NEW%';" 2>/dev/null)
echo "  替换完成 $((t1-t0))s   旧域名残留 $left   新域名 $now"
[ "$left" -ne 0 ] && echo "  !! 仍有残留,请检查"

for s in fhzy1.com fhapi9.com bjgx; do rm -rf /home/wwwroot/$s/runtime/*/temp/* 2>/dev/null || true; done
echo "  模板缓存已清"
echo "  回滚: mysql -uroot -p<root> $DB < $BK/rollback.sql"
echo
echo "  ★ 别忘了改发布程序 picDomain,否则新内容又带回旧域名:"
echo "    ssh root@216.180.225.138 'cd /home/dev/ffcore && node /tmp/upd_publisher.js $OLD $NEW --apply'"
