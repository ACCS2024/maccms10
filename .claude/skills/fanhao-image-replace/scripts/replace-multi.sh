#!/usr/bin/env bash
# 番号封面图床迁移(多桶版) —— 比 replace.sh 强在:边界安全 + 一次处理多个零散域名
#
#   bash replace-multi.sh            # 预演
#   bash replace-multi.sh --apply    # 执行
#
# 用前先跑 0.5 节的两项自检,再按分三类结论改下面那几行 run,NEW 改成本次新域名。
# 2026-09-08 首次使用:fh200831.top -> fh260908.top,迁移 168,767 行
# 逐桶执行,每桶:备份 -> 追加 rollback -> 边界安全的 REPLACE
# 顺序要紧:畸形的 fmtu.netfhtu.comupload 必须先修,否则会被 fmtu.netfhtu.com 的替换污染成 fh260908.topupload
set -uo pipefail
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
NEW="fh260908.top"
BK=/home/migrate-fanhao-20260828/imgrep-$(date +%Y%m%d-%H%M%S)
Q="mysql -uroot -p5f6448cd1dd23be0 fhzy1_com -N -B"
QQ="mysql -uroot -p5f6448cd1dd23be0 fhzy1_com"
say(){ [ "$APPLY" = 1 ] && echo "  $*" || echo "  [预演] $*"; }
[ "$APPLY" = 1 ] && mkdir -p "$BK"

run(){ # $1=匹配子串(含边界) $2=替换成 $3=说明
  local from="$1" to="$2" note="$3"
  local n; n=$($Q -e "select count(*) from mac_vod where vod_pic like '%${from}%';" 2>/dev/null)
  if [ "${n:-0}" -eq 0 ]; then say "$note: 0 行,跳过"; return; fi
  if [ "$APPLY" = 1 ]; then
    $Q -e "select vod_id, vod_pic from mac_vod where vod_pic like '%${from}%';" 2>/dev/null \
      > "$BK/$(echo "$from"|tr -c 'a-zA-Z0-9' '_').tsv"
    echo "UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'${to}','${from}') WHERE vod_pic LIKE '%${to}%';" >> "$BK/rollback.sql"
    $QQ -e "UPDATE mac_vod SET vod_pic=REPLACE(vod_pic,'${from}','${to}') WHERE vod_pic LIKE '%${from}%';" 2>/dev/null
    local left; left=$($Q -e "select count(*) from mac_vod where vod_pic like '%${from}%';" 2>/dev/null)
    say "$note: 改 $n 行,残留 $left"
  else
    say "$note: 待改 $n 行"
  fi
}

echo "════ 封面图床迁移 -> $NEW ════"
run "fmtu.netfhtu.comupload/" "$NEW/upload/"  "① 修 12 行畸形URL(缺斜杠,旧域名已死)"
run "//fh200831.top/"         "//$NEW/"       "② 主力域名 fh200831.top"
run "//fh.lbfh2025.com/"      "//$NEW/"       "③ 零散 fh.lbfh2025.com(同图)"
run "//fmtu.netfhtu.com/"     "//$NEW/"       "④ 零散 fmtu.netfhtu.com(旧404,顺带修好)"

if [ "$APPLY" = 1 ]; then
  dup=$($Q -e "select count(*) from mac_rep where rep_original='fh200831.top' and rep_replacement='$NEW';" 2>/dev/null)
  if [ "${dup:-0}" -eq 0 ]; then
    $QQ -e "INSERT INTO mac_rep (rep_type,rep_original,rep_replacement,rep_note,rep_status,rep_applied,rep_applied_time,rep_create_time)
            VALUES ('视频封面替换','fh200831.top','$NEW','封面图床域名轮转,新旧同源同图,旧域名仍可访问',1,1,UNIX_TIMESTAMP(),UNIX_TIMESTAMP());" 2>/dev/null
    echo "  替换助手已登记 fh200831.top -> $NEW"
  else echo "  替换助手已有该记录,跳过"; fi
  echo "UPDATE mac_rep SET rep_status=0 WHERE rep_original='fh200831.top' AND rep_replacement='$NEW';" >> "$BK/rollback.sql"
fi

echo "── 改后域名分布复核 ──"
$Q -e "select concat('  ',rpad(dm,34,' '),lpad(c,8,' '))
  from (select if(vod_pic like 'http%',substring_index(substring_index(vod_pic,'//',-1),'/',1),
                  if(vod_pic='','(空)','(相对路径)')) dm,count(*) c from mac_vod group by dm) t
  where dm<>'(空)' order by c desc;" 2>/dev/null
[ "$APPLY" = 1 ] && echo "  备份+回滚 -> $BK"
exit 0
