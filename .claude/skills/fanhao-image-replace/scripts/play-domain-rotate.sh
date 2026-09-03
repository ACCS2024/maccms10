#!/usr/bin/env bash
# 播放域名轮转:按【URL 路径里的内容日期】把域名归位
#   5/6月 -> 2605.fhbbff.com   7/8月 -> 2607.fhbbff.com   9月 -> 2609.fhbbff.com
#
# 关键:不能用裸 REPLACE('2607',...) —— "2607" 也出现在路径日期 /20260701/ 里,
# 那样会把 6149 行的播放地址改成 /202609.fhbbff.com01/,整批播不了。
# 这里一律「WHERE 按路径月份限定 + REPLACE 只替换域名串」。
set -uo pipefail
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
BK=/home/migrate-fanhao-20260828/playrot-$(date +%Y%m%d-%H%M%S)
Q="mysql -uroot -p5f6448cd1dd23be0 fhzy1_com -N -B"
QQ="mysql -uroot -p5f6448cd1dd23be0 fhzy1_com"
say(){ [ "$APPLY" = 1 ] && echo "  $*" || echo "  [预演] $*"; }
[ "$APPLY" = 1 ] && mkdir -p "$BK"

# 路径月份表达式:https://host/YYYYMMDD/... 的第 4 段取前 6 位
YM="substring(substring_index(substring_index(vod_play_url,'/',4),'/',-1),1,6)"

run_bucket() {  # $1=旧域名 $2=新域名 $3=月份 IN 列表 $4=说明
  local old="$1" new="$2" months="$3" note="$4"
  local where="vod_play_url like '%${old}/%' and $YM in ($months)"
  local n; n=$($Q -e "select count(*) from mac_vod where $where;" 2>/dev/null)
  if [ "${n:-0}" -eq 0 ]; then say "$old -> $new ($note): 0 行,跳过"; return; fi

  if [ "$APPLY" = 1 ]; then
    # 备份受影响行
    $Q -e "select vod_id, vod_play_url from mac_vod where $where;" 2>/dev/null \
       > "$BK/$(echo "$old-$new" | tr '.' '_').tsv"
    # 回滚
    echo "UPDATE mac_vod SET vod_play_url=REPLACE(vod_play_url,'${new}','${old}') WHERE vod_play_url LIKE '%${new}/%' AND $YM IN (${months});" >> "$BK/rollback.sql"
    # mac_rep 登记(判重)
    local dup; dup=$($Q -e "select count(*) from mac_rep where rep_original='$old' and rep_replacement='$new' and rep_type='视频播放地址';" 2>/dev/null)
    if [ "${dup:-0}" -eq 0 ]; then
      $QQ -e "INSERT INTO mac_rep (rep_type,rep_original,rep_replacement,rep_note,rep_status,rep_applied,rep_applied_time,rep_create_time)
              VALUES ('视频播放地址','$old','$new','$note(按内容日期轮转)',1,1,UNIX_TIMESTAMP(),UNIX_TIMESTAMP());" 2>/dev/null
    fi
    $QQ -e "UPDATE mac_vod SET vod_play_url=REPLACE(vod_play_url,'${old}','${new}') WHERE $where;" 2>/dev/null
    local left; left=$($Q -e "select count(*) from mac_vod where $where;" 2>/dev/null)
    say "$old -> $new ($note): 改 $n 行,残留 $left"
  else
    say "$old -> $new ($note): 待改 $n 行"
  fi
}

echo "════ 按内容日期归位播放域名 ════"
run_bucket "2605.fhbbff.com" "2607.fhbbff.com" "'202607','202608'" "7/8月内容"
run_bucket "2604.fhbbff.com" "2605.fhbbff.com" "'202605','202606'" "5/6月内容"
run_bucket "2605.fhbbff.com" "2609.fhbbff.com" "'202609'"          "9月内容"

echo "── 改后复核:域名 × 路径月 是否已全部一致 ──"
$Q -e "
select concat('  ', rpad(dom,20,' '), ' 路径月 ', ym, '  ', lpad(c,6,' '), '  ',
              if(should=dom or should='(无规则)','✓','✗ 应为 '), if(should=dom or should='(无规则)','',should))
from (select substring_index(substring_index(vod_play_url,'//',-1),'/',1) dom,
             $YM ym,
             case $YM when '202605' then '2605.fhbbff.com' when '202606' then '2605.fhbbff.com'
                      when '202607' then '2607.fhbbff.com' when '202608' then '2607.fhbbff.com'
                      when '202609' then '2609.fhbbff.com' else '(无规则)' end should,
             count(*) c
      from mac_vod where vod_play_url regexp '//26[0-9][0-9][.]fhbbff[.]com/'
      group by dom, ym, should) t
order by ym, dom;" 2>/dev/null

[ "$APPLY" = 1 ] && echo "  备份+回滚 -> $BK"
exit 0
