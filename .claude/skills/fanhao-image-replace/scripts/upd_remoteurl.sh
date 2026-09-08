#!/usr/bin/env bash
# 把三站的 upload.remoteurl / api.vod.imgurl 换到新图床域名。
#
#   bash upd_remoteurl.sh <新域名>            # 预演
#   bash upd_remoteurl.sh <新域名> --apply    # 执行
#
# 管的是「相对路径封面」——库里存 upload/vod/xxx.jpg 不带域名(番号约 6.2 万行 vod_pic
# 另加 6 万行 thumb/slide),前台和采集 API 都靠这两个键拼出完整地址。
# 所以它跟 vod_pic 里写死域名的那批是两套东西,replace-multi.sh 管不到这里。
#
# 三站配置各一份且值不同(fhzy1/bjgx 一个图床,fhapi9 另一个),必须逐站按各自的旧值替换。
#
# 🔴 为什么不能用 sed 's/imgurl.*/.../':配置里 'imgurl' 出现 6 次,只有 api.vod 那处有值,
#    其余 5 处(art/actor/role/website/link)是 '' —— 填错会让采集方拿到错域名。
#    这里改成「按各站当前的确切 URL 原值替换」,只会命中有值的那两处。
#
# 🔴 改的是会被 include 的 PHP 文件,写坏 = 整站 500。所以每站都:
#    先备份 -> 再改 -> php -l 语法检查 -> 重新 include 复核键值 -> 任一步失败立刻还原。
set -uo pipefail

NEW="${1:-}"; APPLY=0
[ "${2:-}" = "--apply" ] && APPLY=1
if [ -z "$NEW" ]; then echo "用法: bash upd_remoteurl.sh <新域名> [--apply]" >&2; exit 1; fi
NEW="${NEW#http://}"; NEW="${NEW#https://}"; NEW="${NEW%/}"
NEWURL="https://$NEW/"

PHP=/www/server/php/83/bin/php
SITES="fhzy1.com fhapi9.com bjgx"
BK="/home/migrate-fanhao-20260828/remoteurl-$(date +%Y%m%d-%H%M%S)"
say(){ [ "$APPLY" = 1 ] && echo "  $*" || echo "  [预演] $*"; }
[ "$APPLY" = 1 ] && mkdir -p "$BK"

# 读某站某个键的当前值
getval(){ # $1=站 $2=php表达式片段
  $PHP -r "\$c=include '/home/wwwroot/$1/application/extra/maccms.php'; echo $2 ?? '';" 2>/dev/null
}

echo "════ upload.remoteurl / api.vod.imgurl -> $NEWURL ════"
fail=0
for s in $SITES; do
  CFG="/home/wwwroot/$s/application/extra/maccms.php"
  [ -f "$CFG" ] || { echo "  $s: 配置不存在,跳过"; continue; }

  cur_r=$(getval "$s" "\$c['upload']['remoteurl']")
  cur_i=$(getval "$s" "\$c['api']['vod']['imgurl']")
  echo "── $s ──"
  echo "    现 remoteurl = $cur_r"
  echo "    现 imgurl    = $cur_i"

  if [ "$cur_r" = "$NEWURL" ] && [ "$cur_i" = "$NEWURL" ]; then
    say "已是目标值,跳过"; continue
  fi

  # 待替换的旧值(去重,只取非空的)
  olds=$(printf '%s\n%s\n' "$cur_r" "$cur_i" | grep -v '^$' | sort -u)
  [ -z "$olds" ] && { echo "    两个键都是空值,跳过(不凭空写入)"; continue; }

  # 预演:报告每个旧值在文件里出现几次
  for o in $olds; do
    n=$(grep -Fc -- "$o" "$CFG")
    echo "    旧值 $o  在配置里出现 $n 次"
    if [ "$n" -gt 2 ]; then
      echo "    !! 出现次数 >2,可能命中预期外的键,本站跳过"; fail=1; continue 2
    fi
  done

  [ "$APPLY" = 1 ] || { say "待改"; continue; }

  cp -p "$CFG" "$BK/$s-maccms.php"
  for o in $olds; do
    $PHP -r '
      $f=$argv[1]; $o=$argv[2]; $n=$argv[3];
      $s=file_get_contents($f);
      file_put_contents($f, str_replace($o,$n,$s));
    ' "$CFG" "$o" "$NEWURL"
  done

  # 自检 ①:语法
  if ! $PHP -l "$CFG" >/dev/null 2>&1; then
    cp -p "$BK/$s-maccms.php" "$CFG"; echo "    ✗ 语法检查失败,已还原"; fail=1; continue
  fi
  # 自检 ②:键值确实变了,且空 imgurl 没被写脏
  new_r=$(getval "$s" "\$c['upload']['remoteurl']")
  new_i=$(getval "$s" "\$c['api']['vod']['imgurl']")
  empties=$(grep -c "'imgurl' => ''," "$CFG")
  if [ "$new_r" != "$NEWURL" ] || [ "$new_i" != "$NEWURL" ]; then
    cp -p "$BK/$s-maccms.php" "$CFG"; echo "    ✗ 复核不符($new_r / $new_i),已还原"; fail=1; continue
  fi
  echo "    ✓ remoteurl=$new_r  imgurl=$new_i   (其它空 imgurl 仍为 $empties 处)"
done

if [ "$APPLY" = 1 ]; then
  for s in $SITES; do rm -rf /home/wwwroot/$s/runtime/*/temp/* /home/wwwroot/$s/runtime/cache/* 2>/dev/null; done
  echo "  模板缓存已清(三站)"
  echo "  配置备份 -> $BK   还原: cp $BK/<站>-maccms.php /home/wwwroot/<站>/application/extra/maccms.php"
fi
[ "$fail" -ne 0 ] && { echo "  !! 有站失败,见上"; exit 1; }
exit 0
