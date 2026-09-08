#!/usr/bin/env bash
# 把三站配置里所有「对外渲染封面地址」的键换到新图床域名。
#
#   bash upd_remoteurl.sh <新域名>            # 预演(打印将改哪些键)
#   bash upd_remoteurl.sh <新域名> --apply    # 执行
#
# 管三个键:
#   upload.remoteurl      相对路径封面(库里存 upload/vod/xxx.jpg,不带域名)靠它拼域名
#                         —— 番号约 6.2 万行 vod_pic + 6 万行 thumb/slide
#   api.vod.imgurl        采集 API 吐给下游的封面基址
#   upload.api.ftp.url    FTP 图床的对外基址(Ftp.php:61 `return $settings['url'].'/'.$file_path`)
#                         —— 只在 upload.mode 切成 ftp 时才被读(Upload.php:38
#                         `if(!in_array($config['mode'],['local','remote']))`),
#                         平时是死配置;一并改是为了将来切换保存方式时不落到空基址。
#
# 三站配置各一份、值还不一样(2026-09-08 前 fhzy1/bjgx 一个图床、fhapi9 另一个),
# 所以逐站读各自当前值,不写死旧域名。
#
# 写法:整份配置数组 var_export 回盘 —— 这正是 maccms 后台保存走的路径
# (common.php mac_arr2file:var_export + opcache_invalidate),实测重新导出与原文件逐字节一致。
#
# 🔴 改的是被 include 的 PHP,写坏 = 整站 500。所以每站都:
#    备份 -> 改 -> php -l -> 重新 include -> **逐键递归 diff,断言只有目标键变了** -> 否则立刻还原。
#    (比 grep 计数强:能证明 art/actor/role/website/link 那 5 个空 imgurl、以及其余 780 行没被碰。)
set -uo pipefail

NEW="${1:-}"; APPLY=0
[ "${2:-}" = "--apply" ] && APPLY=1
if [ -z "$NEW" ]; then echo "用法: bash upd_remoteurl.sh <新域名> [--apply]" >&2; exit 1; fi
NEW="${NEW#http://}"; NEW="${NEW#https://}"; NEW="${NEW%/}"
case "$NEW" in *[!a-zA-Z0-9.-]*|""|.*|*.) echo "域名不合法: $NEW" >&2; exit 1;; esac

PHP=/www/server/php/83/bin/php
SITES="fhzy1.com fhapi9.com bjgx"
BK="/home/migrate-fanhao-20260828/remoteurl-$(date +%Y%m%d-%H%M%S)"
[ "$APPLY" = 1 ] && mkdir -p "$BK"

echo "════ 封面对外基址 -> https://$NEW/ ════"
fail=0
for s in $SITES; do
  CFG="/home/wwwroot/$s/application/extra/maccms.php"
  [ -f "$CFG" ] || { echo "── $s ── 配置不存在,跳过"; continue; }
  echo "── $s ──"
  [ "$APPLY" = 1 ] && cp -p "$CFG" "$BK/$s-maccms.php"

  BKF="$BK/$s-maccms.php" APPLY="$APPLY" NEW="$NEW" $PHP -r '
    $cfg   = $argv[1];
    $new   = getenv("NEW");
    $apply = getenv("APPLY") === "1";
    $bk    = getenv("BKF");
    $url   = "https://$new/";
    // FTP 那处 Ftp.php 拼的是 $url . "/" . $path,自己带斜杠 → 这里不留尾斜杠,避免 //
    $sets = [
      [["upload","remoteurl"],      $url],
      [["api","vod","imgurl"],      $url],
      [["upload","api","ftp","url"], "https://$new"],
    ];

    $get = function($a,$path){ foreach($path as $k){ if(!is_array($a)||!array_key_exists($k,$a)) return null; $a=$a[$k]; } return $a; };
    $set = function(&$a,$path,$v){ $r=&$a; foreach($path as $k){ if(!is_array($r)) $r=[]; if(!array_key_exists($k,$r)) $r[$k]=[]; $r=&$r[$k]; } $r=$v; };
    // 递归比对两个数组,列出所有值不同的路径
    $diff = function($x,$y,$p="") use (&$diff){
      $out=[]; $keys=array_unique(array_merge(array_keys((array)$x),array_keys((array)$y)));
      foreach($keys as $k){
        $px = $p===""?$k:"$p.$k";
        $vx = is_array($x)&&array_key_exists($k,$x)?$x[$k]:"\0NONE";
        $vy = is_array($y)&&array_key_exists($k,$y)?$y[$k]:"\0NONE";
        if(is_array($vx)&&is_array($vy)) $out=array_merge($out,$diff($vx,$vy,$px));
        elseif($vx!==$vy) $out[]=$px;
      }
      return $out;
    };

    $before = include $cfg;
    $after  = $before;
    $todo = [];
    foreach($sets as [$path,$v]){
      $cur = $get($before,$path);
      $label = implode(".",$path);
      printf("    %-24s 现=%-34s 目标=%s\n", $label, var_export($cur,true), $v);
      if($cur !== $v){ $todo[]=$label; $set($after,$path,$v); }
    }
    if(!$todo){ echo "    全部已是目标值,跳过\n"; exit(0); }
    if(!$apply){ printf("    [预演] 待改: %s\n", implode(", ",$todo)); exit(0); }

    // 落盘:与 mac_arr2file 同法
    file_put_contents($cfg, "<?php\nreturn ".var_export($after,true).";\n");
    if(function_exists("opcache_invalidate")) @opcache_invalidate($cfg,true);

    // 自检 ①:语法
    exec("/www/server/php/83/bin/php -l ".escapeshellarg($cfg)." 2>&1", $o, $rc);
    if($rc !== 0){ copy($bk,$cfg); echo "    ✗ 语法检查失败,已还原\n"; exit(2); }
    // 自检 ②:重新读回,逐键递归 diff —— 只允许目标键发生变化
    $reload = include $cfg;
    $changed = $diff($before,$reload);
    sort($changed);
    $expect = ["api.vod.imgurl","upload.api.ftp.url","upload.remoteurl"];
    $unexpected = array_diff($changed,$expect);
    if($unexpected){ copy($bk,$cfg); printf("    ✗ 改动溢出到 %s,已还原\n", implode(", ",$unexpected)); exit(3); }
    foreach($sets as [$path,$v]){
      if($get($reload,$path)!==$v){ copy($bk,$cfg); echo "    ✗ 复核不符,已还原\n"; exit(4); }
    }
    printf("    ✓ 已改 %d 个键,递归 diff 确认无溢出\n", count($changed));
    foreach($sets as [$path,$v]) printf("      %-24s = %s\n", implode(".",$path), $get($reload,$path));
  ' "$CFG" || fail=1
done

if [ "$APPLY" = 1 ]; then
  for s in $SITES; do rm -rf /home/wwwroot/$s/runtime/*/temp/* /home/wwwroot/$s/runtime/cache/* 2>/dev/null; done
  echo "  模板缓存已清(三站)"
  echo "  配置备份 -> $BK"
  echo "  还原: cp $BK/<站>-maccms.php /home/wwwroot/<站>/application/extra/maccms.php"
fi
[ "$fail" -ne 0 ] && { echo "  !! 有站失败,见上"; exit 1; }
exit 0
