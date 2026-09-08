<?php
/**
 * 主替换(一次跑完):
 *   1. 前台「替换助手」mac_rep 登记(引导下游采集方)
 *   2. mac_vod.vod_pic 存量域名替换(http/https 一并归一到 https://B)
 *   3. upload.remoteurl 改成新域名(管 52% 相对路径 upload/vod/... 封面 + 今后新图)
 *      —— 写完自动 chown www:www(否则后台/采集/上传保存全静默失败,踩过的坑)
 *   4. 清 runtime 缓存 + config-shadow(配置改动生效)
 *   5. 打印替换后域名分布
 *
 * 改下面 CONFIG 三项再跑:
 *   php replace.php <webroot>
 *
 * 前置:已跑 classify.php 定好 $domains;已跑 backup_rows.php 备份。
 */
require __DIR__ . "/_db.php";
$root = rtrim($argv[1] ?? "/home/wwwroot/lebozy.com", "/");

// ── CONFIG(2026-09 轮转:lb260817.top → lb260908.top)─────────────────────
$NEW = "lb260908.top";                    // 新图床域名(目标,当前月轮转域名)
$domains = [                              // 要替换的源域名(来自 classify.php:swap+recover)
    "lb260817.top",                       // 上月已收敛到此,本月整域迁到 lb260908
];
$repRegister = ["lb260817.top"];          // 只登记体量大的;杂七杂八的别写
// ─────────────────────────────────────────────────────────────────────────

$pdo = lb_pdo($root);
$now = time();

echo "═══ 1. 前台替换助手登记(rep_type=视频封面替换)═══\n";
$ins = $pdo->prepare(
    "INSERT INTO mac_rep (rep_type,rep_original,rep_replacement,rep_note,rep_status,rep_applied,rep_applied_time,rep_create_time)
     VALUES ('视频封面替换',?,?,?,1,1,?,?)"
);
foreach ($repRegister as $d) {
    $chk = $pdo->prepare("SELECT COUNT(*) FROM mac_rep WHERE rep_original=? AND rep_replacement=?");
    $chk->execute([$d, $NEW]);
    if ($chk->fetchColumn() > 0) { echo "  跳过(已登记): $d\n"; continue; }
    $ins->execute([$d, $NEW, "封面图床域名迁移至 $NEW", $now, $now]);
    echo "  登记: $d -> $NEW (rep_id=" . $pdo->lastInsertId() . ")\n";
}

echo "\n═══ 2. 更新存量 vod_pic ═══\n";
$total = 0;
foreach ($domains as $d) {
    // 全域名带 scheme 匹配,只碰 host 位,不会误伤路径里的数字日期
    $sql = "UPDATE mac_vod
            SET vod_pic = REPLACE(REPLACE(vod_pic,'https://$d','https://$NEW'),'http://$d','https://$NEW')
            WHERE vod_pic LIKE '%$d%'";
    $n = $pdo->query($sql)->rowCount();
    $total += $n;
    printf("  %-24s 改 %6d 行\n", $d, $n);
}
echo "  合计 $total 行\n";

echo "\n═══ 3. 更新图床渲染域名配置(remoteurl + api.ftp.url,都归到 https://B/)═══\n";
// 对外渲染封面用到两处配置,必须都指新域名,否则会漏:
//   · upload.remoteurl —— 相对路径封面 upload/vod/... 不带域名,靠它拼;新图也靠它显示。
//   · upload.api.ftp.url —— 启用 FTP 图床回传时,新上传封面用它拼 URL。乐播现在是空的(不走
//     FTP,采集封面是完整 URL),这里防御性同步:今后一旦启用 FTP 图床,新图也走新域名。
$newUrl  = "https://$NEW/";
$cfgFile = $root . "/application/extra/maccms.php";
if (!is_file($cfgFile)) {
    echo "  ⚠ 配置文件不存在,跳过: $cfgFile\n";
} else {
    $src = file_get_contents($cfgFile);
    $orig = $src;
    // 3a. 先把任何残留旧域名(不限 remoteurl)整域替新
    foreach ($domains as $d) {
        $src = str_replace(["https://$d/", "http://$d/"], $newUrl, $src);
    }
    // 3b. 强制 upload.remoteurl = 新域名(即便原本为空/其它,也拉到新;单行,顶层键)
    $src = preg_replace("/('remoteurl'\s*=>\s*)'[^']*'/", "\${1}'$newUrl'", $src, 1);
    // 3c. 强制 upload.api.ftp.url = 新域名。锚定在 'ftp' => array( ... ) 块内的第一个 'url',
    //     避免误伤同名的 qiniu/upyun 'url'。/s 让 . 跨行;.*? 非贪婪停在 ftp 块内首个 url。
    $src = preg_replace("/('ftp'\s*=>\s*array\s*\(.*?'url'\s*=>\s*)'[^']*'/s", "\${1}'$newUrl'", $src, 1);

    if ($src === $orig) {
        echo "  remoteurl / api.ftp.url 已是 $newUrl,无需改动\n";
    } else {
        // 语法自检:tmp 必须写在 extra/ 外 —— application/middleware/Begin.php 反webshell
        // 中间件会在每次 HTTP 请求里把 extra/ 内非白名单文件删掉,并发请求会在 php -l 前
        // 把 extra/ 里的 tmp 删掉("文件打不开")。放到系统 temp 目录规避。
        $tmp = sys_get_temp_dir() . "/maccms_cfg_lint_" . getmypid() . ".php";
        file_put_contents($tmp, $src);
        exec("php -l " . escapeshellarg($tmp) . " 2>&1", $lintOut, $lintRc);
        @unlink($tmp);
        if ($lintRc !== 0) {
            echo "  ❌ 改后语法错,已放弃写入(保持原配置):" . implode(" ", $lintOut) . "\n";
        } else {
            $bak = $cfgFile . ".bak-remoteurl-" . date("Ymd-His");
            @copy($cfgFile, $bak);          // 备份到 extra/ 内也会被 Begin 扫掉,但这是瞬时的;真备份见 §1 gz
            file_put_contents($cfgFile, $src);   // 直接覆盖白名单文件本身(maccms.php 在白名单,不会被扫)
            // 关键坑:root 写过的配置必须 chown 回 www,否则后台/采集/上传保存全静默失败
            @chown($cfgFile, "www"); @chgrp($cfgFile, "www");
            // 回读确认最终值(读 $src 内容,不 include —— 避 CLI opcache 读到旧文件)
            preg_match("/'remoteurl'\s*=>\s*'([^']*)'/", $src, $mr);
            preg_match("/'ftp'\s*=>\s*array\s*\(.*?'url'\s*=>\s*'([^']*)'/s", $src, $mf);
            printf("  ✅ 写入并 chown www:www;remoteurl=%s  api.ftp.url=%s\n", $mr[1] ?? "?", $mf[1] ?? "?");
        }
    }
}

echo "\n═══ 4. 清 runtime 缓存 + config-shadow ═══\n";
$rt = $root . "/runtime";
$cleared = 0;
foreach ((glob("$rt/index/temp/*.php") ?: []) as $f) { @unlink($f) && $cleared++; }
exec("rm -rf " . escapeshellarg("$rt/cache") . "/* 2>/dev/null");
@unlink("$rt/config-shadow/maccms.php");
echo "  已清 index/temp(*.php $cleared 个)、cache/*、config-shadow/maccms.php\n";

echo "\n═══ 5. 替换后域名分布 ═══\n";
foreach ($pdo->query(
    "SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(vod_pic,'/',3),'//',-1) d, COUNT(*) c
     FROM mac_vod WHERE vod_pic LIKE 'http%' GROUP BY d ORDER BY c DESC") as $r) {
    printf("  %-24s %d\n", $r["d"], $r["c"]);
}
echo "\n完成。验证见 SKILL §5:首页/详情封面直连应全 https://{$NEW} 且 200;/index.php/macrep.html 当前生效值 = {$NEW}\n";
