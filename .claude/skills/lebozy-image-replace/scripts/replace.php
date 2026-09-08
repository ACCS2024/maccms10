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

echo "\n═══ 3. 更新 upload.remoteurl(相对路径封面 + 今后新图)═══\n";
// 各站的相对路径封面 upload/vod/... 不带域名,靠本站 upload.remoteurl 补;
// 只改 vod_pic 不改这里 => 那 52% 老封面 + 今后新图仍打旧域名。必须同步改。
$cfgFile = $root . "/application/extra/maccms.php";
if (!is_file($cfgFile)) {
    echo "  ⚠ 配置文件不存在,跳过: $cfgFile\n";
} else {
    $src = file_get_contents($cfgFile);
    $orig = $src;
    $backedUp = false;
    foreach ($domains as $d) {
        foreach (["https://$d/", "http://$d/"] as $oldUrl) {
            if (strpos($src, $oldUrl) !== false) {
                if (!$backedUp) {
                    $bak = $cfgFile . ".bak-remoteurl-" . date("Ymd-His");
                    @copy($cfgFile, $bak);
                    echo "  备份: $bak\n";
                    $backedUp = true;
                }
                $src = str_replace($oldUrl, "https://$NEW/", $src);
                echo "  改: $oldUrl -> https://$NEW/\n";
            }
        }
    }
    if ($src !== $orig) {
        // 语法自检:确保改完仍是合法 PHP(否则整站崩)
        $tmp = $cfgFile . ".tmp." . getmypid();
        file_put_contents($tmp, $src);
        exec("php -l " . escapeshellarg($tmp) . " 2>&1", $lintOut, $lintRc);
        if ($lintRc !== 0) {
            @unlink($tmp);
            echo "  ❌ 改后语法错,已放弃写入(保持原配置):" . implode(" ", $lintOut) . "\n";
        } else {
            rename($tmp, $cfgFile);
            // 关键坑:root 写过的配置必须 chown 回 www,否则后台/采集/上传保存全静默失败
            @chown($cfgFile, "www"); @chgrp($cfgFile, "www");
            if (preg_match('/[\'"]remoteurl[\'"]\s*=>\s*[\'"]([^\'"]*)[\'"]/', $src, $m)) {
                echo "  ✅ 写入并 chown www:www;现 remoteurl = " . $m[1] . "\n";
            } else {
                echo "  ✅ 写入并 chown www:www\n";
            }
        }
    } else {
        echo "  remoteurl 当前不含待迁域名,无需改动(可能已改过)\n";
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
