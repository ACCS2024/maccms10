<?php
/**
 * 主替换:mac_vod.vod_pic 里指定源域名 → 新域名 B(http/https 一并归一到 https://B),
 * 并往前台「替换助手」mac_rep 登记体量大的那几个(引导下游采集方)。
 *
 * 改下面 CONFIG 三项再跑:
 *   php replace.php <webroot>
 *
 * 前置:已跑 classify.php 定好 $domains;已跑 backup_rows.php 备份。
 */
require __DIR__ . "/_db.php";
$root = $argv[1] ?? "/home/wwwroot/lebozy.com";

// ── CONFIG ───────────────────────────────────────────────────────────────
$NEW = "lb260817.top";                    // 新图床域名(目标)
$domains = [                              // 要替换的源域名(来自 classify.php:swap+recover)
    "jh.lb260522.top", "fmlb.netlbtu.com", "f.lbp2025.com",
    "lb260401.top", "le.lebsltu2025627.com", "fm.lbtup2025.com", "fw.lbbf9.com",
];
$repRegister = ["jh.lb260522.top", "fmlb.netlbtu.com"];  // 只登记体量大的;杂七杂八的别写
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
    $sql = "UPDATE mac_vod
            SET vod_pic = REPLACE(REPLACE(vod_pic,'https://$d','https://$NEW'),'http://$d','https://$NEW')
            WHERE vod_pic LIKE '%$d%'";
    $n = $pdo->query($sql)->rowCount();
    $total += $n;
    printf("  %-24s 改 %6d 行\n", $d, $n);
}
echo "  合计 $total 行\n";

echo "\n═══ 3. 替换后域名分布 ═══\n";
foreach ($pdo->query(
    "SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(vod_pic,'/',3),'//',-1) d, COUNT(*) c
     FROM mac_vod WHERE vod_pic LIKE 'http%' GROUP BY d ORDER BY c DESC") as $r) {
    printf("  %-24s %d\n", $r["d"], $r["c"]);
}
echo "\n提醒:还要改 upload.remoteurl(管相对路径老封面+新图)、清 runtime 缓存与 config-shadow。见 SKILL §3/§5。\n";
