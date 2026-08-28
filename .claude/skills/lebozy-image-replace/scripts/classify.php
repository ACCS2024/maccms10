<?php
/**
 * 安全闸:列出 mac_vod.vod_pic 里所有 http 域名,逐个取样,把「换成新域名 B、路径不动」
 * 后的结果分三类:同图可换 / 旧死新活=恢复 / 旧活新无=需先同步。
 *
 *   php classify.php <webroot> <新域名B> [每域名取样数=2]
 * 例:php classify.php /home/wwwroot/lebozy.com lb260817.top 3
 *
 * 只读,不改任何数据。输出直接决定 replace.php 的 $domains 该放哪些。
 */
require __DIR__ . "/_db.php";

$root = $argv[1] ?? "/home/wwwroot/lebozy.com";
$B    = $argv[2] ?? null;
$n    = max(1, (int)($argv[3] ?? 2));
if (!$B) { fwrite(STDERR, "用法: php classify.php <webroot> <新域名B> [取样数]\n"); exit(1); }

$pdo = lb_pdo($root);

$domains = $pdo->query(
    "SELECT SUBSTRING_INDEX(SUBSTRING_INDEX(vod_pic,'/',3),'//',-1) d, COUNT(*) c
     FROM mac_vod WHERE vod_pic LIKE 'http%' GROUP BY d ORDER BY c DESC"
)->fetchAll(PDO::FETCH_ASSOC);

function probe($url)
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_NOBODY => 0, CURLOPT_RETURNTRANSFER => 1, CURLOPT_TIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => 1, CURLOPT_SSL_VERIFYPEER => 0]);
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $size = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
    curl_close($ch);
    return [(int)$code, (int)$size];
}

$buckets = ['swap' => [], 'recover' => [], 'needsync' => [], 'unknown' => []];
printf("%-26s %8s  判定\n", "域名", "条数");
echo str_repeat("-", 60), "\n";
foreach ($domains as $row) {
    $d = $row["d"]; $c = $row["c"];
    if ($d === $B) { printf("%-26s %8d  = 目标域名(跳过)\n", $d, $c); continue; }
    $st = $pdo->prepare("SELECT vod_pic FROM mac_vod WHERE vod_pic LIKE ? LIMIT $n");
    $st->execute(["http%$d%"]);
    $same = 0; $oldOk = 0; $newOk = 0; $tot = 0;
    foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $u) {
        $tot++;
        [$oc, $os] = probe($u);
        [$nc, $ns] = probe(preg_replace('#^https?://' . preg_quote($d, '#') . '#', "https://$B", $u));
        if ($oc == 200) $oldOk++;
        if ($nc == 200) $newOk++;
        if ($oc == 200 && $nc == 200 && $os == $ns && $os > 0) $same++;
    }
    if ($newOk == $tot && $same == $tot)            { $verdict = "✅ 同图可换";      $buckets['swap'][] = $d; }
    elseif ($newOk == $tot && $oldOk < $tot)        { $verdict = "🔵 旧死新活=恢复"; $buckets['recover'][] = $d; }
    elseif ($newOk < $tot && $oldOk == $tot)        { $verdict = "❌ 旧活新无=需先同步"; $buckets['needsync'][] = $d; }
    elseif ($newOk == $tot)                         { $verdict = "✅ 新域可取(建议换)"; $buckets['swap'][] = $d; }
    else                                            { $verdict = "⚠ 新域取不全(核对)"; $buckets['unknown'][] = $d; }
    printf("%-26s %8d  %s (旧%d/新%d/同图%d, 共%d样)\n", $d, $c, $verdict, $oldOk, $newOk, $same, $tot);
}
echo "\n建议 replace.php \$domains(可安全换 + 恢复类):\n  ";
echo implode(", ", array_map(fn($x) => "\"$x\"", array_merge($buckets['swap'], $buckets['recover']))), "\n";
if ($buckets['needsync']) {
    echo "\n需先同步再强制换(export_tosync.php 导清单交图床方):\n  ";
    echo implode(", ", $buckets['needsync']), "\n";
}
