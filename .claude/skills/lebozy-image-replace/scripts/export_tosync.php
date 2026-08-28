<?php
/**
 * 「旧活新无」型域名(如 vip3.lbbf9.com):导出其全部真实图片 URL 清单,
 * 交图床运营方把这些图同步到新域名同路径,同步完再强制 replace。
 *
 *   php export_tosync.php <webroot> <该域名> [输出路径]
 * 例:php export_tosync.php /home/wwwroot/lebozy.com vip3.lbbf9.com /tmp/tosync.txt
 *
 * 输出每行:vod_id \t 原图URL。同时打印去掉域名后的路径样例,便于图床方比对。
 */
require __DIR__ . "/_db.php";

$root = $argv[1] ?? "/home/wwwroot/lebozy.com";
$d    = $argv[2] ?? null;
$out  = $argv[3] ?? "/tmp/tosync-" . preg_replace('/[^a-z0-9]/i', '_', (string)$d) . "-" . date("Ymd-His") . ".txt";
if (!$d) { fwrite(STDERR, "用法: php export_tosync.php <webroot> <域名> [输出]\n"); exit(1); }

$pdo = lb_pdo($root);
$rows = $pdo->query("SELECT vod_id, vod_pic FROM mac_vod WHERE vod_pic LIKE '%$d%'")->fetchAll(PDO::FETCH_NUM);
$fp = fopen($out, "w");
foreach ($rows as $r) { fwrite($fp, $r[0] . "\t" . $r[1] . "\n"); }
fclose($fp);

echo "导出 " . count($rows) . " 条 -> $out\n";
echo "样例路径(图床方需把这些图放到新域名同路径):\n";
foreach (array_slice($rows, 0, 5) as $r) {
    echo "  " . preg_replace('#^https?://[^/]+#', '', $r[1]) . "\n";
}
