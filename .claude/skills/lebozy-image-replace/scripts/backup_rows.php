<?php
/**
 * 备份将被改的行(vod_id + vod_pic)到 gz。真反悔时按 vod_id 主键回灌。
 *
 *   php backup_rows.php <webroot> <域名逗号分隔> [输出路径]
 * 例:php backup_rows.php /home/wwwroot/lebozy.com "jh.lb260522.top,fmlb.netlbtu.com" /tmp/bk.tsv.gz
 *
 * 注:脚本以 www 跑时写不了 /root,先写 /tmp 再由 root mv 到 backups/。
 */
require __DIR__ . "/_db.php";

$root    = $argv[1] ?? "/home/wwwroot/lebozy.com";
$domsArg = $argv[2] ?? "";
$out     = $argv[3] ?? "/tmp/vod_pic-backup-" . date("Ymd-His") . ".tsv.gz";
if ($domsArg === "") { fwrite(STDERR, "用法: php backup_rows.php <webroot> <域名逗号分隔> [输出]\n"); exit(1); }

$domains = array_filter(array_map("trim", explode(",", $domsArg)));
$pdo = lb_pdo($root);
$f = gzopen($out, "wb");
$n = 0;
foreach ($domains as $d) {
    $st = $pdo->prepare("SELECT vod_id, vod_pic FROM mac_vod WHERE vod_pic LIKE ?");
    $st->execute(["%$d%"]);
    while ($r = $st->fetch(PDO::FETCH_NUM)) { gzwrite($f, $r[0] . "\t" . $r[1] . "\n"); $n++; }
}
gzclose($f);
echo "备份 $n 行 -> $out\n";
echo "回灌示例: zcat $out | while IFS=\$'\\t' read id pic; do mysql ... -e \"UPDATE mac_vod SET vod_pic='\$pic' WHERE vod_id=\$id\"; done\n";
