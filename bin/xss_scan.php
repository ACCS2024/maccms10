<?php
/**
 * 存量脏数据扫描器（只读，不改任何数据）—— 配合 2026-08 前台 XSS 治理。
 *
 * 用途：修复只对"新写入"加了闸，闸【建立之前】入库的历史行可能仍夹带
 *   - 属性截断向量：URL/名称类字段里的裸引号 " ' 、尖括号 < > 、on事件、js伪协议；
 *   - 存储型 XSS：富文本 *_content 里的 <script>/<iframe>/<svg onload>/on事件/js伪协议；
 *   - 评论/留言里【未实体编码】的裸 HTML（正常数据应是 &lt; 形态）。
 *
 * 运行（在站点根目录所在服务器上）：
 *   php bin/xss_scan.php            # 扫描并打印报告
 *   php bin/xss_scan.php --samples  # 额外打印每类前 5 条样本(截断)
 *
 * 读取站点自身 .env / config/database.php 的连接信息，仅执行 SELECT COUNT / LIMIT。
 * 绝不 UPDATE/DELETE。清洗动作请等这份报告确认后另行执行（可加 --fix 版本）。
 */

$root = dirname(__DIR__);
$showSamples = in_array('--samples', $argv, true);

/* ---------- 解析 DB 连接（兼容 .env 扁平键 / config/database.php 默认值） ---------- */
$env = [];
if (is_file("$root/.env")) {
    // TP 的 .env 多为扁平 KEY=VAL；parse_ini 可能因值含特殊字符失败，手工兜底解析
    $raw = @parse_ini_file("$root/.env", false, INI_SCANNER_RAW);
    if (is_array($raw)) { $env = $raw; }
    if (!$env) {
        foreach (file("$root/.env", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if ($line[0] === '#' || strpos($line, '=') === false) { continue; }
            [$k, $v] = explode('=', $line, 2);
            $env[trim($k)] = trim($v, " \t\"'");
        }
    }
}
$pick = function (array $keys, $def = '') use ($env) {
    foreach ($keys as $k) {
        $g = getenv($k);
        if ($g !== false && $g !== '') { return $g; }
        if (isset($env[$k]) && $env[$k] !== '') { return $env[$k]; }
    }
    return $def;
};
$host   = $pick(['DB_HOST', 'DATABASE.HOSTNAME', 'HOSTNAME'], '127.0.0.1');
$port   = $pick(['DB_PORT', 'DATABASE.HOSTPORT'], '3306');
$dbname = $pick(['DB_NAME', 'DATABASE.DATABASE']);
$user   = $pick(['DB_USER', 'DATABASE.USERNAME']);
$pass   = $pick(['DB_PASS', 'DATABASE.PASSWORD']);
$prefix = $pick(['DB_PREFIX', 'DATABASE.PREFIX'], 'mac_');

if ($dbname === '' || $user === '') {
    fwrite(STDERR, "无法从 .env / 环境变量读取数据库连接（DB_NAME/DB_USER 为空）。\n"
        . "请在站点根目录运行，或先 export DB_HOST/DB_NAME/DB_USER/DB_PASS/DB_PREFIX。\n");
    exit(2);
}

try {
    $pdo = new PDO(
        "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4",
        $user, $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10]
    );
} catch (Throwable $e) {
    fwrite(STDERR, "连接失败: " . $e->getMessage() . "\n");
    exit(2);
}

/* ---------- 检测规则 ---------- */
// 属性截断/URL 类字段：裸引号、尖括号、on事件、js伪协议（合法 URL/名称都不该含）
$ATTR_RX = '(["\'<>]|\\\\bon[a-z]+[[:space:]]*=|javascript:|vbscript:)';
// 富文本正文：真正的可执行结构
$HTML_RX = '(<script|<iframe|<svg|<object|<embed|<form|<math|\\\\bon[a-z]+[[:space:]]*=|javascript:|vbscript:)';
// 评论/留言：出现【裸】危险标签/事件（正常应为 &lt; 实体形态）
$RAW_RX  = '(<script|<iframe|<img|<svg|\\\\bon[a-z]+[[:space:]]*=|javascript:)';

$targets = [
    // 表(去前缀)          列                          规则       类型说明
    ['vod',     ['vod_name','vod_play_url','vod_down_url','vod_pic','vod_pic_thumb','vod_pic_slide','vod_actor','vod_director','vod_remarks','vod_sub'], $ATTR_RX, '属性/URL'],
    ['vod',     ['vod_content','vod_blurb'],                                                        $HTML_RX, '富文本'],
    ['actor',   ['actor_name','actor_pic','actor_remarks','actor_alias'],                           $ATTR_RX, '属性/URL'],
    ['actor',   ['actor_content','actor_blurb'],                                                    $HTML_RX, '富文本'],
    ['art',     ['art_name','art_pic','art_sub','art_remarks'],                                     $ATTR_RX, '属性/URL'],
    ['art',     ['art_content','art_blurb'],                                                        $HTML_RX, '富文本'],
    ['manga',   ['manga_name','manga_pic','manga_sub','manga_remarks'],                             $ATTR_RX, '属性/URL'],
    ['manga',   ['manga_content','manga_blurb'],                                                    $HTML_RX, '富文本'],
    ['role',    ['role_name','role_pic'],                                                           $ATTR_RX, '属性/URL'],
    ['role',    ['role_content'],                                                                   $HTML_RX, '富文本'],
    ['website', ['website_name','website_pic','website_url'],                                       $ATTR_RX, '属性/URL'],
    ['website', ['website_content','website_blurb'],                                                $HTML_RX, '富文本'],
    ['topic',   ['topic_name','topic_pic','topic_pic_slide','topic_sub'],                           $ATTR_RX, '属性/URL'],
    ['topic',   ['topic_blurb','topic_content'],                                                    $HTML_RX, '富文本'],
    ['type',    ['type_name','type_pic'],                                                           $ATTR_RX, '属性/URL'],
    ['comment', ['comment_content','comment_name'],                                                 $RAW_RX,  '裸HTML(应为实体)'],
    ['gbook',   ['gbook_content','gbook_name'],                                                     $RAW_RX,  '裸HTML(应为实体)'],
];

function tableExists(PDO $pdo, string $t): bool {
    try { $pdo->query("SELECT 1 FROM `$t` LIMIT 1"); return true; }
    catch (Throwable $e) { return false; }
}
function colExists(PDO $pdo, string $t, string $c): bool {
    try { $pdo->query("SELECT `$c` FROM `$t` LIMIT 1"); return true; }
    catch (Throwable $e) { return false; }
}

echo "== MacCMS 存量脏数据扫描（只读） ==\n";
echo "库: $dbname  前缀: $prefix  时间: " . date('Y-m-d H:i:s') . "\n";
echo str_repeat('-', 68) . "\n";

$grand = 0;
foreach ($targets as [$tbl, $cols, $rx, $label]) {
    $table = $prefix . $tbl;
    if (!tableExists($pdo, $table)) { continue; }
    foreach ($cols as $col) {
        if (!colExists($pdo, $table, $col)) { continue; }
        try {
            $n = (int)$pdo->query("SELECT COUNT(*) FROM `$table` WHERE `$col` REGEXP '$rx'")->fetchColumn();
        } catch (Throwable $e) {
            fwrite(STDERR, "  [跳过] $table.$col: " . $e->getMessage() . "\n");
            continue;
        }
        if ($n > 0) {
            $grand += $n;
            printf("[命中] %-26s %-8s %6d 行\n", "$tbl.$col", "($label)", $n);
            if ($showSamples) {
                $pk = $tbl . '_id';
                $idcol = colExists($pdo, $table, $pk) ? "`$pk`" : "'?'";
                $rows = $pdo->query("SELECT $idcol AS id, `$col` AS v FROM `$table` WHERE `$col` REGEXP '$rx' LIMIT 5");
                foreach ($rows as $r) {
                    $v = preg_replace('/\s+/', ' ', (string)$r['v']);
                    printf("        id=%-8s %s\n", $r['id'], mb_substr($v, 0, 120));
                }
            }
        }
    }
}
echo str_repeat('-', 68) . "\n";
echo $grand === 0
    ? "✓ 未发现存量脏数据 —— 只对新写入加闸即可，无需清洗。\n"
    : "⚠ 共 $grand 行命中。确认样本后再执行清洗（勿直接改，先备份）。加 --samples 看样本。\n";
