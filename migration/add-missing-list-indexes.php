<?php

declare(strict_types=1);

/**
 * 给【存量】maccms 库补齐列表/排行/深分页所需的复合索引(幂等)。
 *
 * 为什么需要这个脚本
 * ------------------
 * application/common/model/Vod.php 的深分页快车道写的是
 *     Db::name('Vod')->force('idx_vod_status_recycle_time')
 * 而这批索引以前【只在 install.sql 之外手工建过】—— 2026-08-26 乐播那台是在事故
 * 处理时临时加的。结果是:任何按 install.sql 全新装出来的库,一旦请求走到深分页,
 * FORCE INDEX 指向不存在的索引会直接抛
 *     SQLSTATE[42000] 1176 Key 'idx_vod_status_recycle_time' doesn't exist
 * 页面 500 —— 不是慢,是崩。
 *
 * install.sql 已补上(新装的库自带),本脚本负责已经装好的老库。
 *
 * 用法(在站点根目录执行):
 *     php migration/add-missing-list-indexes.php --dsn=... 或直接读站点 .env
 *     php migration/add-missing-list-indexes.php [--dry-run]
 */

$root = dirname(__DIR__);

function fail(string $m): never { fwrite(STDERR, "[fail] {$m}\n"); exit(1); }
function out(string $m): void { fwrite(STDOUT, "[index] {$m}\n"); }

/** 读取站点根目录 .env 里的数据库凭据 */
function readEnv(string $root): array
{
    $file = $root . '/.env';
    if (!is_file($file)) {
        fail("找不到 {$file},请在站点根目录运行");
    }
    $cfg = [];
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === ';' || $line[0] === '#' || !str_contains($line, '=')) {
            continue;
        }
        [$k, $v] = explode('=', $line, 2);
        $cfg[trim($k)] = trim($v);
    }
    foreach (['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASS'] as $k) {
        if (!isset($cfg[$k])) {
            fail(".env 缺少 {$k}");
        }
    }
    return $cfg;
}

// 表 => [索引名 => 列]
const WANTED = [
    'vod' => [
        // 深分页快车道 force() 的那一条,缺了直接 500
        'idx_vod_status_recycle_time' => ['vod_status', 'vod_recycle_time', 'vod_time'],
        'idx_st_time'                 => ['vod_status', 'vod_time'],
        'idx_type_st_time'            => ['type_id', 'vod_status', 'vod_time'],
        'idx_type1_st_time'           => ['type_id_1', 'vod_status', 'vod_time'],
        'idx_type_st_hits'            => ['type_id', 'vod_status', 'vod_hits'],
        'idx_st_hits_day'             => ['vod_status', 'vod_hits_day'],
        'idx_st_hits_week'            => ['vod_status', 'vod_hits_week'],
        'idx_st_hits_month'           => ['vod_status', 'vod_hits_month'],
        'idx_st_level_time'           => ['vod_status', 'vod_level', 'vod_time'],
    ],
    'art' => [
        'idx_art_st_time'       => ['art_status', 'art_time'],
        'idx_art_type_st_time'  => ['type_id', 'art_status', 'art_time'],
        'idx_art_type1_st_time' => ['type_id_1', 'art_status', 'art_time'],
    ],
];

$options = getopt('', ['dry-run']);
$dryRun = array_key_exists('dry-run', $options);

$env    = readEnv($root);
$host   = $env['DB_HOST'];
$port   = $env['DB_PORT'] ?? '3306';
$dbName = $env['DB_NAME'];
$prefix = $env['DB_PREFIX'] ?? 'mac_';

$pdo = new PDO(
    "mysql:host={$host};port={$port};dbname={$dbName};charset=utf8mb4",
    $env['DB_USER'],
    $env['DB_PASS'],
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$created = 0;
$skipped = 0;

foreach (WANTED as $shortTable => $indexes) {
    $table = $prefix . $shortTable;

    $stmt = $pdo->prepare(
        'select count(*) from information_schema.tables where table_schema = ? and table_name = ?'
    );
    $stmt->execute([$dbName, $table]);
    if ((int) $stmt->fetchColumn() === 0) {
        out("跳过 {$table}:表不存在");
        continue;
    }

    // 该表现有列,用来跳过 schema 不含某列的老版本库
    $stmt = $pdo->prepare(
        'select column_name from information_schema.columns where table_schema = ? and table_name = ?'
    );
    $stmt->execute([$dbName, $table]);
    $columns = array_flip($stmt->fetchAll(PDO::FETCH_COLUMN));

    foreach ($indexes as $name => $cols) {
        $missingCol = null;
        foreach ($cols as $c) {
            if (!isset($columns[$c])) { $missingCol = $c; break; }
        }
        if ($missingCol !== null) {
            out("跳过 {$table}.{$name}:本库没有列 {$missingCol}");
            $skipped++;
            continue;
        }

        $stmt = $pdo->prepare(
            'select count(*) from information_schema.statistics
              where table_schema = ? and table_name = ? and index_name = ?'
        );
        $stmt->execute([$dbName, $table, $name]);
        if ((int) $stmt->fetchColumn() > 0) {
            $skipped++;
            continue;
        }

        $colSql = '`' . implode('`,`', $cols) . '`';
        $sql = "ALTER TABLE `{$table}` ADD INDEX `{$name}` ({$colSql})";

        if ($dryRun) {
            out("[dry-run] {$sql}");
            $created++;
            continue;
        }

        $t0 = microtime(true);
        $pdo->exec($sql);
        out(sprintf('+ %s.%s (%s)  %.1fs', $table, $name, implode(',', $cols), microtime(true) - $t0));
        $created++;
    }
}

out(sprintf('%s %d 个索引,已存在/跳过 %d 个', $dryRun ? '待创建' : '新建', $created, $skipped));
