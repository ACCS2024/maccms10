<?php
/** Additive backup schema on a dedicated MySQL database; no application/site bootstrap. */
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/migration/lib/VodCoverBackupMigration.php';
if (getenv('VOD_COVER_AUDIT_MYSQL') !== '1') { throw new RuntimeException('Explicit dedicated MySQL fixture required'); }
$pdo = new PDO('mysql:host=' . (getenv('VOD_COVER_AUDIT_HOST') ?: '127.0.0.1') . ';dbname=maccms_audit_ai_cover;charset=utf8mb4',
    'root', getenv('VOD_COVER_AUDIT_PASSWORD') ?: '', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES=>false]);
$prefix = 'cover_schema_audit_';
$table = $prefix . 'vod';
$create = static function (string $extra = '', string $engine = 'InnoDB') use ($pdo, $table): void {
    $pdo->exec('DROP TABLE IF EXISTS `' . $table . '`');
    $pdo->exec('CREATE TABLE `' . $table . '` (vod_id INT UNSIGNED PRIMARY KEY, vod_pic VARCHAR(1024) NOT NULL, '
        . 'vod_pic_thumb VARCHAR(1024) NOT NULL, vod_pic_original VARCHAR(1024) NOT NULL' . $extra . ') ENGINE=' . $engine);
};
$reject = static function (callable $operation, string $message): void {
    try { $operation(); } catch (RuntimeException | InvalidArgumentException $error) { check(true, $message); return; }
    check(false, $message);
};
try {
    foreach (['', 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'] as $mode) {
        $pdo->exec('SET SESSION sql_mode=' . $pdo->quote($mode));
        $create();
        $pdo->exec("INSERT INTO `$table` VALUES (1,'current-cover.png','current-thumb.png','old-cover.png'),(2,'','','')");
        $before = $pdo->query('SELECT * FROM `' . $table . '` ORDER BY vod_id')->fetchAll(PDO::FETCH_ASSOC);
        $migration = new VodCoverBackupMigration($pdo, $prefix);
        $report = $migration->preflight();
        check($report['blockers'] === [] && count($report['changes']) === 1 && $report['rewrites_existing_data'] === false, 'Preflight did not identify only the additive backup column');
        check($pdo->query('SELECT * FROM `' . $table . '` ORDER BY vod_id')->fetchAll(PDO::FETCH_ASSOC) === $before, 'Read-only preflight changed existing data or columns');
        $pdo->beginTransaction();
        $reject(fn() => $migration->apply(), 'Migration accepted an outer transaction');
        check($pdo->inTransaction(), 'Migration implicitly committed the caller transaction');
        $pdo->rollBack();
        $report = $migration->apply();
        check($report['blockers'] === [] && $report['changes'] === [], 'Applied schema did not pass preflight');
        $after = $pdo->query('SELECT * FROM `' . $table . '` ORDER BY vod_id')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($after as $i => $row) {
            check(array_key_exists('vod_pic_thumb_original', $row) && $row['vod_pic_thumb_original'] === null, 'Historical thumbnail state was guessed');
            unset($row['vod_pic_thumb_original']);
            check($row === $before[$i], 'Migration changed an existing image pointer');
        }
        check($migration->apply()['changes'] === [], 'Migration is not idempotent');
        $pdo->exec("UPDATE `$table` SET vod_pic_thumb_original='' WHERE vod_id=2");
        check($pdo->query("SELECT vod_pic_thumb_original FROM `$table` WHERE vod_id=2")->fetchColumn() === '', 'Known empty thumbnail cannot be distinguished from missing backup');
        $create(', vod_pic_thumb_original VARCHAR(255) NOT NULL DEFAULT \'\'');
        check($migration->preflight()['blockers'] === ['original_thumbnail_definition_requires_review'], 'Incompatible existing backup column was silently changed');
        $reject(fn() => $migration->apply(), 'Incompatible schema applied without review');
        $create('', 'MyISAM');
        check($migration->preflight()['blockers'] === ['vod_table_missing_or_not_innodb'], 'Nontransactional video table was accepted');
    }
    $ddl = file_get_contents(dirname(__DIR__) . '/application/install/sql/install.sql');
    check(preg_match('/CREATE TABLE `mac_vod` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match) === 1, 'Installer video DDL missing');
    $pdo->exec('DROP TABLE IF EXISTS `' . $table . '`');
    $pdo->exec(str_replace('`mac_vod`', '`' . $table . '`', $match[0]));
    $report = (new VodCoverBackupMigration($pdo, $prefix))->preflight();
    check($report['blockers'] === [] && $report['changes'] === [], 'New installation is not compatible with explicit migration');
    $reject(fn() => new VodCoverBackupMigration($pdo, 'bad`prefix'), 'Unsafe table prefix accepted');
    echo "Video cover schema: {$checks} checks passed on PHP " . PHP_VERSION . " / MySQL\n";
} finally { if ($pdo->inTransaction()) { $pdo->rollBack(); } $pdo->exec('DROP TABLE IF EXISTS `' . $table . '`'); }
