<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require __DIR__ . '/lib/VodCoverBackupMigration.php';
try {
    $apply = false;
    foreach (array_slice($argv, 1) as $argument) {
        if ($argument === '--help') {
            echo "Usage: php migration/add-vod-cover-backup.php [--apply]\nDefault: read-only preflight. Set VOD_COVER_SCHEMA_DSN (mysql with explicit dbname),\nVOD_COVER_SCHEMA_USER, VOD_COVER_SCHEMA_PASSWORD and optional VOD_COVER_SCHEMA_PREFIX (mac_).\nAdds nullable thumbnail backup state; preserves all historical image values.\n";
            exit(0);
        }
        if ($argument !== '--apply') { throw new InvalidArgumentException('Unknown option'); }
        $apply = true;
    }
    $dsn = getenv('VOD_COVER_SCHEMA_DSN');
    if (!is_string($dsn) || !str_starts_with($dsn, 'mysql:') || !preg_match('/(?:^mysql:|;)dbname=[^;]+/', $dsn)) {
        throw new InvalidArgumentException('Set VOD_COVER_SCHEMA_DSN with an explicit database');
    }
    $pdo = new PDO($dsn, getenv('VOD_COVER_SCHEMA_USER') ?: '', getenv('VOD_COVER_SCHEMA_PASSWORD') ?: '',
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES=>false]);
    $prefix = getenv('VOD_COVER_SCHEMA_PREFIX');
    $migration = new VodCoverBackupMigration($pdo, $prefix === false ? 'mac_' : $prefix);
    $report = $migration->preflight();
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n";
    if ($report['blockers']) { exit(1); }
    if ($apply) { $report = $migration->apply(); echo json_encode(['after'=>$report], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n"; }
    exit($report['blockers'] || ($apply && $report['changes']) ? 1 : 0);
} catch (PDOException $error) {
    fwrite(STDERR, "Cover schema database operation failed; inspect and rerun preflight.\n"); exit(1);
} catch (Throwable $error) {
    fwrite(STDERR, 'Cover schema migration failed: ' . $error->getMessage() . "\n"); exit(1);
}
