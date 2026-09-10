<?php
declare(strict_types=1);
/** Standalone CLI: does not load the application, its .env or any business credentials. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require __DIR__.'/lib/LedgerVisibilityMigration.php';
$options = getopt('', ['help','apply']);
if (isset($options['help'])) {
    echo "Usage: php migration/preserve-ledger-records.php [--apply]\n"
        . "Default is read-only preflight. Set LEDGER_SCHEMA_DSN, LEDGER_SCHEMA_USER,\n"
        . "LEDGER_SCHEMA_PASSWORD and optional LEDGER_SCHEMA_PREFIX (default mac_).\n"
        . "Apply adds a visibility flag and index; it does not delete or rewrite financial fields.\n"
        . "Use a maintenance window and a verified backup for existing tables.\n";
    exit(0);
}
try {
    foreach (array_slice($argv,1) as $argument) {
        if ($argument !== '--apply') { throw new InvalidArgumentException('Unknown option'); }
    }
    $dsn = getenv('LEDGER_SCHEMA_DSN');
    if (!is_string($dsn) || !str_starts_with($dsn,'mysql:')) { throw new InvalidArgumentException('Set an explicit mysql LEDGER_SCHEMA_DSN with dbname'); }
    $pdo = new PDO($dsn, getenv('LEDGER_SCHEMA_USER') ?: '', getenv('LEDGER_SCHEMA_PASSWORD') ?: '', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $prefix = getenv('LEDGER_SCHEMA_PREFIX');
    $migration = new LedgerVisibilityMigration($pdo, $prefix === false ? 'mac_' : $prefix);
    $report = $migration->preflight();
    echo json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),"\n";
    if ($report['blockers']) { exit(1); }
    if (array_key_exists('apply',$options)) {
        $after = $migration->apply();
        echo json_encode(['after'=>$after],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR),"\n";
        exit($after['blockers'] || $after['changes'] ? 1 : 0);
    }
    exit(0);
} catch (PDOException $error) {
    fwrite(STDERR,"Ledger visibility operation failed (database error). Inspect the database and rerun preflight.\n"); exit(1);
} catch (Throwable $error) {
    fwrite(STDERR,'Ledger visibility operation failed: '.$error->getMessage()."\n"); exit(1);
}
