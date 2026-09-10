<?php
declare(strict_types=1);
/** Standalone CLI; intentionally does not load the application or read its .env. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require __DIR__ . '/lib/PaymentSchemaMigration.php';
$options = getopt('', ['help', 'apply']);
if (isset($options['help'])) {
    echo "Usage: php migration/harden-payment-schema.php [--apply]\n"
        . "Default is read-only preflight. Set PAYMENT_SCHEMA_DSN, PAYMENT_SCHEMA_USER,\n"
        . "PAYMENT_SCHEMA_PASSWORD and optional PAYMENT_SCHEMA_PREFIX (default mac_).\n"
        . "Apply requires a maintenance window: widening the ledger column rebuilds it and blocks writes.\n";
    exit(0);
}
try {
    $dsn = getenv('PAYMENT_SCHEMA_DSN');
    if (!is_string($dsn) || !str_starts_with($dsn, 'mysql:')) {
        throw new InvalidArgumentException('Set an explicit mysql PAYMENT_SCHEMA_DSN with dbname');
    }
    $username = getenv('PAYMENT_SCHEMA_USER');
    $password = getenv('PAYMENT_SCHEMA_PASSWORD');
    $pdo = new PDO($dsn, $username === false ? '' : $username, $password === false ? '' : $password,
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES=>false]);
    $prefix = getenv('PAYMENT_SCHEMA_PREFIX');
    $migration = new PaymentSchemaMigration($pdo, $prefix === false ? 'mac_' : $prefix);
    $report = $migration->preflight();
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
    if ($report['blockers']) { exit(1); }
    if (array_key_exists('apply', $options)) {
        $after = $migration->apply();
        echo json_encode(['after'=>$after], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
        exit($after['blockers'] || $after['changes'] ? 1 : 0);
    }
    exit(0);
} catch (PDOException $e) {
    // Driver messages may contain connection details or the duplicated order code.
    fwrite(STDERR, "Payment schema operation failed (database error). Inspect the database and rerun preflight.\n");
    exit(1);
} catch (Throwable $e) {
    fwrite(STDERR, "Payment schema operation failed: " . $e->getMessage() . "\n");
    exit(1);
}
