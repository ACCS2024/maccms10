<?php
declare(strict_types=1);
/** Standalone CLI. No application bootstrap, .env or implicit business connection. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require __DIR__ . '/lib/CommentRewardMigration.php';
$options = getopt('', ['help','apply']);
if (isset($options['help'])) {
    echo "Usage: php migration/verify-comment-rewards.php [--apply]\n"
        . "Default is read-only preflight. Set COMMENT_REWARD_SCHEMA_DSN, COMMENT_REWARD_SCHEMA_USER,\n"
        . "COMMENT_REWARD_SCHEMA_PASSWORD and optional COMMENT_REWARD_SCHEMA_PREFIX (default mac_).\n"
        . "Apply adds a default-zero provenance flag and eligibility index. Existing comments are never verified automatically.\n"
        . "Use a maintenance window and a verified backup for existing tables.\n";
    exit(0);
}
try {
    foreach (array_slice($argv, 1) as $argument) {
        if ($argument !== '--apply') { throw new InvalidArgumentException('Unknown option'); }
    }
    $dsn = getenv('COMMENT_REWARD_SCHEMA_DSN');
    if (!is_string($dsn) || !str_starts_with($dsn, 'mysql:')) {
        throw new InvalidArgumentException('Set an explicit mysql COMMENT_REWARD_SCHEMA_DSN with dbname');
    }
    $pdo = new PDO($dsn, getenv('COMMENT_REWARD_SCHEMA_USER') ?: '', getenv('COMMENT_REWARD_SCHEMA_PASSWORD') ?: '',
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES=>false]);
    $prefix = getenv('COMMENT_REWARD_SCHEMA_PREFIX');
    $migration = new CommentRewardMigration($pdo, $prefix === false ? 'mac_' : $prefix);
    $report = $migration->preflight();
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
    if ($report['blockers']) { exit(1); }
    if (array_key_exists('apply', $options)) {
        $after = $migration->apply();
        echo json_encode(['after'=>$after], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
        exit($after['blockers'] || $after['changes'] ? 1 : 0);
    }
    exit(0);
} catch (PDOException $error) {
    fwrite(STDERR, "Comment reward migration failed (database error). Inspect the database and rerun preflight.\n");
    exit(1);
} catch (Throwable $error) {
    fwrite(STDERR, 'Comment reward migration failed: ' . $error->getMessage() . "\n");
    exit(1);
}
