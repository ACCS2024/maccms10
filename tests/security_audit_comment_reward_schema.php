<?php
/** Explicit MySQL DDL on a dedicated fixture table, never a business connection. */
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/migration/lib/CommentRewardMigration.php';
if (getenv('MEMBERSHIP_AUDIT_MYSQL') !== '1') { throw new RuntimeException('Run with explicit MEMBERSHIP_AUDIT_MYSQL=1 fixture settings'); }
$pdo = new PDO('mysql:host=' . (getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1') . ';dbname=maccms_audit_membership;charset=utf8mb4',
    'root', getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$prefix = 'audit_provenance_';
$ddl = file_get_contents(dirname(__DIR__) . '/application/install/sql/install.sql');
if (!preg_match('/CREATE TABLE `mac_comment` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Installed comment DDL missing'); }
$installedDdl = str_replace('`mac_comment`', '`audit_provenance_comment`', $match[0]);
function provenanceSchemaSeed(bool $installed = false): void {
    global $pdo,$installedDdl;
    $pdo->exec('DROP TABLE IF EXISTS audit_provenance_comment');
    $pdo->exec($installedDdl);
    if (!$installed) {
        $pdo->exec('ALTER TABLE audit_provenance_comment DROP INDEX comment_reward_user, DROP COLUMN comment_reward_verified');
    }
    $pdo->exec("INSERT INTO audit_provenance_comment (comment_id,user_id,comment_name,comment_content,comment_time)
        VALUES (1,1,'legacy','Past identity may be forged',1999999999),(2,2,'legacy','Do not backfill',1)");
}
function provenanceSchemaRows(): array {
    global $pdo;
    return $pdo->query('SELECT comment_id,user_id,comment_name,comment_content,comment_time FROM audit_provenance_comment ORDER BY comment_id')->fetchAll(PDO::FETCH_ASSOC);
}
$migration = new CommentRewardMigration($pdo,$prefix);
provenanceSchemaSeed();
$before = provenanceSchemaRows();
$schema = $pdo->query('SHOW CREATE TABLE audit_provenance_comment')->fetch(PDO::FETCH_NUM)[1];
$report = $migration->preflight();
check(!$report['blockers'] && count($report['changes']) === 1 && $report['existing_rows'] === 2
    && $report['verified_rows'] === 0 && $report['backfill_verified'] === false, 'Legacy preflight did not describe the forward-only migration');
check(provenanceSchemaRows() === $before && $pdo->query('SHOW CREATE TABLE audit_provenance_comment')->fetch(PDO::FETCH_NUM)[1] === $schema,
    'Read-only preflight changed rows or schema');
$after = $migration->apply();
check(!$after['changes'] && !$after['blockers'] && $after['verified_rows'] === 0
    && provenanceSchemaRows() === $before, 'Migration changed legacy content or promoted its provenance');
check((int)$pdo->query('SELECT COUNT(*) FROM audit_provenance_comment WHERE comment_reward_verified=0')->fetchColumn() === 2,
    'Legacy rows were not defaulted to unverified');
$pdo->exec("INSERT INTO audit_provenance_comment (comment_id,user_id,comment_name,comment_content) VALUES (3,1,'ordinary','still unverified')");
check((int)$pdo->query('SELECT comment_reward_verified FROM audit_provenance_comment WHERE comment_id=3')->fetchColumn() === 0,
    'Database default automatically trusted an ordinary new row');
$pdo->exec('UPDATE audit_provenance_comment SET comment_reward_verified=1 WHERE comment_id=3');
$before = provenanceSchemaRows();
$again = $migration->apply();
check(!$again['changes'] && !$again['blockers'] && $again['verified_rows'] === 1 && provenanceSchemaRows() === $before,
    'Idempotent rerun changed existing rows or revoked a post-migration verified row');
provenanceSchemaSeed(true);
check($migration->preflight()['changes'] === [], 'Fresh install schema requires another migration');

foreach (['invalid_value','wrong_default','wrong_type','conflicting_index'] as $case) {
    provenanceSchemaSeed(true);
    if ($case === 'invalid_value') { $pdo->exec('UPDATE audit_provenance_comment SET comment_reward_verified=2 WHERE comment_id=1'); }
    if ($case === 'wrong_default') { $pdo->exec('ALTER TABLE audit_provenance_comment ALTER COLUMN comment_reward_verified SET DEFAULT 1'); }
    if ($case === 'wrong_type') { $pdo->exec('ALTER TABLE audit_provenance_comment MODIFY comment_reward_verified VARCHAR(4) NOT NULL DEFAULT 0'); }
    if ($case === 'conflicting_index') {
        $pdo->exec('ALTER TABLE audit_provenance_comment DROP INDEX comment_reward_user, ADD INDEX comment_reward_user (comment_time)');
    }
    $before = provenanceSchemaRows();
    check($migration->preflight()['blockers'] !== [], "$case was not blocked for manual review");
    $blocked = false;
    try { $migration->apply(); } catch (RuntimeException $error) { $blocked = true; }
    check($blocked && provenanceSchemaRows() === $before, "$case was silently rewritten during apply");
}
foreach (['`bad', 'unsafe-prefix', str_repeat('x',58)] as $bad) {
    $blocked = false;
    try { new CommentRewardMigration($pdo,$bad); } catch (InvalidArgumentException $error) { $blocked = true; }
    check($blocked, 'Unsafe or overlong table prefix was accepted');
}
$pdo->exec('DROP TABLE audit_provenance_comment');
check($migration->preflight()['blockers'] !== [], 'Missing comment table was not blocked');
echo "comment reward schema audit: $checks checks passed on PHP " . PHP_VERSION . " / MySQL\n";
