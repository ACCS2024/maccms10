<?php
/** Real MySQL only: standalone preflight/DDL plus ORM behavior at storage boundaries. */
if (getenv('MEMBERSHIP_AUDIT_MYSQL') !== '1') {
    echo "SKIP payment schema audit: set MEMBERSHIP_AUDIT_MYSQL=1 for the isolated fixture database\n";
    exit(0);
}
require __DIR__ . '/fixtures/security_audit_membership_db.php';
require dirname(__DIR__) . '/migration/lib/PaymentSchemaMigration.php';
use think\facade\Db;
use app\common\model\Order;

$dsn = 'mysql:host=' . (getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1') . ';dbname=maccms_audit_membership;charset=utf8mb4';
$password = getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '';
$pdo = new PDO($dsn, 'root', $password, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES=>false]);
$migration = new PaymentSchemaMigration($pdo, 'audit_');
function schemaSnapshot(PDO $pdo): array {
    $out = [];
    foreach (['order', 'plog'] as $table) {
        // Insert attempts can advance InnoDB counters even after a unique-key rejection.
        $out[] = preg_replace('/ AUTO_INCREMENT=\d+/', '', $pdo->query('SHOW CREATE TABLE audit_' . $table)->fetch(PDO::FETCH_NUM)[1]);
    }
    return $out;
}
function schemaLegacy(PDO $pdo): void {
    membershipSeed();
    $pdo->exec('ALTER TABLE audit_order DROP INDEX order_code, ADD INDEX order_code (order_code)');
    $pdo->exec('ALTER TABLE audit_plog MODIFY plog_points SMALLINT UNSIGNED NOT NULL DEFAULT 0');
}
function schemaOrder(string $code, int $points = 100, string $price = '1.00'): array {
    return ['user_id'=>1, 'order_code'=>$code, 'order_price'=>$price, 'order_points'=>$points];
}
function schemaCli(array $arguments, array $environment): array {
    $pipes = [];
    $process = proc_open([PHP_BINARY, dirname(__DIR__) . '/migration/harden-payment-schema.php', ...$arguments],
        [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes, null, $environment);
    if (!is_resource($process)) { throw new RuntimeException('Cannot start isolated migration CLI'); }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $error = stream_get_contents($pipes[2]); fclose($pipes[2]);
    return [proc_close($process), $output, $error];
}
$environment = ['PAYMENT_SCHEMA_DSN'=>$dsn, 'PAYMENT_SCHEMA_USER'=>'root', 'PAYMENT_SCHEMA_PASSWORD'=>$password,
    'PAYMENT_SCHEMA_PREFIX'=>'audit_'];

$report = $migration->preflight();
check($report['blockers'] === [] && $report['changes'] === [], 'New installation DDL still requires payment schema repair');
check(str_contains($report['ledger_points_type'], 'int unsigned'), 'New ledger column does not support unsigned user balances');
schemaLegacy($pdo);
$before = schemaSnapshot($pdo);
$pdo->exec('START TRANSACTION READ ONLY');
$report = $migration->preflight();
check($pdo->inTransaction(), 'Preflight implicitly committed the read-only transaction');
$pdo->rollBack();
check(array_column($report['changes'], 'id') === ['unique_order_code', 'widen_ledger_points'] && $report['blockers'] === [],
    'Clean legacy schema did not produce the two expected changes');
check(schemaSnapshot($pdo) === $before, 'Preflight mutated legacy schema');
[$status, $output, $error] = schemaCli([], $environment);
check($status === 0 && $error === '' && count(json_decode($output, true, 512, JSON_THROW_ON_ERROR)['changes']) === 2,
    'Default standalone CLI did not produce the read-only plan');
check(schemaSnapshot($pdo) === $before, 'Default standalone CLI applied DDL without --apply');
[$status, $output] = schemaCli(['--help'], []);
check($status === 0 && str_contains($output, 'read-only preflight'), 'CLI help required application/database initialization');
[$status, $output, $error] = schemaCli([], []);
check($status === 1 && str_contains($error, 'explicit mysql'), 'CLI silently selected a database or application configuration');
foreach (['bad-prefix', '`;DROP TABLE audit_order;--', str_repeat('a', 59)] as $prefix) {
    $rejected = false;
    try { new PaymentSchemaMigration($pdo, $prefix); } catch (InvalidArgumentException $e) { $rejected = true; }
    check($rejected, 'Unsafe or oversized prefix was accepted as an SQL identifier');
}

// Collation-aware duplicates include case and trailing-space equivalents.
Db::name('Order')->insert(schemaOrder('SensitiveDuplicate'));
Db::name('Order')->insert(schemaOrder('sensitiveduplicate '));
$state = membershipState();
$report = $migration->preflight();
check($report['duplicate_groups'] === 1 && $report['duplicate_excess_rows'] === 1, 'Preflight missed a collation-equivalent duplicate');
check(!str_contains(strtolower(json_encode($report)), 'sensitiveduplicate'), 'Preflight disclosed a raw order code');
check(count($report['duplicate_samples']) === 1 && (int)$report['duplicate_samples'][0]['row_count'] === 2,
    'Preflight omitted the row IDs needed for manual reconciliation');
$blocked = false;
try { $migration->apply(); } catch (RuntimeException $e) { $blocked = true; }
check($blocked && schemaSnapshot($pdo) === $before && membershipState() === $state,
    'Duplicate orders were deleted, altered, or partially migrated');
[$status, $output] = schemaCli(['--apply'], $environment);
check($status === 1 && membershipState() === $state && schemaSnapshot($pdo) === $before,
    'CLI --apply ignored duplicate-order blockers');

membershipSeed();
Db::name('Order')->insert(schemaOrder('   '));
check(in_array('blank_order_codes_require_manual_reconciliation', $migration->preflight()['blockers'], true),
    'Blank order code was accepted for automatic migration');
membershipSeed();
$report = $migration->preflight(); // A reviewed plan is not authority to apply stale data.
Db::name('Order')->insert(schemaOrder('arrived-after-review'));
Db::name('Order')->insert(schemaOrder('arrived-after-review'));
$blocked = false;
try { $migration->apply(); } catch (RuntimeException $e) { $blocked = true; }
check($blocked && schemaSnapshot($pdo) === $before, 'Apply failed to repeat preflight after data changed');

membershipSeed();
check((new Order())->saveData(schemaOrder('capacity-order', 65536, '655.36'))['code'] === 1,
    'Legacy order table did not reproduce the ledger-capacity mismatch');
$state = membershipState();
check((new Order())->notify('capacity-order', 'weixin', '655.36')['code'] !== 1 && membershipState() === $state,
    'Legacy ledger overflow did not safely roll back the payment');
$after = $migration->apply();
check($after['blockers'] === [] && $after['changes'] === [], 'Clean legacy migration did not finish');
check(membershipState() === $state, 'Migration rewrote order or balance data');
$hardened = schemaSnapshot($pdo);
check($migration->apply()['changes'] === [] && schemaSnapshot($pdo) === $hardened, 'Rerunning completed migration was not idempotent');
check((new Order())->notify('capacity-order', 'weixin', '655.36')['code'] === 1
    && memberRow()['user_points'] === 65636 && (int)Db::name('Plog')->value('plog_points') === 65536,
    'Widened real ledger still rejected an otherwise valid payment above 65535 points');
$state = membershipState();
check((new Order())->notify('capacity-order', 'weixin', '655.36')['code'] === 1 && membershipState() === $state,
    'Ledger migration broke successful payment replay idempotency');

// The database, not a racy application precheck, enforces uniqueness on insert/update.
foreach (['capacity-order', 'CAPACITY-ORDER '] as $code) {
    $result = (new Order())->saveData(schemaOrder($code));
    check($result === ['code'=>1002, 'msg'=>'save_err'] && membershipState() === $state,
        'Duplicate insertion threw/leaked an SQL error or overwrote an order');
}
check((new Order())->saveData(schemaOrder('other-order'))['code'] === 1, 'Independent order insertion failed');
$otherId = (int)Db::name('Order')->where('order_code', 'other-order')->value('order_id');
$state = membershipState();
check((new Order())->saveData(['order_id'=>$otherId] + schemaOrder('capacity-order')) === ['code'=>1002, 'msg'=>'save_err']
    && membershipState() === $state, 'Conflicting order edit was not rejected atomically');
membershipSeed(0);
check((new Order())->saveData(schemaOrder('max-points', 16777215))['code'] === 1
    && (new Order())->notify('max-points', 'weixin', '1.00')['code'] === 1
    && memberRow()['user_points'] === 16777215 && (int)Db::name('Plog')->value('plog_points') === 16777215,
    'Ledger does not cover the existing unsigned MEDIUMINT order-points range');
$state = membershipState();
check((new Order())->saveData(schemaOrder('over-order-bound', 16777216))['code'] === 1002 && membershipState() === $state,
    'Order storage overflow escaped controlled failure or changed financial state');
membershipSeed(4294967295);
check((new Order())->saveData(schemaOrder('over-user-bound', 1))['code'] === 1, 'Upper balance fixture order failed');
$state = membershipState();
check((new Order())->notify('over-user-bound', 'weixin', '1.00')['code'] !== 1 && membershipState() === $state,
    'A user balance overflow wrote a paid order or ledger');

// A previous interrupted DDL run can be inspected and resumed without undoing its first change.
schemaLegacy($pdo);
$plan = $migration->preflight()['changes'];
$pdo->exec($plan[0]['sql']);
check(array_column($migration->preflight()['changes'], 'id') === ['widen_ledger_points'], 'Partial run was not resumable');
[$status, $output, $error] = schemaCli(['--apply'], $environment);
check($status === 0 && $error === '' && $migration->preflight()['changes'] === [], 'CLI failed to resume the remaining DDL');

// An unrelated index with the planned name must not be silently replaced.
schemaLegacy($pdo);
$pdo->exec('ALTER TABLE audit_order DROP INDEX order_code, ADD INDEX order_code (order_code(5)), ADD INDEX uniq_order_code (user_id)');
$before = schemaSnapshot($pdo);
check(in_array('uniq_order_code_index_name_conflict', $migration->preflight()['blockers'], true),
    'Prefix index/unrelated index was treated as complete unique order-code protection');
$blocked = false;
try { $migration->apply(); } catch (RuntimeException $e) { $blocked = true; }
check($blocked && schemaSnapshot($pdo) === $before, 'Migration removed an unrelated/custom index');
$pdo->exec('ALTER TABLE audit_order DROP INDEX order_code, DROP INDEX uniq_order_code, ADD INDEX order_code (order_code)');
$pdo->exec('ALTER TABLE audit_plog MODIFY plog_points INT NOT NULL DEFAULT 0');
Db::name('Plog')->insert(['user_id'=>1, 'plog_type'=>1, 'plog_points'=>-1]);
check(in_array('ledger_points_values_require_manual_reconciliation', $migration->preflight()['blockers'], true),
    'Signed negative ledger data was accepted for unsigned conversion');
Db::name('Plog')->delete(true);
$pdo->exec('ALTER TABLE audit_plog MODIFY plog_points BIGINT UNSIGNED NOT NULL DEFAULT 0');
check(array_column($migration->preflight()['changes'], 'id') === ['unique_order_code'], 'Existing wider custom ledger was narrowed');

// Parallel migration invocations are rejected; the application still requires maintenance mode.
$other = new PDO($dsn, 'root', $password, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$lock = 'payment-schema:' . substr(hash('sha256', 'maccms_audit_membership/audit_'), 0, 40);
$stmt = $other->prepare('SELECT GET_LOCK(?, 0)'); $stmt->execute([$lock]);
check((int)$stmt->fetchColumn() === 1, 'Cannot acquire migration concurrency fixture lock');
$before = schemaSnapshot($pdo);
$blocked = false;
try { $migration->apply(); } catch (RuntimeException $e) { $blocked = true; }
check($blocked && schemaSnapshot($pdo) === $before, 'Concurrent migration ignored the advisory lock');
$stmt = $other->prepare('SELECT RELEASE_LOCK(?)'); $stmt->execute([$lock]);
check($migration->apply()['changes'] === [], 'Migration lock did not permit a clean retry');
echo "payment schema audit: $checks checks passed (MySQL, PHP " . PHP_VERSION . ")\n";
