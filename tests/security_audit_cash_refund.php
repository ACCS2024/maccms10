<?php
/** Full-value refunds and settlement serialization using the real ORM and financial DDL. */
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_cash_refund_db.php';
use think\facade\Db;
use app\common\model\Cash;
use app\common\util\PointsBalance;

foreach ([PointsBalance::MAX - 10, PointsBalance::MAX] as $available) {
    cashRefundSeed($available);
    $before = cashRefundState();
    check((new Cash())->delData(['cash_id'=>1])['code'] !== 1, 'An overflowing refund returned success');
    check(cashRefundState() === $before, 'An overflowing refund clipped the balance, consumed frozen points or deleted evidence');
}
cashRefundSeed(PointsBalance::MAX - 20);
check((new Cash())->delData(['cash_id'=>1])['code'] === 1, 'An exact-maximum refund was rejected');
check(memberRow()['user_points'] === PointsBalance::MAX && memberRow()['user_points_froze'] === 0
    && Db::name('Cash')->count() === 0 && Db::name('Plog')->count() === 0,
    'Refund must return the entire reservation without creating an extra payment ledger');
$before = cashRefundState();
check((new Cash())->delData(['cash_id'=>1])['code'] === 1 && cashRefundState() === $before,
    'A refund replay changed balances at the maximum');

cashRefundSeed(100, 65535, 65535);
check((new Cash())->delData(['cash_id'=>1])['code'] === 1
    && memberRow()['user_points'] === 65635 && memberRow()['user_points_froze'] === 0,
    'The complete SMALLINT cash-points range was not refundable');

foreach (['missing_user', 'insufficient_frozen', 'zero_points', 'unknown_status'] as $fault) {
    cashRefundSeed();
    if ($fault === 'missing_user') { Db::name('User')->where('user_id', 1)->delete(); }
    if ($fault === 'insufficient_frozen') { Db::name('User')->where('user_id', 1)->update(['user_points_froze'=>19]); }
    if ($fault === 'zero_points') { Db::name('Cash')->where('cash_id', 1)->update(['cash_points'=>0]); }
    if ($fault === 'unknown_status') { Db::name('Cash')->where('cash_id', 1)->update(['cash_status'=>2]); }
    $before = cashRefundState();
    check((new Cash())->delData(['cash_id'=>1])['code'] !== 1 && cashRefundState() === $before,
        'Invalid refund state changed the ledger: ' . $fault);
    if ($fault !== 'unknown_status') {
        check((new Cash())->auditData(['cash_id'=>1])['code'] !== 1 && cashRefundState() === $before,
            'An invalid pending withdrawal was settled: ' . $fault);
    }
}

cashRefundSeed(PointsBalance::MAX, 0, 20, 1);
check((new Cash())->delData(['cash_id'=>1])['code'] === 1
    && memberRow()['user_points'] === PointsBalance::MAX && memberRow()['user_points_froze'] === 0,
    'Deleting a previously paid withdrawal incorrectly attempted a refund');
cashRefundSeed();
foreach ([[], null, 'cash_id=1'] as $where) {
    $before = cashRefundState();
    check((new Cash())->delData($where)['code'] !== 1 && cashRefundState() === $before,
        'An unbounded or malformed refund scope was accepted');
}

// Failure on the second row must restore the first refund and the first deletion.
foreach (['overflow', 'unknown_status', 'delete_failure'] as $fault) {
    cashRefundSeed();
    cashRefundSecondUser($fault === 'overflow' ? PointsBalance::MAX - 29 : 70);
    if ($fault === 'unknown_status') { Db::name('Cash')->where('cash_id', 2)->update(['cash_status'=>2]); }
    if ($fault === 'delete_failure') {
        Db::execute($mysql
            ? "CREATE TRIGGER cash_refund_delete_fail BEFORE DELETE ON audit_cash FOR EACH ROW BEGIN IF OLD.cash_id = 2 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture delete failure'; END IF; END"
            : "CREATE TRIGGER cash_refund_delete_fail BEFORE DELETE ON audit_cash WHEN OLD.cash_id = 2 BEGIN SELECT RAISE(FAIL, 'fixture delete failure'); END");
    }
    $before = cashRefundState();
    check((new Cash())->delData(['user_id'=>[1,2]])['code'] !== 1, 'A partial refund batch was acknowledged: ' . $fault);
    check(cashRefundState() === $before, 'A later failure left an earlier refund committed: ' . $fault);
    if ($fault === 'delete_failure') { Db::execute('DROP TRIGGER cash_refund_delete_fail'); }
}

// A credit committed before acquiring the transaction must affect the SQL upper bound.
cashRefundSeed(PointsBalance::MAX - 20);
$manager->beforeStart = static function (): void {
    Db::name('User')->where('user_id', 1)->setInc('user_points', 1);
    $GLOBALS['cash_refund_winner'] = cashRefundState();
};
check((new Cash())->delData(['cash_id'=>1])['code'] !== 1
    && cashRefundState() === $GLOBALS['cash_refund_winner'], 'Refund used a stale balance before a concurrent credit');

// Two individually affordable refunds for one user must also fit their combined balance.
cashRefundSeed(PointsBalance::MAX - 40, 50);
Db::name('Cash')->insert(['cash_id'=>2, 'user_id'=>1, 'cash_points'=>30, 'cash_money'=>'30.00']);
$before = cashRefundState();
check((new Cash())->delData(['user_id'=>1])['code'] !== 1 && cashRefundState() === $before,
    'A batch of same-user refunds crossed the capacity after its first credit');

// Preserve the existing reservation read-back guard on the other unsigned balance column.
$GLOBALS['config']['user'] += ['cash_status'=>'1', 'cash_ratio'=>'1', 'cash_min'=>'1'];
$cashInput = ['cash_money'=>'20.00', 'cash_bank_name'=>'fixture', 'cash_bank_no'=>'123', 'cash_payee_name'=>'fixture'];
cashRefundSeed(100, PointsBalance::MAX - 10);
Db::name('Cash')->delete(true);
$before = cashRefundState();
check((new Cash())->saveData($cashInput)['code'] !== 1 && cashRefundState() === $before,
    'Overflow of frozen points silently lost part of a new reservation');
cashRefundSeed(100, PointsBalance::MAX - 20);
Db::name('Cash')->delete(true);
check((new Cash())->saveData($cashInput)['code'] === 1 && memberRow()['user_points'] === 80
    && memberRow()['user_points_froze'] === PointsBalance::MAX, 'An exact-maximum frozen reservation was rejected');
check((new Cash())->delData(['user_id'=>1])['code'] === 1 && memberRow()['user_points'] === 100
    && memberRow()['user_points_froze'] === PointsBalance::MAX - 20,
    'Refund changed other frozen reservations at the column boundary');

// Ledger rejection may be a structured failure or a PHP Error, not just a PDO exception.
foreach (['member_fail_log_types', 'member_throw_log_types'] as $fault) {
    cashRefundSeed();
    $GLOBALS[$fault] = [9];
    $before = cashRefundState();
    check((new Cash())->auditData(['cash_id'=>1])['code'] !== 1 && cashRefundState() === $before,
        'Settlement ledger failure did not roll back frozen points and paid state: ' . $fault);
}
cashRefundSeed();
cashRefundSecondUser();
Db::execute($mysql
    ? "CREATE TRIGGER cash_refund_log_fail BEFORE INSERT ON audit_plog FOR EACH ROW BEGIN IF NEW.user_id = 2 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture log failure'; END IF; END"
    : "CREATE TRIGGER cash_refund_log_fail BEFORE INSERT ON audit_plog WHEN NEW.user_id = 2 BEGIN SELECT RAISE(FAIL, 'fixture log failure'); END");
$before = cashRefundState();
check((new Cash())->auditData(['user_id'=>[1,2]])['code'] !== 1 && cashRefundState() === $before,
    'Second settlement ledger failure did not roll back the first settlement and log');
Db::execute('DROP TRIGGER cash_refund_log_fail');

// Either competing transition may win; the loser must not pay or refund a second time.
foreach (['refund', 'audit'] as $winner) {
    cashRefundSeed();
    $manager->beforeStart = static function () use ($winner): void {
        $cash = new Cash();
        $result = $winner === 'refund' ? $cash->delData(['cash_id'=>1]) : $cash->auditData(['cash_id'=>1]);
        check($result['code'] === 1, 'The first transition failed');
    };
    $result = $winner === 'refund' ? (new Cash())->auditData(['cash_id'=>1]) : (new Cash())->delData(['cash_id'=>1]);
    check($result['code'] === 1, 'The losing transition did not safely acknowledge the completed state');
    check(memberRow()['user_points'] === ($winner === 'refund' ? 100 : 80)
        && memberRow()['user_points_froze'] === 0 && Db::name('Cash')->count() === 0
        && Db::name('Plog')->count() === ($winner === 'refund' ? 0 : 1),
        'Competing refund/settlement produced two financial outcomes');
}
cashRefundSeed(PointsBalance::MAX);
check((new Cash())->auditData(['cash_id'=>1])['code'] === 1, 'A full available balance should not block spending frozen points');
$before = cashRefundState();
check((new Cash())->auditData(['cash_id'=>1])['code'] === 1 && cashRefundState() === $before
    && memberRow()['user_points'] === PointsBalance::MAX && memberRow()['user_points_froze'] === 0
    && (int)Db::name('Plog')->value('plog_points') === 20,
    'Repeated settlement changed the completed ledger');

if ($mysql) {
    // Probe real InnoDB locks from a second connection while the first transition is midway.
    $peer = new PDO('mysql:host=' . (getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1')
        . ';dbname=maccms_audit_membership;charset=utf8mb4', 'root', getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '',
        [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $peer->exec('SET SESSION innodb_lock_wait_timeout=1');
    $peer->exec("SET SESSION sql_mode=''");
    $probe = null;
    $manager->event('after_update', static function ($query) use (&$probe): void {
        if ($probe === null || $query->getTable() !== 'audit_user') { return; }
        $callback = $probe;
        $probe = null;
        $callback();
    });
    foreach (['refund', 'audit'] as $operation) {
        cashRefundSeed(PointsBalance::MAX - 20);
        $lockResults = [];
        $probe = static function () use ($peer, &$lockResults): void {
            foreach ([
                'cash'=>"UPDATE audit_cash SET cash_status=1 WHERE cash_id=1",
                'user'=>"UPDATE audit_user SET user_points=user_points+1 WHERE user_id=1",
            ] as $table => $sql) {
                try { $peer->exec($sql); $lockResults[$table] = 'unlocked'; }
                catch (PDOException $e) { $lockResults[$table] = $e->errorInfo[1] ?? 0; }
            }
        };
        $cash = new Cash();
        $result = $operation === 'refund' ? $cash->delData(['cash_id'=>1]) : $cash->auditData(['cash_id'=>1]);
        check($result['code'] === 1, 'Lock-probed transition failed: ' . $operation);
        check($probe === null && $lockResults === ['cash'=>1205, 'user'=>1205],
            'Cash/user rows were not both locked against competing settlement/credit: ' . $operation);
        check(memberRow()['user_points'] === ($operation === 'refund' ? PointsBalance::MAX : PointsBalance::MAX - 20)
            && memberRow()['user_points_froze'] === 0 && Db::name('Plog')->count() === ($operation === 'refund' ? 0 : 1),
            'Lock contention caused a partial or duplicate transition: ' . $operation);
    }
}

echo "cash refund audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL non-strict' : ' / SQLite') . "\n";
