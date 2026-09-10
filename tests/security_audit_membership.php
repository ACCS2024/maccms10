<?php
/** Atomic membership/reward regressions with real models, transactions and ledger validation. */
require __DIR__ . '/fixtures/financial_before_begin.php';
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS', getenv('MEMBERSHIP_AUDIT_MYSQL') === '1' ? FinancialBeforeBeginMysql::class : FinancialBeforeBeginSqlite::class);
require __DIR__ . '/fixtures/security_audit_membership_db.php';
use think\facade\Db;
use app\common\model\User;
use app\common\model\Order;
$plan = ['group_id'=>3, 'long'=>'day'];

membershipSeed();
check((new User())->upgrade($plan)['code'] === 1, 'Valid paid membership upgrade failed');
check(memberRow()['user_points'] === 80 && memberRow()['user_end_time'] > time(), 'Membership was free or expiry was not updated');
check([memberRow(2)['user_points'], memberRow(3)['user_points'], memberRow(4)['user_points']] === [2, 1, 1], 'Referral rewards did not match one successful charge');
check(Db::name('Plog')->count() === 4, 'Each balance change must have its own ledger');

membershipSeed(0);
$GLOBALS['member_groups'][3]['group_points_day'] = 0;
check((new User())->upgrade($plan)['code'] === 1, 'Explicitly configured free plans must remain available');
check(memberRow()['user_points'] === 0 && memberRow()['user_end_time'] > time(), 'Free plan changed the balance');
check(Db::name('Plog')->count() === 1 && Db::name('Plog')->value('plog_points') === 0
    && memberRow(2)['user_points'] === 0, 'Free plan generated referral rewards or lost its audit entry');

foreach ([-1, '20.1', '20x', [], null] as $fee) {
    membershipSeed();
    $GLOBALS['member_groups'][3]['group_points_day'] = $fee;
    $before = membershipState();
    check((new User())->upgrade($plan)['code'] !== 1 && membershipState() === $before, 'Malformed configured fee produced a free or truncated-price upgrade');
}
foreach ([[], ['group_id'=>[3], 'long'=>'day'], ['group_id'=>3, 'long'=>[]], ['group_id'=>99, 'long'=>'day']] as $input) {
    membershipSeed();
    $before = membershipState();
    check((new User())->upgrade($input)['code'] !== 1 && membershipState() === $before, 'Malformed plan mutated financial state');
}
membershipSeed(10);
$GLOBALS['user']['user_points'] = 1000; // An optimistic request/session snapshot is insufficient authority.
$before = membershipState();
check((new User())->upgrade($plan)['code'] !== 1 && membershipState() === $before, 'Stale balance snapshot allowed an underfunded upgrade');

foreach ([7, 4, 5, 6] as $failedType) {
    membershipSeed();
    $GLOBALS['member_fail_log_types'] = [$failedType];
    $before = membershipState();
    $result = (new User())->upgrade($plan);
    check($result['code'] !== 1 && !str_contains($result['msg'], 'fixture'), 'Non-exception ledger rejection was ignored or leaked');
    check(membershipState() === $before && $GLOBALS['member_cookies'] === [], 'Ledger rejection failed to roll back membership, all balances and logs');
}
membershipSeed();
$GLOBALS['member_throw_log_types'] = [7];
$before = membershipState();
check((new User())->upgrade($plan)['code'] !== 1 && membershipState() === $before, 'Throwable escaped membership rollback');

// Force a second request to complete after the first request has captured its global snapshot.
membershipSeed(20);
$GLOBALS['financial_before_begin'] = static function () use ($plan): void {
    check((new User())->upgrade($plan)['code'] === 1, 'Concurrent winner failed');
};
check((new User())->upgrade($plan)['code'] !== 1, 'Two concurrent upgrades spent a balance sufficient for only one');
check(memberRow()['user_points'] === 0 && Db::name('Plog')->count() === 4 && memberRow(2)['user_points'] === 2,
    'Concurrent losing request duplicated a charge or reward');
membershipSeed(40);
$GLOBALS['financial_before_begin'] = static function () use ($plan): void {
    check((new User())->upgrade($plan)['code'] === 1, 'First funded renewal failed');
    $GLOBALS['member_first_expiry'] = memberRow()['user_end_time'];
};
check((new User())->upgrade($plan)['code'] === 1, 'Second funded renewal failed');
check(memberRow()['user_points'] === 0 && memberRow()['user_end_time'] === $GLOBALS['member_first_expiry'] + 86400,
    'Concurrent funded renewals deducted twice but extended only once');
check(Db::name('Plog')->count() === 8 && memberRow(2)['user_points'] === 4, 'Each funded renewal must reward exactly once');

foreach ([7, 4, 5, 6] as $failedType) {
    membershipSeed(); membershipOrderSeed();
    $GLOBALS['member_fail_log_types'] = [$failedType];
    $before = membershipState();
    $context = $GLOBALS['user'];
    check((new Order())->notify('member-once', 'weixin', '10.00')['code'] !== 1, 'Paid membership ledger rejection was acknowledged');
    check(membershipState() === $before && $GLOBALS['user'] === $context, 'Paid membership failure left a partial credit, membership or user context');
}
membershipSeed(); membershipOrderSeed();
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] === 1, 'Valid paid membership order failed');
check(memberRow()['user_points'] === 100 && memberRow(2)['user_points'] === 2 && Db::name('Plog')->count() === 5,
    'Paid membership credit, deduction and rewards were not recorded once');
$before = membershipState();
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] === 1 && membershipState() === $before,
    'Paid order replay repeated membership or referral rewards');

// Reward() can also be called from other purchasing transactions. Its failure must propagate.
foreach ([4, 5, 6] as $failedType) {
    membershipSeed();
    $GLOBALS['member_fail_log_types'] = [$failedType];
    $before = membershipState();
    $thrown = false;
    try { (new User())->reward(20); } catch (RuntimeException $e) { $thrown = true; }
    check($thrown && membershipState() === $before, 'Standalone reward left a partial payout after a ledger rejection');
}
foreach ([['user_pid'=>1], ['user_pid_2'=>2], ['user_pid_3'=>99]] as $badReferral) {
    membershipSeed();
    Db::name('User')->where('user_id', 1)->update($badReferral);
    $before = membershipState();
    check((new User())->upgrade($plan)['code'] !== 1 && membershipState() === $before,
        'Self, duplicate or missing referral caused unbalanced/duplicate rewards');
}
membershipSeed();
$GLOBALS['member_fail_log_types'] = [5];
$before = membershipState();
$rolledBack = false;
Db::startTrans();
try {
    Db::name('User')->where('user_id', 1)->setDec('user_points', 20);
    (new User())->reward(20); // The old callers do not inspect a return value.
    Db::commit();
} catch (Exception $e) {
    Db::rollback();
    $rolledBack = true;
}
check($rolledBack && membershipState() === $before, 'Legacy purchasing transaction committed despite reward failure');
echo 'Membership transaction regressions: ' . $checks . ' assertions passed on PHP ' . PHP_VERSION
    . ' / ' . ($mysql ? 'MySQL installation schema' : 'SQLite') . "\n";
