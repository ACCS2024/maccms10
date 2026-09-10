<?php
/** Atomic upper bounds must hold even when MySQL clips unsigned overflows instead of throwing. */
require __DIR__ . '/fixtures/security_audit_membership_db.php';
use think\facade\Db;
use app\common\model\Order;
use app\common\model\User;
use app\common\util\PointsBalance;
if ($mysql) { Db::execute("SET SESSION sql_mode=''"); }

function overflowOrderSeed(int $balance, int $points = 20): void {
    membershipSeed($balance);
    membershipOrderSeed($points);
    Db::name('Order')->where('order_id', 1)->update(['order_remarks'=>'']);
}
overflowOrderSeed(PointsBalance::MAX - 10);
$before = membershipState();
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] !== 1 && membershipState() === $before,
    'Payment overflow clipped the credited balance, marked the order paid, or wrote a full-value ledger');
overflowOrderSeed(PointsBalance::MAX - 20);
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] === 1
    && memberRow()['user_points'] === PointsBalance::MAX && (int)Db::name('Plog')->value('plog_points') === 20,
    'A payment reaching the exact unsigned maximum did not credit its full ledger amount');
$before = membershipState();
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] === 1 && membershipState() === $before,
    'A paid order replay at the maximum balance attempted a second credit');

// A later credit between the initial order/user read and the transaction must be included in the bound.
overflowOrderSeed(PointsBalance::MAX - 20);
$manager->beforeStart = static function (): void {
    Db::name('User')->where('user_id', 1)->setInc('user_points', 1);
    $GLOBALS['overflow_winner_state'] = membershipState();
};
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] !== 1
    && membershipState() === $GLOBALS['overflow_winner_state'], 'Payment used a stale balance to permit an overflowing credit');

foreach ([2,3,4] as $recipient) {
    membershipSeed();
    $GLOBALS['config']['user']['reward_ratio_2'] = $GLOBALS['config']['user']['reward_ratio_3'] = '10';
    Db::name('User')->where('user_id', $recipient)->update(['user_points'=>PointsBalance::MAX - 1]);
    $before = membershipState();
    $failed = false;
    try { (new User())->reward(20, 1); } catch (RuntimeException $e) { $failed = true; }
    check($failed && membershipState() === $before, 'Referral overflow clipped a payout or left earlier recipients/logs committed');
}
membershipSeed();
Db::name('User')->where('user_id', 2)->update(['user_points'=>PointsBalance::MAX - 2]);
check((new User())->reward(20, 1)['code'] === 1 && memberRow(2)['user_points'] === PointsBalance::MAX
    && (int)Db::name('Plog')->where('user_id', 2)->value('plog_points') === 2,
    'A referral payout reaching the exact maximum was rejected or incompletely logged');
membershipSeed(40);
Db::name('User')->where('user_id', 2)->update(['user_points'=>PointsBalance::MAX - 1]);
$before = membershipState();
check((new User())->upgrade(['group_id'=>3,'long'=>'day'])['code'] !== 1 && membershipState() === $before,
    'Referral overflow failed to roll back the surrounding membership charge and expiry');
membershipSeed(100);
membershipOrderSeed();
Db::name('User')->where('user_id', 2)->update(['user_points'=>PointsBalance::MAX - 1]);
$before = membershipState();
check((new Order())->notify('member-once', 'weixin', '10.00')['code'] !== 1 && membershipState() === $before,
    'Referral overflow failed to roll back the complete paid-membership order transaction');

// Guard validation and repeat credits do not rely on MySQL's numeric coercion or a previous read.
membershipSeed(PointsBalance::MAX - 10);
check(PointsBalance::credit(1, 10) && memberRow()['user_points'] === PointsBalance::MAX, 'Exact-capacity atomic credit failed');
check(!PointsBalance::credit(1, 1) && memberRow()['user_points'] === PointsBalance::MAX, 'A subsequent credit crossed the balance bound');
foreach ([0, -1, PointsBalance::MAX + 1, '1.0', '1e1', [], true, INF, NAN, 1.5] as $amount) {
    membershipSeed(0);
    $before = membershipState();
    check(!PointsBalance::credit(1, $amount) && membershipState() === $before, 'Invalid credit amount was coerced into a balance mutation');
}
membershipSeed(0);
foreach ([0, -1, 999, [1], true, '1e0'] as $userId) {
    check(!PointsBalance::credit($userId, 1) && memberRow()['user_points'] === 0, 'Missing or malformed recipient was credited');
}
check(PointsBalance::credit(1, (string)PointsBalance::MAX) && memberRow()['user_points'] === PointsBalance::MAX,
    'The shared credit primitive does not cover the full unsigned balance range');
echo "points overflow audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL non-strict' : ' / SQLite') . "\n";
