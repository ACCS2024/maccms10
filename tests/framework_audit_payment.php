<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\Order;

$frameworkAuditTables = ['user', 'group', 'order', 'plog'];
require __DIR__ . '/fixtures/framework_audit_db.php';

// Match the production money column on MySQL; SQLite exercises numeric PDO values.
if ($mysql) {
    Db::execute('ALTER TABLE audit_order MODIFY order_price DECIMAL(12,2) UNSIGNED NOT NULL DEFAULT 0.00');
}
Db::execute('ALTER TABLE audit_user ADD COLUMN user_end_time INTEGER DEFAULT 0');
Db::execute('ALTER TABLE audit_plog ADD COLUMN plog_remarks TEXT');
function paymentSnapshot(): array {
    return [balance(), Db::name('Order')->where('order_id', 1)->find(), Db::name('Plog')->order('plog_id')->select()->toArray()];
}

seed(); orderSeed();
$manager->beforeStart = static function (): void {
    Db::name('Order')->where('order_id', 1)->update(['order_status'=>1]);
    Db::name('User')->where('user_id', 1)->setInc('user_points', 20);
    Db::name('Plog')->insert(['user_id'=>1,'plog_type'=>1,'plog_points'=>20]);
};
expect((new Order())->notify('once', 'test', 10)['code'] === 1, 'A concurrent winning payment must be acknowledged');
expect(balance()['user_points'] === 120 && Db::name('Plog')->count() === 1, 'Concurrent callbacks must credit only once');
expect((new Order())->notify('once', 'test', 10)['code'] === 1 && balance()['user_points'] === 120, 'Paid callback replay must be idempotent');

$invalidAmounts = [0, 'invalid', INF, NAN, -INF, -1, '9.99', 9.99, '10.01', 10.01, '11', '9999999999.99',
    '10000000000.00', '10.001', 10.001, '10.000', 10.00000000000001, '1e1', ' 10.00', '10.00 ',
    '+10.00', '0xA', true, false, [], new stdClass()];
foreach ($invalidAmounts as $amount) {
    seed(); orderSeed();
    $before = paymentSnapshot();
    expect((new Order())->notify('once', 'test', $amount)['code'] === 2005, 'Mismatched or malformed payment amount must be rejected');
    expect(paymentSnapshot() === $before, 'Invalid amount must not mutate the order, balance or logs');
}
seed(); orderSeed();
expect((new Order())->notify('once', 'test', 9)['code'] !== 1, 'Underpayment must be rejected');
expect((new Order())->notify('once', 'test', 10)['code'] === 1 && balance()['user_points'] === 120, 'Valid payment must still credit');
$before = paymentSnapshot();
foreach ($invalidAmounts as $amount) {
    expect((new Order())->notify('once', 'test', $amount)['code'] === 2005, 'Paid order replay must not bypass amount verification');
    expect(paymentSnapshot() === $before, 'Rejected replay changed the paid order, balance or logs');
}
foreach ([10, 10.0, '10', '10.0', '10.00', '00010.00'] as $amount) {
    expect((new Order())->notify('once', 'test', $amount)['code'] === 1, 'Equivalent valid decimal replay must remain idempotent');
    expect(paymentSnapshot() === $before, 'Valid replay credited the user again');
}
foreach ([['0.10', 0.1], ['10.01', 10.01], ['10.10', '10.1'], ['9999999999.99', '9999999999.99']] as [$expected, $amount]) {
    seed(); orderSeed();
    Db::name('Order')->where('order_id', 1)->update(['order_price' => $expected]);
    expect((new Order())->notify('once', 'test', $amount)['code'] === 1, 'Valid decimal amount failed exact comparison');
    expect(balance()['user_points'] === 120 && Db::name('Plog')->count() === 1, 'Valid decimal payment did not credit exactly once');
}
foreach (['alipay', 'weixin', 'epay', 'codepay', 'zhapay', 'jeepay', 'WEIXIN'] as $channel) {
    seed(); orderSeed();
    $before = paymentSnapshot();
    expect((new Order())->notify('once', $channel)['code'] === 2005, 'External payment channel accepted an omitted amount');
    expect(paymentSnapshot() === $before, 'Missing external amount mutated payment state');
}
seed(); orderSeed();
expect((new Order())->notify('once', 'internal')['code'] === 1, 'Trusted internal legacy invocation lost its explicit compatibility path');

// A price change between the initial read and the conditional write invalidates the payment.
seed(); orderSeed();
$manager->beforeStart = static function (): void {
    Db::name('Order')->where('order_id', 1)->update(['order_price' => '11.00']);
};
expect((new Order())->notify('once', 'test', '10.00')['code'] !== 1, 'Payment used a stale price after a concurrent amount change');
expect(balance()['user_points'] === 100 && Db::name('Order')->value('order_status') === 0
    && Db::name('Plog')->count() === 0, 'Stale-price payment wrote financial state');
seed(); orderSeed();
$manager->beforeStart = static function (): void {
    Db::name('Order')->where('order_id', 1)->update(['order_price' => '11.00', 'order_status' => 1]);
    Db::name('User')->where('user_id', 1)->setInc('user_points', 20);
    Db::name('Plog')->insert(['user_id' => 1, 'plog_type' => 1, 'plog_points' => 20]);
};
expect((new Order())->notify('once', 'test', '10.00')['code'] === 2005, 'Concurrent completed order skipped the refreshed amount check');
expect(balance()['user_points'] === 120 && Db::name('Plog')->count() === 1, 'Concurrent completed payment was credited twice');

seed(); orderSeed();
$GLOBALS['audit_plog_error'] = true;
$result = (new Order())->notify('once', 'test', 10);
expect($result['code'] !== 1 && !str_contains($result['msg'], 'injected'), 'Throwable must return a generic failure');
expect(balance()['user_points'] === 100 && Db::name('Order')->value('order_status') === 0, 'Payment/log failure must roll back both writes');

// Exercise the real paid-order member upgrade after exact amount validation.
class PaymentAuditMemberCache extends FrameworkAuditCache {
    public function get($key, $default = null) {
        return [1 => ['group_id' => 1, 'group_name' => 'test'],
            3 => ['group_id' => 3, 'group_name' => 'member', 'group_status' => 1]];
    }
}
function cookie($name, $value = null, $options = []) {}
think\Container::getInstance()->instance('cache', new PaymentAuditMemberCache());
$GLOBALS['config']['user']['reward_status'] = '0';
foreach (['weixin', 'internal'] as $channel) {
    seed(); orderSeed();
    Db::name('Order')->where('order_id', 1)->update(['order_remarks' => json_encode([
        'biz' => 'member_upgrade', 'group_id' => 3, 'long' => 'day', 'upgrade_points' => 20,
    ])]);
    $amount = $channel === 'internal' ? null : '10.00';
    expect((new Order())->notify('once', $channel, $amount)['code'] === 1, 'Paid member upgrade failed');
    expect((int)balance()['group_id'] === 3 && balance()['user_end_time'] > time()
        && balance()['user_points'] === 100 && Db::name('Plog')->count() === 2, 'Member upgrade did not preserve its balance and ledger effects');
    $before = paymentSnapshot();
    expect((new Order())->notify('once', $channel, $amount)['code'] === 1 && paymentSnapshot() === $before, 'Member upgrade replay changed balance or membership twice');
    expect((new Order())->notify('once', $channel, '9.99')['code'] === 2005 && paymentSnapshot() === $before, 'Wrong-amount member upgrade replay bypassed verification');
}

finishFrameworkAudit('framework_audit_payment');
