<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\Order;

$frameworkAuditTables = ['user', 'group', 'order', 'plog'];
require __DIR__ . '/fixtures/framework_audit_db.php';

seed(); orderSeed();
$manager->beforeStart = static function (): void {
    Db::name('Order')->where('order_id', 1)->update(['order_status'=>1]);
    Db::name('User')->where('user_id', 1)->setInc('user_points', 20);
    Db::name('Plog')->insert(['user_id'=>1,'plog_type'=>1,'plog_points'=>20]);
};
expect((new Order())->notify('once', 'test', 10)['code'] === 1, 'A concurrent winning payment must be acknowledged');
expect(balance()['user_points'] === 120 && Db::name('Plog')->count() === 1, 'Concurrent callbacks must credit only once');
expect((new Order())->notify('once', 'test', 10)['code'] === 1 && balance()['user_points'] === 120, 'Paid callback replay must be idempotent');

foreach ([0, 'invalid', INF, NAN, -1] as $amount) {
    seed(); orderSeed();
    expect((new Order())->notify('once', 'test', $amount)['code'] !== 1, 'Invalid supplied payment amount must be rejected');
    expect(balance()['user_points'] === 100 && Db::name('Order')->value('order_status') === 0, 'Invalid amount must not mutate payment state');
}
seed(); orderSeed();
expect((new Order())->notify('once', 'test', 9)['code'] !== 1, 'Underpayment must be rejected');
expect((new Order())->notify('once', 'test', 10)['code'] === 1 && balance()['user_points'] === 120, 'Valid payment must still credit');
seed(); orderSeed();
$GLOBALS['audit_plog_error'] = true;
$result = (new Order())->notify('once', 'test', 10);
expect($result['code'] !== 1 && !str_contains($result['msg'], 'injected'), 'Throwable must return a generic failure');
expect(balance()['user_points'] === 100 && Db::name('Order')->value('order_status') === 0, 'Payment/log failure must roll back both writes');


finishFrameworkAudit('framework_audit_payment');
