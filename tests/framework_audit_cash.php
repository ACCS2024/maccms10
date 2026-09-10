<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\Cash;

$frameworkAuditTables = ['user', 'cash', 'plog'];
require __DIR__ . '/fixtures/framework_audit_db.php';

function cashInput($amount): array {
    return ['cash_money'=>$amount,'cash_bank_name'=>'bank','cash_bank_no'=>'123','cash_payee_name'=>'test'];
}

seed();
expect((new Cash())->saveData(cashInput(60))['code'] === 1, 'First withdrawal must reserve points');
expect((new Cash())->saveData(cashInput(60))['code'] !== 1, 'Stale global balance must not allow a second overdraft');
expect(balance()['user_points'] === 40 && balance()['user_points_froze'] === 60 && Db::name('Cash')->count() === 1, 'Reservation must conserve available/frozen points');
expect((new Cash())->auditData(['user_id'=>1])['code'] === 1, 'Pending withdrawal must settle');
expect((new Cash())->auditData(['user_id'=>1])['code'] === 1, 'Repeated audit must safely acknowledge');
expect(balance()['user_points'] === 40 && balance()['user_points_froze'] === 0 && Db::name('Plog')->count() === 1, 'Repeated audit must not settle twice');
expect((new Cash())->delData(['user_id'=>1])['code'] === 1 && balance()['user_points'] === 40, 'Deleting paid withdrawal must not refund');

seed();
(new Cash())->saveData(cashInput(60));
expect((new Cash())->delData(['user_id'=>1])['code'] === 1, 'Pending withdrawal must be refundable');
expect((new Cash())->delData(['user_id'=>1])['code'] === 1 && balance()['user_points'] === 100 && balance()['user_points_froze'] === 0, 'Delete replay must refund once');

seed();
Db::execute($mysql
    ? "CREATE TRIGGER fail_cash BEFORE INSERT ON audit_cash FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected'"
    : "CREATE TRIGGER fail_cash BEFORE INSERT ON audit_cash BEGIN SELECT RAISE(FAIL, 'injected'); END");
expect((new Cash())->saveData(cashInput(50))['code'] !== 1, 'Failed withdrawal insert must report failure');
expect(balance()['user_points'] === 100 && balance()['user_points_froze'] === 0, 'Failed withdrawal insert must roll back reservation');
Db::execute('DROP TRIGGER fail_cash');

seed();
(new Cash())->saveData(cashInput(60));
$GLOBALS['audit_plog_error'] = true;
expect((new Cash())->auditData(['user_id'=>1])['code'] !== 1, 'Settlement log failure must fail');
expect(Db::name('Cash')->value('cash_status') === 0 && balance()['user_points_froze'] === 60, 'Settlement log failure must roll back status and frozen debit');

seed();
foreach ([-1, 0, 'nan', INF, [], 1e100] as $amount) {
    expect((new Cash())->saveData(cashInput($amount))['code'] !== 1, 'Invalid withdrawal amount must fail');
}
expect(Db::name('Cash')->count() === 0 && balance()['user_points'] === 100, 'Invalid withdrawals must leave balances unchanged');
expect((new Cash())->auditData([])['code'] !== 1 && (new Cash())->delData([])['code'] !== 1, 'Empty destructive scope must fail');

seed();
Db::name('User')->where('user_id', 1)->update(['user_points'=>200000]);
expect((new Cash())->saveData(cashInput(65535))['code'] === 1, 'Maximum stored cash points must be accepted');
expect((new Cash())->saveData(cashInput(65536))['code'] !== 1, 'Cash points above SMALLINT UNSIGNED must be rejected');
expect(balance()['user_points'] === 134465 && balance()['user_points_froze'] === 65535 && Db::name('Cash')->count() === 1, 'Cash storage boundary must preserve the ledger');

// Batch operations must respect both the selected IDs and transaction boundaries.
seed();
(new Cash())->saveData(cashInput(20));
$firstId = (int)Db::name('Cash')->where('user_id', 1)->value('cash_id');
$GLOBALS['user'] = ['user_id'=>2,'user_points'=>100,'user_points_froze'=>0];
(new Cash())->saveData(cashInput(30));
$secondId = (int)Db::name('Cash')->where('user_id', 2)->value('cash_id');
expect((new Cash())->auditData(['cash_id'=>[$firstId]])['code'] === 1, 'Selected withdrawal must settle');
expect(Db::name('Cash')->where('cash_id', $secondId)->value('cash_status') === 0 && balance(2)['user_points_froze'] === 30, 'Unselected withdrawal must remain pending');

seed();
(new Cash())->saveData(cashInput(20));
$GLOBALS['user'] = ['user_id'=>2,'user_points'=>100,'user_points_froze'=>0];
(new Cash())->saveData(cashInput(30));
Db::execute($mysql
    ? "CREATE TRIGGER fail_second_log BEFORE INSERT ON audit_plog FOR EACH ROW BEGIN IF NEW.user_id = 2 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected'; END IF; END"
    : "CREATE TRIGGER fail_second_log BEFORE INSERT ON audit_plog WHEN NEW.user_id = 2 BEGIN SELECT RAISE(FAIL, 'injected'); END");
expect((new Cash())->auditData(['user_id'=>[1,2]])['code'] !== 1, 'Second settlement failure must fail the whole batch');
expect(Db::name('Cash')->where('cash_status', 0)->count() === 2 && Db::name('Plog')->count() === 0, 'Batch failure must restore statuses and earlier logs');
expect(balance()['user_points_froze'] === 20 && balance(2)['user_points_froze'] === 30, 'Batch failure must restore all frozen balances');
Db::execute('DROP TRIGGER fail_second_log');
Db::name('User')->where('user_id', 2)->update(['user_points_froze'=>0]);
expect((new Cash())->delData(['user_id'=>[1,2]])['code'] !== 1, 'Inconsistent second frozen balance must prevent batch refund');
expect(Db::name('Cash')->count() === 2 && balance()['user_points'] === 80 && balance()['user_points_froze'] === 20, 'Failed batch refund must restore earlier deletion and refund');


finishFrameworkAudit('framework_audit_cash');
