<?php
/** Physical COMMIT acknowledgement loss must not allow a second cash reservation. */
declare(strict_types=1);
require __DIR__.'/fixtures/cash_owner_db.php';
require dirname(__DIR__).'/migration/lib/CashRequestMigration.php';
use think\facade\Db;
use app\common\model\Cash;
Db::execute('DROP TABLE IF EXISTS audit_cash_request');
Db::execute($mysql?CashRequestMigration::ddl('audit_'):'CREATE TABLE audit_cash_request(user_id INTEGER NOT NULL,request_id TEXT NOT NULL,payload_hash TEXT NOT NULL,cash_id INTEGER NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(user_id,request_id))');
$observer=$mysql?new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname='.MEMBERSHIP_AUDIT_DATABASE.';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:''):new PDO('sqlite:'.MEMBERSHIP_AUDIT_DATABASE);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
$input=['request_id'=>str_repeat('b',64),'cash_money'=>'20.00','cash_bank_name'=>'Ordinary bank','cash_bank_no'=>'123456','cash_payee_name'=>'Ordinary name'];
try {
    foreach(['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after'] as $fault) {
        cashOwnerSeed('reserve');Db::name('CashRequest')->delete(true);
        PurchaseOwnerFault::reset([$fault=>1]);
        $result=(new Cash())->saveRequestForUser(1,$input);
        check(in_array($result['code'],[2004,2005],true)&&$result['info']['retryable']===false,'Lost commit acknowledgement must remain uncertain');
        $calls=PurchaseOwnerFault::$calls;
        check((new Cash())->saveRequestForUser(1,$input)['code']===2005&&PurchaseOwnerFault::$calls===$calls,'The same failed HTTP request cannot start another transaction');
        $committed=str_ends_with($fault,'after');
        check((int)$observer->query('SELECT COUNT(*) FROM audit_cash_request')->fetchColumn()===($committed?1:0),'Receipt must share the actual commit outcome');
        check((int)$observer->query('SELECT COUNT(*) FROM audit_cash')->fetchColumn()===($committed?1:0),'Cash row and receipt cannot commit separately');
        PurchaseOwnerFault::reset();Db::connect()->close();
        think\Container::getInstance()->instance('request',new think\Request());
        $retry=(new Cash())->saveRequestForUser(1,$input);
        check($retry['code']===1&&$retry['info']['request_id']===$input['request_id'],'A later independent request must resolve the persisted request key');
        check((int)$observer->query('SELECT COUNT(*) FROM audit_cash_request')->fetchColumn()===1
            &&(int)$observer->query('SELECT COUNT(*) FROM audit_cash')->fetchColumn()===1
            &&(int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===80,
            'Retry after acknowledgement loss must leave one receipt and one 20-point reservation');
    }
    echo 'Cash receipt owner: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
} finally { PurchaseOwnerFault::reset();Db::execute('DROP TABLE IF EXISTS audit_cash_request'); }
