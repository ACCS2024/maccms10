<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/purchase_owner_faults.php';
$cashOwnerMysql=getenv('MEMBERSHIP_AUDIT_MYSQL')==='1';
$cashOwnerDirectory=sys_get_temp_dir().'/cash-owner-'.bin2hex(random_bytes(12));
if(!mkdir($cashOwnerDirectory,0700))throw new RuntimeException('Cannot create cash fixture');
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS',$cashOwnerMysql?PurchaseOwnerMysql::class:PurchaseOwnerSqlite::class);
define('MEMBERSHIP_AUDIT_DATABASE',$cashOwnerMysql?'maccms_audit_cash_owner':$cashOwnerDirectory.'/cash.sqlite');
if($cashOwnerMysql) {
    $server=new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'');
    $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_cash_owner CHARACTER SET utf8mb4');
}
require __DIR__.'/security_audit_cash_refund_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($cashOwnerDirectory));
function cashOwnerSeed(string $operation): void {
    think\Container::getInstance()->instance('request',new think\Request());
    PurchaseOwnerFault::reset();cashRefundSeed();
    $GLOBALS['config']['user']+=['cash_status'=>'1','cash_ratio'=>'1','cash_min'=>'1'];
    if($operation==='reserve') {
        think\facade\Db::name('Cash')->delete(true);
        think\facade\Db::name('User')->where('user_id',1)->update(['user_points'=>100,'user_points_froze'=>0]);
    }
}
function cashOwnerRun(string $operation): array {
    $cash=new app\common\model\Cash();
    return match($operation){'reserve'=>$cash->saveData(['cash_money'=>'20.00','cash_bank_name'=>'ordinary bank','cash_bank_no'=>'123456','cash_payee_name'=>'ordinary name']),
        'refund'=>$cash->delData(['cash_id'=>1]),'settle'=>$cash->auditData(['cash_id'=>1])};
}
