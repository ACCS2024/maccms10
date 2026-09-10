<?php
/** Payment acknowledgement faults around actual ORM/PDO calls, with an independent committed-state observer. */
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_fault_db.php';
use think\facade\Db;
use app\common\model\Order;
use app\common\model\User;
use app\common\util\FinancialOperationException;

$observer=$mysql
    ? new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname='.MEMBERSHIP_AUDIT_DATABASE.';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'')
    : new PDO('sqlite:'.MEMBERSHIP_AUDIT_DATABASE);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
function orderOwnerSeed(bool $membership=true):void {
    ownerSeed();membershipOrderSeed();
    if(!$membership){Db::name('Order')->where('order_id',1)->update(['order_remarks'=>'']);}
}
function orderOwnerRun():array {return (new Order())->notify('member-once','weixin','10.00');}
function orderOwnerAbort(PDO $pdo):void {PurchaseOwnerFault::reset();if($pdo->inTransaction()){$pdo->rollBack();}Db::connect()->close();}
function orderOwnerStored(PDO $observer,bool $membership):void {
    check((int)$observer->query('SELECT order_status FROM audit_order')->fetchColumn()===1,'Independent observer confirms the paid order');
    check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===($membership?100:120),'Independent observer confirms the full balance');
    check((int)$observer->query('SELECT COUNT(*) FROM audit_plog')->fetchColumn()===($membership?5:1),'Independent observer confirms all operation ledgers');
    check((int)$observer->query('SELECT SUM(user_points) FROM audit_user WHERE user_id>1')->fetchColumn()===($membership?4:0),'Independent observer confirms the correct referrals');
}
foreach([false,true]as $membership){
    orderOwnerSeed($membership);check(orderOwnerRun()['code']===1,'Ordinary payment succeeds');orderOwnerStored($observer,$membership);
    $before=ownerState();check(orderOwnerRun()['code']===1 && ownerState()===$before,'Paid replay preserves every balance and ledger');
    foreach(['orm_begin_before','pdo_begin_before','pdo_begin_after','orm_begin_after']as $stage){
        orderOwnerSeed($membership);$before=ownerState();$pdo=Db::connect()->getPdo();PurchaseOwnerFault::reset([$stage=>1]);$result=orderOwnerRun();
        check($result['code']===2004 && !isset($result['info']) && ownerState()===$before,'BEGIN failure returns controlled failure with no financial effects: '.$stage);
        check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)===1,'Actual BEGIN fault leaves no original owner transaction');
    }
    foreach(['orm_rollback_before','pdo_rollback_before','pdo_rollback_after','orm_rollback_after']as $stage){
        foreach($membership?[1,7,5]:[1]as $ledger){
            orderOwnerSeed($membership);$before=ownerState();$pdo=Db::connect()->getPdo();$GLOBALS['member_fail_log_types']=[$ledger];PurchaseOwnerFault::reset([$stage=>1]);$result=orderOwnerRun();
            check($result['code']!==1 && !isset($result['info']['outcome']) && ownerState()===$before,'Confirmed owner rollback restores all payment/member effects: '.$ledger.'/'.$stage);
            check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1 && (PurchaseOwnerFault::$calls[$stage]??0)>=1,'Actual owner fault has bounded cleanup and ends the original PDO');
            check($GLOBALS['member_cookies']===[],'Failed payment publishes no membership cookie');
        }
    }
    foreach(['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after']as $stage){
        orderOwnerSeed($membership);$before=ownerState();$pdo=Db::connect()->getPdo();PurchaseOwnerFault::reset([$stage=>1]);$result=orderOwnerRun();
        check($result['code']===2004 && $result['info']['outcome']==='commit_unknown' && !$result['info']['retryable'],'COMMIT acknowledgement loss is explicitly unknown: '.$stage);
        check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)===1,'COMMIT fault really ran and original PDO is no longer active');
        if(str_ends_with($stage,'after')){orderOwnerStored($observer,$membership);}else{check(ownerState()===$before,'COMMIT-before fault is actually rolled back');}
        check($GLOBALS['member_cookies']===[],'Unknown payment commit publishes no membership cookie');
        $after=ownerState();$calls=PurchaseOwnerFault::$calls;
        try{(new User())->reward(20,1);throw new RuntimeException('Reward was not blocked');}catch(FinancialOperationException $e){check($e->result()['code']===2005,'Unknown payment blocks direct reward');}
        check(orderOwnerRun()['code']===2005 && ownerBuy()['code']===2005 && (new User())->upgrade(['group_id'=>3,'long'=>'day'])['code']===2005,'Unknown payment blocks cross-domain attempts, including already-paid replay');
        check(ownerState()===$after && PurchaseOwnerFault::$calls===$calls,'Cross-domain block performs no further transaction attempt');
        ownerRequest();PurchaseOwnerFault::reset();check(orderOwnerRun()['code']===1,'Fresh callback can reconcile through durable order status');orderOwnerStored($observer,$membership);
    }
    orderOwnerSeed($membership);$before=ownerState();$pdo=Db::connect()->getPdo();$GLOBALS['member_fail_log_types']=[1];PurchaseOwnerFault::reset(['pdo_rollback_before'=>'always']);$result=orderOwnerRun();
    check($result['code']===2005 && !$result['info']['retryable'] && $pdo->inTransaction(),'Unrecoverable owner cleanup retains uncertainty and the original active PDO');
    check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1 && (PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,'Unrecoverable cleanup makes one ORM attempt and one native fallback');
    check((int)$observer->query('SELECT order_status FROM audit_order')->fetchColumn()===0 && orderOwnerRun()['code']===2005,'Pending payment is invisible and cannot be attempted again');
    orderOwnerAbort($pdo);check(ownerState()===$before,'Explicit fixture-owned cleanup removes retained pending effects');
}
// In particular, an inner unacknowledged rollback may leave extra ORM depth; one ORM rollback is not sufficient.
foreach(['orm_nested_begin_before','orm_nested_begin_after','orm_nested_commit_before','orm_nested_commit_after','caller_rollback_before','caller_rollback_after','caller_release_before','caller_release_after']as $stage){
    foreach([1,2]as $occurrence){
        orderOwnerSeed();$before=ownerState();$pdo=Db::connect()->getPdo();
        if(str_contains($stage,'rollback')){$GLOBALS['member_fail_log_types']=[$occurrence===1?7:5];}
        PurchaseOwnerFault::reset([$stage=>str_contains($stage,'rollback')?'always':$occurrence]);$result=orderOwnerRun();
        check($result['code']!==1 && !isset($result['info']['outcome']) && ownerState()===$before,'Containing payment owner restores all state after actual member/reward fault: '.$stage.'/'.$occurrence);
        check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)>=$occurrence,'Original physical payment transaction ends after the actual inner fault');
        check($GLOBALS['member_cookies']===[],'No member cookie escapes failed payment');
    }
}
// A provider success response must not describe an unrelated caller's uncommitted writes as durable payment.
foreach([false,true]as $paid){
    foreach([0,1,3]as $depth){
        orderOwnerSeed();$pdo=Db::connect()->getPdo();
        if($depth===0){$pdo->beginTransaction();}else{for($i=0;$i<$depth;$i++){Db::startTrans();}}
        Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);
        if($paid){Db::name('Order')->where('order_id',1)->update(['order_status'=>1]);}
        $before=ownerState();PurchaseOwnerFault::reset();
        try{
            check(orderOwnerRun()['code']===2004 && $pdo->inTransaction() && ownerState()===$before,'Existing raw/managed caller is rejected intact, including pending paid replay');
            check(PurchaseOwnerFault::$calls===[],'Rejected callback neither starts nor ends the caller transaction');
        }finally{orderOwnerAbort($pdo);}
    }
}
if($mysql){
    foreach(['order','user','plog']as $table){
        orderOwnerSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');$before=ownerState();PurchaseOwnerFault::reset();
        try{check(orderOwnerRun()['code']===2004 && ownerState()===$before && PurchaseOwnerFault::$calls===[],'Nontransactional '.$table.' is rejected before BEGIN or writes');}
        finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
    }
}
printf("Order owner acknowledgements: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
