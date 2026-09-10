<?php
declare(strict_types=1);
require __DIR__.'/fixtures/card_fault_db.php';
use think\facade\Db;
use app\common\model\User;
use app\common\model\Order;
use app\common\util\FinancialOperationException;
$observer=$mysql?new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname='.MEMBERSHIP_AUDIT_DATABASE.';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:''):new PDO('sqlite:'.MEMBERSHIP_AUDIT_DATABASE);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
function cardOwnerAbort(PDO $pdo):void {PurchaseOwnerFault::reset();if($pdo->inTransaction()){$pdo->rollBack();}Db::connect()->close();}
function cardOwnerCommitted(PDO $observer):void {
    check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===120,'Observer confirms the full card credit');
    check((int)$observer->query('SELECT card_use_status FROM audit_card')->fetchColumn()===1,'Observer confirms the consumed card');
    check((int)$observer->query('SELECT COUNT(*) FROM audit_plog')->fetchColumn()===1 && (int)$observer->query('SELECT plog_points FROM audit_plog')->fetchColumn()===20,'Observer confirms exactly one full-value receipt');
}
cardOwnerSeed();check(cardOwnerRun()['code']===1,'Ordinary owner redemption succeeds');cardOwnerCommitted($observer);
foreach(['orm_begin_before','pdo_begin_before','pdo_begin_after','orm_begin_after']as $stage){
    cardOwnerSeed();$before=cardState();$pdo=Db::connect()->getPdo();PurchaseOwnerFault::reset([$stage=>1]);$result=cardOwnerRun();
    check($result['code']===1004 && cardState()===$before,'BEGIN acknowledgement faults have controlled zero-write failure: '.$stage);
    check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)===1,'Actual BEGIN fault does not leave an owner transaction');
}
foreach(['orm_rollback_before','pdo_rollback_before','pdo_rollback_after','orm_rollback_after']as $stage){
    foreach(['missing','ledger']as $reason){
        cardOwnerSeed();if($reason==='missing'){Db::name('Card')->where('card_id',1)->delete();}else{$GLOBALS['member_fail_log_types']=[1];}
        $before=cardState();$pdo=Db::connect()->getPdo();PurchaseOwnerFault::reset([$stage=>1]);$result=cardOwnerRun();
        check($result['code']===($reason==='missing'?1002:1004) && cardState()===$before,'Confirmed cleanup restores card, balance and ledger: '.$reason.'/'.$stage);
        check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1 && (PurchaseOwnerFault::$calls[$stage]??0)>=1,'Card owner exercises the fault and performs bounded cleanup');
    }
}
foreach(['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after']as $stage){
    cardOwnerSeed();$before=cardState();$pdo=Db::connect()->getPdo();PurchaseOwnerFault::reset([$stage=>1]);$result=cardOwnerRun();
    check($result['code']===2004 && $result['info']['outcome']==='commit_unknown' && !$result['info']['retryable'],'Attempted COMMIT acknowledgement loss is unknown: '.$stage);
    check(!$pdo->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)===1,'Actual COMMIT fault ends original physical ownership');
    if(str_ends_with($stage,'after')){cardOwnerCommitted($observer);}else{check(cardState()===$before,'COMMIT-before fault is actually rolled back');}
    $state=cardState();$calls=PurchaseOwnerFault::$calls;
    check(cardOwnerRun()['code']===2005 && (new Order())->notify('ordinary-order','weixin','10.00')['code']===2005
        && (new User())->upgrade(['group_id'=>3,'long'=>'day'])['code']===2005,'Unknown card completion blocks other financial operations in the same context');
    try{(new User())->reward(20,1);throw new RuntimeException('Reward did not stop');}catch(FinancialOperationException $e){check($e->result()['code']===2005,'Unknown card completion blocks direct rewards');}
    check(cardState()===$state && PurchaseOwnerFault::$calls===$calls,'Cross-domain blocking makes no second transaction attempt');
    check(!str_contains(json_encode($result),'fixture-card') && !str_contains(json_encode($result),'fixture'),'Unknown response does not expose card credentials');
}
cardOwnerSeed();$before=cardState();$pdo=Db::connect()->getPdo();$GLOBALS['member_fail_log_types']=[1];PurchaseOwnerFault::reset(['pdo_rollback_before'=>'always']);$result=cardOwnerRun();
check($result['code']===2005 && $pdo->inTransaction() && !$result['info']['retryable'],'Unrecoverable card rollback preserves uncertainty and retained PDO');
check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1 && (PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,'Unrecoverable rollback performs one ORM call and one original-PDO fallback');
check((int)$observer->query('SELECT card_use_status FROM audit_card')->fetchColumn()===0 && cardOwnerRun()['code']===2005,'Retained pending claim is invisible and blocked from retry');
cardOwnerAbort($pdo);check(cardState()===$before,'Explicit fixture cleanup removes the retained card claim');
foreach([0,1,3]as $depth){
    cardOwnerSeed();$pdo=Db::connect()->getPdo();if($depth===0){$pdo->beginTransaction();}else{for($i=0;$i<$depth;$i++){Db::startTrans();}}
    Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);$before=cardState();PurchaseOwnerFault::reset();
    try{check(cardOwnerRun()['code']===1004 && $pdo->inTransaction() && cardState()===$before && PurchaseOwnerFault::$calls===[],'Existing caller transaction is rejected without changing it');}
    finally{cardOwnerAbort($pdo);}
}
foreach([
    ['user','UPDATE','user_points','NEW.user_points+1'],
    ['plog','INSERT','user_id','99'],['plog','INSERT','plog_type','2'],['plog','INSERT','plog_points','1'],['plog','INSERT','plog_remarks',"'changed'"],
    ['card','UPDATE','card_use_status','0'],['card','UPDATE','card_sale_status','0'],['card','UPDATE','card_use_time','0'],['card','UPDATE','user_id','2'],
    ['card','UPDATE','card_points','1'],['card','UPDATE','card_money','11'],['card','UPDATE','card_no',"'changed'"],['card','UPDATE','card_pwd',"'changed'"],
]as [$table,$event,$field,$value]){
    cardOwnerSeed();$before=cardState();$body=$mysql?'FOR EACH ROW SET NEW.'.$field.'='.$value:'BEGIN UPDATE audit_'.$table.' SET '.$field.'='.$value.' WHERE '.$table.'_id=NEW.'.$table.'_id; END';
    Db::execute('CREATE TRIGGER audit_card_storage '.($mysql?'BEFORE':'AFTER').' '.$event.' ON audit_'.$table.' '.$body);
    try{check(cardOwnerRun()['code']===1004 && cardState()===$before && !Db::connect()->getPdo()->inTransaction(),'Altered stored card effect is fully rejected: '.$table.'.'.$field);}
    finally{Db::execute('DROP TRIGGER audit_card_storage');}
}
if($mysql){
    foreach(['card','user','plog']as $table){
        cardOwnerSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');$before=cardState();PurchaseOwnerFault::reset();
        try{check(cardOwnerRun()['code']===1004 && cardState()===$before && PurchaseOwnerFault::$calls===[],'Nontransactional '.$table.' is rejected before redemption');}
        finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
    }
    cardOwnerSeed(100,300);Db::execute('ALTER TABLE audit_plog MODIFY plog_points TINYINT UNSIGNED NOT NULL DEFAULT 0');$before=cardState();
    try{check(cardOwnerRun()['code']===1004 && cardState()===$before,'Non-strict 300-to-255 ledger clipping cannot consume a card');}
    finally{Db::execute('ALTER TABLE audit_plog MODIFY plog_points INT UNSIGNED NOT NULL DEFAULT 0');}
}
printf("Card owner and exact storage: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
