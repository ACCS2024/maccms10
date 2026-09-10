<?php
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_fault_db.php';
use think\facade\Db;
use app\common\util\ContentPurchase;
use app\common\util\PurchaseTransaction;
ownerSeed();$result=ownerBuy();check($result['code']===1&&memberRow(1)['user_points']===80&&Db::name('Plog')->count()===4,'Normal owner commits all actual ledgers and account balances');
$before=ownerState();check(ownerBuy()['code']===1&&ownerState()===$before,'Existing owner purchase is idempotent');
foreach(['orm_begin_before','pdo_begin_before','pdo_begin_after','orm_begin_after']as $stage){
    ownerSeed();$before=ownerState();PurchaseOwnerFault::reset([$stage=>1]);$result=ownerBuy();
    check($result['code']===2003 && ownerState()===$before,'BEGIN fault is controlled and zero-write: '.$stage);
    check(!Db::connect()->getPdo()->inTransaction(),'BEGIN fault cannot leave the original owner transaction active: '.$stage);
}
foreach(['orm_rollback_before','pdo_rollback_before','pdo_rollback_after','orm_rollback_after']as $stage){
    foreach(['insufficient','ledger','quote_final','reward']as $reason){
        ownerSeed($reason==='insufficient'?10:100);$before=ownerState();
        if($reason==='ledger')$GLOBALS['member_fail_log_types']=[8];
        if($reason==='reward')$GLOBALS['member_fail_log_types']=[5];
        PurchaseOwnerFault::reset([$stage=>1]);
        $result=$reason==='quote_final'?ContentPurchase::buyVideo(1,fn($user)=>['code'=>6001,'msg'=>'password_required']):ownerBuy();
        check($result['code']===($reason==='insufficient'?2002:($reason==='quote_final'?6001:2003))&&ownerState()===$before,
            'One owner error finish rolls back every financial effect: '.$reason.'/'.$stage);
        check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1,'Owner performs at most one ORM rollback: '.$reason.'/'.$stage);
        check(!Db::connect()->getPdo()->inTransaction(),'Owner fallback never leaves an active original transaction: '.$reason.'/'.$stage);
    }
}
foreach(['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after']as $stage){
    ownerSeed();$before=ownerState();PurchaseOwnerFault::reset([$stage=>1]);$result=ownerBuy();
    check($result['code']===2004&&$result['info']['retryable']===false,'Any attempted COMMIT fault has a distinct unknown response: '.$stage);
    $after=ownerState();$committed=in_array($stage,['pdo_commit_after','orm_commit_after'],true);
    check($committed?(memberRow(1)['user_points']===80&&Db::name('Plog')->count()===4&&Db::name('Ulog')->count()===1):$after===$before,
        'Independent actual storage retains the real commit state, not an assumed result: '.$stage);
    $calls=PurchaseOwnerFault::$calls;check(ownerBuy()['code']===2005&&ownerState()===$after&&PurchaseOwnerFault::$calls===$calls,'Unknown completion fences another purchase in this request');
    ownerRequest();PurchaseOwnerFault::reset();check(ownerBuy()['code']===1,'A fresh request is not incorrectly fenced by a previous request in this worker');
}
ownerSeed();$before=ownerState();$GLOBALS['member_fail_log_types']=[8];$original=Db::connect()->getPdo();PurchaseOwnerFault::reset(['pdo_rollback_before'=>'always']);$result=ownerBuy();
check($result['code']===2005&&$result['info']['retryable']===false&&$original->inTransaction(),'An unrecoverable rollback is explicitly uncertain; close is not falsely reported as rollback');
check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1&&(PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,'Unrecoverable cleanup performs one ORM call and one bounded original-PDO fallback');
check(ownerBuy()['code']===2005,'Unrecoverable cleanup fences this request');
PurchaseOwnerFault::reset();$original->rollBack();unset($original);check(ownerState()===$before,'Fixture explicitly releases its retained original PDO and observes full rollback');
ownerSeed();$before=ownerState();Db::startTrans();Db::name('User')->where('user_id',1)->update(['user_name'=>'outer-sentinel']);$original=Db::connect()->getPdo();
check(ownerBuy()['code']===2003&&$original->inTransaction()&&memberRow(1)['user_name']==='outer-sentinel','Pre-existing caller remains untouched');Db::rollback();
ownerSeed();$before=ownerState();$original=Db::connect();$result=ContentPurchase::buyVideo(1,function($user)use($manager){$manager->connect(null,true);return ownerQuote($user);});
check($result['code']===2005&&ownerState()===$before,'Replacement after quote cannot redirect any debit, and original transaction is rolled back');
check(!$original->getPdo()->inTransaction(),'Replacement preserves cleanup of the saved original owner');
foreach(['orm_nested_begin_before','orm_nested_begin_after','orm_nested_commit_before','orm_nested_commit_after','caller_rollback_before','caller_rollback_after','caller_release_before','caller_release_after']as $stage){
    ownerSeed();$before=ownerState();if(str_contains($stage,'rollback'))$GLOBALS['member_fail_log_types']=[5];PurchaseOwnerFault::reset([$stage=>1]);$result=ownerBuy();
    check($result['code']===2003&&ownerState()===$before,'Containing purchase owner confirms rollback of all effects after an isolated referral fault: '.$stage);
    check((PurchaseOwnerFault::$calls[$stage]??0)>=1,'The actual referral transaction fault was reached: '.$stage);
    check(!Db::connect()->getPdo()->inTransaction(),'Nested referral fault leaves no owner transaction active: '.$stage);
}
ownerSeed();$before=ownerState();$result=ContentPurchase::buyVideo(1,function($user){Db::name('User')->where('user_id',1)->setDec('user_points',1);Db::connect()->getPdo()->commit();return ownerQuote($user);});
check($result['code']===2005&&memberRow(1)['user_points']===99,'Unexpected transaction completion is unknown, never falsely described as rolled back');
check(ownerBuy()['code']===2005,'Unexpected transaction completion fences the current request');
ownerSeed();$before=ownerState();$result=ContentPurchase::buyVideo(1,function($user){
    Db::name('User')->where('user_id',1)->setDec('user_points',1);
    Db::connect()->getPdo()->commit();
    throw new RuntimeException('Ordinary callback failure after an unexpected transaction end');
});
check($result['code']===2005&&memberRow(1)['user_points']===99,'An unexpected end followed by an exception cannot be called a confirmed rollback');
check(preg_match('/^[a-f0-9]{24}$/D',$result['info']['reference'])===1,'Unknown result has a bounded diagnostic reference');
$repeat=ownerBuy();
check($repeat['code']===2005&&$repeat['info']['reference']===$result['info']['reference']&&!$repeat['info']['retryable'],'Request fence preserves diagnostic identity and prevents a second financial attempt');
// Automatic reconnect is an explicit precondition of this owner transaction contract.
ownerSeed();$before=ownerState();$savedConfig=$manager->getConfig();
$changedConfig=$savedConfig;$changedConfig['connections']['audit']['break_reconnect']=true;
$manager->setConfig($changedConfig);$manager->connect(null,true);
check(ownerBuy()['code']===2003&&ownerState()===$before,'Owner rejects automatic reconnect before starting or charging');
$manager->setConfig($savedConfig);$manager->connect(null,true);
foreach (glob(dirname(__DIR__).'/application/lang/*.php') as $file) {
    $language=require $file;
    $message=$language['index/buy_popedom_outcome_unknown']??null;
    check(is_string($message)&&substr_count($message,'%s')===1&&str_contains(sprintf($message,'ordinary-reference'),'ordinary-reference'),
        'Every shipped language must preserve the unknown-outcome diagnostic reference');
}
printf("Purchase owner acknowledgements: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
