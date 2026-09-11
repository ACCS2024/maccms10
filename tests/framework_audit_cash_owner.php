<?php
declare(strict_types=1);
require __DIR__.'/fixtures/cash_owner_db.php';
use think\facade\Db;
use app\common\model\Cash;
$observer=$mysql?new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname='.MEMBERSHIP_AUDIT_DATABASE.';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:''):new PDO('sqlite:'.MEMBERSHIP_AUDIT_DATABASE);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
function cashOwnerObserve(PDO $pdo): array {
    $result=[];foreach(['user','cash','plog'] as $table)$result[]=$pdo->query('SELECT * FROM audit_'.$table.' ORDER BY '.$table.'_id')->fetchAll(PDO::FETCH_ASSOC);return $result;
}
$cases=['normal','orm_begin_before','pdo_begin_before','pdo_begin_after','orm_begin_after',
    'orm_rollback_before','pdo_rollback_before','pdo_rollback_after','orm_rollback_after',
    'orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after','rollback_unrecoverable','caller_raw','caller_orm'];
foreach(['reserve','refund','settle'] as $operation)foreach($cases as $case) {
    cashOwnerSeed($operation);$connection=Db::connect();$connection->query('SELECT 1',[],true);$pdo=$connection->getPdo();
    $before=cashOwnerObserve($observer);$rollback=str_contains($case,'rollback');$caller=str_starts_with($case,'caller_');
    if($rollback) {
        [$table,$event]=match($operation){'reserve'=>['cash','INSERT'],'refund'=>['cash','DELETE'],'settle'=>['plog','INSERT']};
        Db::execute('CREATE TRIGGER cash_owner_reject BEFORE '.$event.' ON audit_'.$table.' '.($mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='ordinary persistence failure'":"BEGIN SELECT RAISE(ABORT,'ordinary persistence failure'); END"));
    }
    if($caller){if($case==='caller_raw')$pdo->beginTransaction();else Db::startTrans();Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);}
    PurchaseOwnerFault::reset($case==='rollback_unrecoverable'?['pdo_rollback_before'=>'always']:(str_starts_with($case,'orm_')||str_starts_with($case,'pdo_')?[$case=>1]:[]));
    try {
        $result=cashOwnerRun($operation);$unknown=str_contains($case,'commit')||$case==='rollback_unrecoverable';
        check(($result['code']===1)===($case==='normal'),'Cash acknowledgement fault returned incorrect success: '.$operation.'/'.$case);
        if($unknown) {
            check(in_array($result['code'],[2004,2005],true)&&$result['info']['retryable']===false&&!empty($result['info']['reference']),'Cash lost its unknown result and diagnostic reference');
            $calls=PurchaseOwnerFault::$calls;
            foreach(['reserve','refund','settle'] as $next)check(cashOwnerRun($next)['code']===2005,'Unknown cash result allowed another operation: '.$next);
            check(PurchaseOwnerFault::$calls===$calls,'Unknown cash result started another transaction');
            if($case==='rollback_unrecoverable') {
                check($pdo->inTransaction()&&(PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1&&(PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,'Unknown cash rollback lost original ownership or exceeded bounded cleanup');
                check(cashOwnerObserve($pdo)!==$before,'Rollback fixture failed to retain actual pending writes');
            } else {check(!$pdo->inTransaction(),'Cash COMMIT failure left an active original transaction');}
        } elseif($caller) {
            check($pdo->inTransaction()&&Db::name('User')->where('user_id',1)->value('user_name')==='caller-sentinel'&&PurchaseOwnerFault::$calls===[],'Cash operation changed or ended its caller transaction');
        } else {
            check(!$pdo->inTransaction(),'Cash known failure retained a transaction');
            if($case!=='normal')check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1,'Cash cleanup was not bounded');
        }
        $state=cashOwnerObserve($observer);
        if($case==='normal'||str_ends_with($case,'commit_after')) {
            $user=$state[0][0];
            check((int)$user['user_points']===($operation==='refund'?100:80)&&(int)$user['user_points_froze']===($operation==='reserve'?20:0),'Observer found partially committed cash balances');
            check(count($state[1])===($operation==='refund'?0:1)&&count($state[2])===($operation==='settle'?1:0),'Observer found partially committed cash/ledger rows');
            if($operation==='settle')check((int)$state[1][0]['cash_status']===1&&(int)$state[2][0]['plog_points']===20,'Cash settlement state/receipt incomplete');
        } else {check($state===$before,'Failed cash transition changed independently visible data');}
        check(!str_contains(json_encode($result),'123456')&&!str_contains(json_encode($result),'ordinary name'),'Cash outcome leaked payee information');
    } finally {
        PurchaseOwnerFault::reset();if($pdo->inTransaction())$pdo->rollBack();$connection->close();
        if($rollback)Db::execute('DROP TRIGGER cash_owner_reject');
    }
}
if($mysql)foreach(['reserve','refund','settle'] as $operation)foreach($operation==='settle'?['cash','user','plog']:['cash','user'] as $table) {
    cashOwnerSeed($operation);Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');$before=cashOwnerObserve($observer);PurchaseOwnerFault::reset();
    try{check(cashOwnerRun($operation)['code']!==1&&cashOwnerObserve($observer)===$before&&PurchaseOwnerFault::$calls===[],'Cash started on nontransactional '.$table);}
    finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
}
echo 'Cash owner transactions: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
