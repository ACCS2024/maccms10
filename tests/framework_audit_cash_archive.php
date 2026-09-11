<?php
/** Actual archive/refund atomicity, actor scope, storage readback and bounded financial batches. */
declare(strict_types=1);
require __DIR__.'/fixtures/cash_owner_db.php';
use think\facade\Db;
use app\common\model\Cash;
use app\common\util\CashArchive;
Db::execute('ALTER TABLE audit_cash ADD cash_remarks TEXT NULL');
$cash=new Cash();
foreach([0,1] as $status)foreach([null,['type'=>'user','id'=>1],['type'=>'admin','id'=>2]] as $actor) {
    cashRefundSeed(80,$status===0?20:0,20,$status);$original=Db::name('Cash')->where('cash_id',1)->find();$time=time();
    check($cash->delData(['cash_id'=>1],$actor)['code']===1,'Valid cash removal must atomically archive the original record');
    $archive=Db::name('CashHistory')->where('cash_id',1)->find();
    check(Db::name('Cash')->count()===0&&CashArchive::original($archive)===$original,'Cash snapshot must preserve every original stored field and type');
    check((int)$archive['cash_status']===($status===0?2:1)&&$archive['cash_actor_type']===($actor['type']??'internal')
        &&(int)$archive['cash_actor_id']===($actor['id']??0)&&(int)$archive['cash_time_archive']>=$time,'Archive must identify cancellation/paid state, actor and completion time');
    check(memberRow()['user_points']===($status===0?100:80)&&memberRow()['user_points_froze']===0,'Only a pending withdrawal is refundable');
    $before=cashRefundState();check($cash->delData(['cash_id'=>1],$actor)['code']===1&&cashRefundState()===$before,'Repeated removal cannot replace its archive or refund twice');
}
foreach([[],['type'=>'user','id'=>2],['type'=>'admin','id'=>0],['type'=>'internal','id'=>1],['type'=>[],'id'=>1],['type'=>'admin','id'=>true]] as $actor) {
    cashRefundSeed();$before=cashRefundState();check($cash->delData(['cash_id'=>1],$actor)['code']!==1&&cashRefundState()===$before,'An invalid actor or wrong member owner must preserve all financial rows');
}
cashRefundSeed();Db::name('Cash')->where('cash_id',1)->update(['cash_remarks'=>"历史备注 + ordinary\r\nname"]);$original=Db::name('Cash')->where('cash_id',1)->find();
check($cash->delData(['cash_id'=>1])['code']===1&&CashArchive::original(Db::name('CashHistory')->where('cash_id',1)->find())===$original,'Legacy extra columns and multiline Unicode must survive archival');
cashRefundSeed();Db::name('Cash')->where('cash_id',1)->update(['cash_remarks'=>str_repeat('a',CashArchive::MAX_PAYLOAD_BYTES+1)]);$before=cashRefundState();
check($cash->delData(['cash_id'=>1])['code']!==1&&cashRefundState()===$before,'Oversized legacy payload cannot consume a reservation or lose evidence');
foreach(['reject','payload','identity','owner_balance','other_owner_balance','previous_archive','deleted_archive'] as $fault) {
    cashRefundSeed();cashRefundSecondUser();$before=cashRefundState();
    if($fault==='reject')$body=$mysql?"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='archive unavailable'":"SELECT RAISE(ABORT,'archive unavailable');";
    elseif($fault==='payload')$body=$mysql?"SET NEW.cash_payload='changed'":"UPDATE audit_cash_history SET cash_payload='changed' WHERE cash_id=NEW.cash_id;";
    elseif($fault==='identity')$body=$mysql?'SET NEW.cash_actor_id=99':'UPDATE audit_cash_history SET cash_actor_id=99 WHERE cash_id=NEW.cash_id;';
    elseif($fault==='owner_balance')$body='UPDATE audit_user SET user_points=user_points+1 WHERE user_id=NEW.user_id'.($mysql?'':';');
    elseif($fault==='other_owner_balance')$body='UPDATE audit_user SET user_points=user_points+1 WHERE user_id=2'.($mysql?'':';');
    elseif($fault==='previous_archive')$body=$mysql?"BEGIN IF OLD.cash_id=2 THEN UPDATE audit_cash_history SET cash_payload='changed' WHERE cash_id=1; END IF; END":"UPDATE audit_cash_history SET cash_payload='changed' WHERE cash_id=1 AND OLD.cash_id=2;";
    else $body='DELETE FROM audit_cash_history WHERE cash_id=OLD.cash_id'.($mysql?'':';');
    $cashTrigger=in_array($fault,['previous_archive','deleted_archive'],true);
    $table=$cashTrigger?'cash':'cash_history';$event=$cashTrigger?'DELETE':'INSERT';
    Db::execute('CREATE TRIGGER archive_failure '.($mysql&&!$cashTrigger?'BEFORE':'AFTER').' '.$event.' ON audit_'.$table.' '.($mysql?'FOR EACH ROW '.$body:'BEGIN '.$body.' END'));
    try{check($cash->delData(['user_id'=>[1,2]])['code']!==1&&cashRefundState()===$before,'Archive or later storage changes must roll back every refund and snapshot: '.$fault);}
    finally{Db::execute('DROP TRIGGER archive_failure');}
}
cashRefundSeed();$original=Db::name('Cash')->where('cash_id',1)->find();$cash->delData(['cash_id'=>1]);
Db::name('Cash')->insert($original);Db::name('User')->where('user_id',1)->update(['user_points'=>80,'user_points_froze'=>20]);$before=cashRefundState();
check($cash->delData(['cash_id'=>1])['code']!==1&&cashRefundState()===$before,'Restored/reused cash IDs cannot overwrite old financial archives');
cashRefundSeed(80,0,20,1);Db::name('User')->where('user_id',1)->delete();
check($cash->delData(['cash_id'=>1])['code']===1&&Db::name('CashHistory')->count()===1,'Paid historical records remain archivable after their account was removed');
$valid=Db::name('CashHistory')->where('cash_id',1)->find();
foreach(['cash_payload'=>'{}','cash_payload_hash'=>'wrong','cash_id'=>0,'user_id'=>2,'cash_time'=>999,'cash_status'=>2] as $field=>$value) {
    try{CashArchive::original(array_replace($valid,[$field=>$value]));check(false,'Corrupt archive must be rejected');}
    catch(RuntimeException|JsonException $error){check(true,'Corrupt archive rejected before rendering');}
}
cashRefundSeed(0,1001,1);$rows=[];
for($id=2;$id<=1001;$id++)$rows[]=['cash_id'=>$id,'user_id'=>1,'cash_points'=>1,'cash_money'=>'1.00','cash_time'=>123];
foreach(array_chunk($rows,200) as $chunk)Db::name('Cash')->insertAll($chunk);
$before=cashRefundState();
foreach(['delData','auditData'] as $method)check($cash->$method(['user_id'=>1])['code']===1008&&cashRefundState()===$before,'Oversized cash batch must fail before financial effects');
check($cash->delData(['cash_id'=>range(1,1000)],['type'=>'user','id'=>1])['code']===1,'Maximum permitted batch must remain usable');
check(Db::name('Cash')->count()===1&&Db::name('CashHistory')->count()===1000&&memberRow()['user_points']===1000&&memberRow()['user_points_froze']===1,'Maximum batch must preserve complete archive and balance totals');
if($mysql) {
    cashRefundSeed();Db::execute('ALTER TABLE audit_cash_history ENGINE=MyISAM');$before=cashRefundState();
    try{check($cash->delData(['cash_id'=>1])['code']!==1&&cashRefundState()===$before,'Nontransactional archive must block refunds');}
    finally{Db::execute('ALTER TABLE audit_cash_history ENGINE=InnoDB');}
}
echo 'Cash archive: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
