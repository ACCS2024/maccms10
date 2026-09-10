<?php
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_fault_db.php';
use think\facade\Db;
use app\common\model\User;
use app\common\util\FinancialOperationException;

$observer=$mysql
 ? new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname='.MEMBERSHIP_AUDIT_DATABASE.';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'')
 : new PDO('sqlite:'.MEMBERSHIP_AUDIT_DATABASE);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
function moneyRun(string $kind):array {
 try{return $kind==='reward'?(new User())->reward(20,1):(new User())->upgrade(['group_id'=>3,'long'=>'day']);}
 catch(FinancialOperationException $error){return $error->result();}
}
function moneyFailure(string $kind):int {return $kind==='reward'?2003:1009;}
function moneyRejectLedger(string $kind):void {$GLOBALS['member_fail_log_types']=[$kind==='reward'?4:7];}
function moneyAbort(PDO $pdo):void {PurchaseOwnerFault::reset();if($pdo->inTransaction()){$pdo->rollBack();}Db::connect()->close();}
function moneyDepth():int {return (new ReflectionProperty(think\db\PDOConnection::class,'transTimes'))->getValue(Db::connect());}
function moneyCommitted(string $kind,PDO $observer):void {
 check((int)$observer->query('SELECT SUM(user_points) FROM audit_user WHERE user_id>1')->fetchColumn()===4,'Independent observer confirms all three referral credits');
 check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===($kind==='reward'?100:80),'Independent observer confirms the correct buyer balance');
 check((int)$observer->query('SELECT COUNT(*) FROM audit_plog')->fetchColumn()===($kind==='reward'?3:4),'Independent observer confirms all operation ledgers');
}
foreach(['reward','membership']as $kind){
 ownerSeed();$result=moneyRun($kind);check($result['code']===1,'Ordinary standalone operation succeeds: '.$kind);moneyCommitted($kind,$observer);
 foreach(['orm_begin_before','pdo_begin_before','pdo_begin_after','orm_begin_after']as $stage){
  ownerSeed();$before=ownerState();PurchaseOwnerFault::reset([$stage=>1]);$result=moneyRun($kind);
  check($result['code']===moneyFailure($kind) && ownerState()===$before,'BEGIN acknowledgement fault has no financial effect: '.$kind.'/'.$stage);
  check(!Db::connect()->getPdo()->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)===1,'Actual BEGIN fault is exercised and its owner transaction ends');
 }
 foreach(['orm_rollback_before','pdo_rollback_before','pdo_rollback_after','orm_rollback_after']as $stage){
  ownerSeed();$before=ownerState();moneyRejectLedger($kind);PurchaseOwnerFault::reset([$stage=>1]);$result=moneyRun($kind);
  check($result['code']===moneyFailure($kind) && ownerState()===$before,'Confirmed owner cleanup restores all financial state: '.$kind.'/'.$stage);
  check(!Db::connect()->getPdo()->inTransaction() && (PurchaseOwnerFault::$calls[$stage]??0)>=1,'Actual rollback fault is exercised and leaves no owner transaction');
  check($GLOBALS['member_cookies']===[],'Failed membership never publishes group cookies');
 }
 foreach(['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after']as $stage){
  ownerSeed();$before=ownerState();PurchaseOwnerFault::reset([$stage=>1]);$result=moneyRun($kind);
  check($result['code']===2004 && !$result['info']['retryable'],'COMMIT acknowledgement always preserves uncertainty: '.$kind.'/'.$stage);
  if(str_ends_with($stage,'after')){moneyCommitted($kind,$observer);}else{check(ownerState()===$before,'Commit-before failure leaves actual storage unchanged');}
  check($GLOBALS['member_cookies']===[],'Unknown commit does not publish membership cookies');
  $state=ownerState();$calls=PurchaseOwnerFault::$calls;
  check(moneyRun('reward')['code']===2005 && moneyRun('membership')['code']===2005 && ownerBuy()['code']===2005,'Unknown operation blocks other financial domains in the same context');
  check(ownerState()===$state && PurchaseOwnerFault::$calls===$calls,'Cross-domain blocking performs no second financial attempt');
 }
 ownerSeed();$before=ownerState();$original=Db::connect()->getPdo();moneyRejectLedger($kind);
 PurchaseOwnerFault::reset(['pdo_rollback_before'=>'always']);$result=moneyRun($kind);
 check($result['code']===2005 && $original->inTransaction(),'Unrecoverable owner rollback is unknown, even after discarding the ORM reference');
 check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1 && (PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,'Owner cleanup remains bounded to one ORM attempt and one original-PDO fallback');
 check(moneyRun($kind)['code']===2005,'Unrecoverable cleanup blocks the original operation');moneyAbort($original);
 check(ownerState()===$before,'Fixture cleanup of the retained owner PDO restores actual storage');

 foreach([1,3]as $depth){
  ownerSeed();$committed=ownerState();for($i=0;$i<$depth;$i++){Db::startTrans();}
  Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);$pdo=Db::connect()->getPdo();$before=ownerState();PurchaseOwnerFault::reset();
  try{
   $result=moneyRun($kind);check($result['code']===1 && $pdo->inTransaction() && moneyDepth()===$depth,'Normal nested operation preserves caller nesting: '.$kind);
   check(memberRow(1)['user_name']==='caller-sentinel','Nested operation preserves the caller ordinary update');
   check((int)$observer->query('SELECT SUM(user_points) FROM audit_user WHERE user_id>1')->fetchColumn()===0,'Nested credits are not published before caller commit');
   if($kind==='membership'){check($result['info']['transaction_pending']===true && $GLOBALS['member_cookies']===[],'Nested membership is explicitly pending and publishes no group cookies');}
   check((PurchaseOwnerFault::$calls['pdo_commit_before']??0)===0 && (PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===0,'Nested service neither commits nor fully rolls back its caller');
   for($i=0;$i<$depth;$i++){Db::rollback();}
   check(ownerState()===$committed,'Ordinary caller ORM rollback restores its entire operation');
  }finally{moneyAbort($pdo);}
 }
 foreach(['orm_nested_begin_before','orm_nested_begin_after','orm_nested_commit_before','orm_nested_commit_after']as $stage){
  ownerSeed();Db::startTrans();Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);$pdo=Db::connect()->getPdo();$before=ownerState();
  try{
   PurchaseOwnerFault::reset([$stage=>1]);$result=moneyRun($kind);
   check($result['code']===moneyFailure($kind) && ownerState()===$before,'Nested acknowledgement restores only the service scope: '.$kind.'/'.$stage);
   check($pdo->inTransaction() && moneyDepth()===1 && (PurchaseOwnerFault::$calls[$stage]??0)===1,'Actual nested failure leaves the original caller active and correctly nested');
   check((PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===0,'Nested recovery never uses full PDO rollback');
  }finally{moneyAbort($pdo);}
 }
 foreach(['caller_rollback_before','caller_rollback_after']as $stage){
  ownerSeed();$committed=ownerState();Db::startTrans();Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);$pdo=Db::connect()->getPdo();
  try{
   moneyRejectLedger($kind);PurchaseOwnerFault::reset([$stage=>1]);$result=moneyRun($kind);
   check($result['code']===2005 && $result['info']['caller_rollback_required'] && $pdo->inTransaction(),'Unacknowledged caller cleanup explicitly requires outer-owner abort: '.$kind.'/'.$stage);
   check(memberRow(1)['user_name']==='caller-sentinel' && (PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===0,'Uncertain service cleanup retains the original caller and its update');
   check(moneyRun('reward')['code']===2005 && moneyRun('membership')['code']===2005,'Uncertain caller cleanup blocks cross-domain retry');
  }finally{moneyAbort($pdo);}
  check(ownerState()===$committed,'Explicit outer-owner abort removes all pending state');
 }
}
// Expiration and actual persisted fields are checked before success or group-cookie publication.
ownerSeed();Db::name('User')->where('user_id',1)->update(['user_end_time'=>4294967295]);$before=ownerState();
check(moneyRun('membership')['code']===1009 && ownerState()===$before,'Membership expiration cannot overflow its installation column');
foreach(['group_id'=>'2','user_end_time'=>'0','user_points'=>'NEW.user_points+1']as $field=>$value){
 ownerSeed();$before=ownerState();
 $body=$mysql?'FOR EACH ROW BEGIN IF NEW.user_id=1 THEN SET NEW.'.$field.'='.$value.'; END IF; END'
  :'WHEN NEW.user_id=1 BEGIN UPDATE audit_user SET '.$field.'='.$value.' WHERE user_id=NEW.user_id; END';
 Db::execute('CREATE TRIGGER audit_member_fields '.($mysql?'BEFORE':'AFTER').' UPDATE ON audit_user '.$body);
 try{check(moneyRun('membership')['code']===1009 && ownerState()===$before,'Changed persisted membership field rolls back every effect: '.$field);}
 finally{Db::execute('DROP TRIGGER audit_member_fields');}
}
foreach(['user_id'=>'99','plog_type'=>'2','plog_points'=>'1','plog_remarks'=>"'changed'"]as $field=>$value){
 ownerSeed();$before=ownerState();
 $body=$mysql?'FOR EACH ROW BEGIN IF NEW.plog_type=7 THEN SET NEW.'.$field.'='.$value.'; END IF; END'
  :'WHEN NEW.plog_type=7 BEGIN UPDATE audit_plog SET '.$field.'='.$value.' WHERE plog_id=NEW.plog_id; END';
 Db::execute('CREATE TRIGGER audit_member_ledger '.($mysql?'BEFORE':'AFTER').' INSERT ON audit_plog '.$body);
 try{check(moneyRun('membership')['code']===1009 && ownerState()===$before,'Changed stored membership ledger rolls back every effect: '.$field);}
 finally{Db::execute('DROP TRIGGER audit_member_ledger');}
}
if($mysql){
 foreach(['user','plog']as $table){
  ownerSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');$before=ownerState();
  try{check(moneyRun('membership')['code']===1009 && ownerState()===$before,'Membership rejects nontransactional '.$table.' before writes');}
  finally{Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');}
 }
 ownerSeed();Db::execute('ALTER TABLE audit_plog MODIFY plog_points TINYINT UNSIGNED NOT NULL DEFAULT 0');
 $GLOBALS['member_groups'][3]['group_points_day']=300;Db::name('User')->where('user_id',1)->update(['user_points'=>1000]);$before=ownerState();
 try{check(moneyRun('membership')['code']===1009 && ownerState()===$before,'Non-strict membership ledger clipping is detected and rolled back');}
 finally{Db::execute('ALTER TABLE audit_plog MODIFY plog_points SMALLINT UNSIGNED NOT NULL DEFAULT 0');}
}
foreach(glob(dirname(__DIR__).'/application/lang/*.php')as $file){
 $language=require $file;$text=$language['model/financial/outcome_unknown']??null;
 check(is_string($text) && substr_count($text,'%s')===1 && str_contains(sprintf($text,'ordinary-reference'),'ordinary-reference'),'Every language preserves the financial diagnostic reference');
 check(is_string($language['model/user/reward_err']??null) && $language['model/user/reward_err']!=='','Every language has a controlled reward-failure message');
}
printf("Reward and membership acknowledgements: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
