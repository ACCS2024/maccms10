<?php
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_fault_db.php';
use think\facade\Db;
use app\common\util\ContentPurchase;
use app\common\util\PurchaseTransaction;

$observer=$mysql
 ? new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname='.MEMBERSHIP_AUDIT_DATABASE.';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'')
 : new PDO('sqlite:'.MEMBERSHIP_AUDIT_DATABASE);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
function callerBuy():array {return ContentPurchase::buy(1,ownerQuote([])['record']);}
function callerDepth():int {return (new ReflectionProperty(think\db\PDOConnection::class,'transTimes'))->getValue(Db::connect());}
function callerBegin(int $balance=100,int $depth=1):array {
 ownerSeed($balance);$committed=ownerState();
 for($i=0;$i<$depth;$i++){Db::startTrans();}
 Db::name('User')->where('user_id',1)->update(['user_name'=>'outer-sentinel']);
 $before=ownerState();PurchaseOwnerFault::reset();
 return [$committed,$before,Db::connect()->getPdo()];
}
function callerEnd(PDO $pdo):void {
 // The test is the outer owner. Production purchase code is forbidden from doing this.
 PurchaseOwnerFault::reset();if($pdo->inTransaction()){$pdo->rollBack();}Db::connect()->close();
}
function callerUntouched(PDO $pdo,int $depth=1):void {
 check($pdo===Db::connect()->getPdo() && $pdo->inTransaction(),'Caller retains the same active physical PDO');
 check(callerDepth()===$depth,'Confirmed scope completion restores exactly the caller nesting level');
 check(memberRow(1)['user_name']==='outer-sentinel','Caller ordinary update survives purchase completion');
 check((PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===0 && (PurchaseOwnerFault::$calls['pdo_commit_before']??0)===0,'Purchase never commits or fully rolls back its caller');
}
foreach([1,3]as $depth){
 [$committed,$before,$pdo]=callerBegin(100,$depth);
 try{
  $result=callerBuy();check($result['code']===1 && memberRow(1)['user_points']===80 && Db::name('Ulog')->count()===1,'Normal nested purchase creates one debit and receipt');
  callerUntouched($pdo,$depth);
  check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===100,'Independent observer cannot see an uncommitted nested debit');
  $saved=ownerState();check(callerBuy()['code']===1 && ownerState()===$saved,'Nested receipt is idempotent before caller commit');
  for($i=0;$i<$depth;$i++){Db::rollback();}
  check(ownerState()===$committed,'Ordinary caller ORM rollback restores the entire nested purchase');
 }finally{callerEnd($pdo);}
}
[$committed,$before,$pdo]=callerBegin();
try{
 check(callerBuy()['code']===1,'Caller can choose to commit a successful purchase');Db::commit();
 check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===80,'Only caller commit publishes the debit to an independent connection');
 check($observer->query('SELECT user_name FROM audit_user WHERE user_id=1')->fetchColumn()==='outer-sentinel','Caller commit also publishes its unrelated update');
}finally{callerEnd($pdo);}

foreach(['insufficient','buyer_ledger','referral_ledger']as $reason){
 [$committed,$before,$pdo]=callerBegin($reason==='insufficient'?10:100);
 try{
  if($reason==='buyer_ledger'){$GLOBALS['member_fail_log_types']=[8];}
  if($reason==='referral_ledger'){$GLOBALS['member_fail_log_types']=[5];}
  $result=callerBuy();check($result['code']===($reason==='insufficient'?2002:2003) && ownerState()===$before,'Business rejection rolls back only the purchase scope: '.$reason);
  callerUntouched($pdo);
 }finally{callerEnd($pdo);}
}
// The old second ORM rollback is never used, including when its acknowledgement would fail.
[$committed,$before,$pdo]=callerBegin(10);
try{
 PurchaseOwnerFault::reset(['orm_nested_rollback_after'=>'always']);$result=callerBuy();
 check($result['code']===2002 && ownerState()===$before,'Insufficient balance retains its normal result under an ORM rollback acknowledgement fault');
 check((PurchaseOwnerFault::$calls['orm_nested_rollback_before']??0)===0,'The purchase performs no caller-owned ORM rollback');callerUntouched($pdo);
}finally{callerEnd($pdo);}

foreach(['caller_savepoint_before','caller_savepoint_after','orm_nested_begin_before','orm_nested_begin_after']as $stage){
 [$committed,$before,$pdo]=callerBegin();
 try{
  PurchaseOwnerFault::reset([$stage=>1]);$result=callerBuy();
  check($result['code']===2003 && ownerState()===$before,'Failed scope creation has no financial effect: '.$stage);callerUntouched($pdo);
 }finally{callerEnd($pdo);}
}
foreach(['before','after']as $position){
 foreach([1,2]as $call){
  [$committed,$before,$pdo]=callerBegin();
  try{
   PurchaseOwnerFault::reset(['orm_nested_commit_'.$position=>$call]);$result=callerBuy();
   check($result['code']===2003 && ownerState()===$before,'Referral or purchase completion fault rolls back to the private target: '.$position.'/'.$call);
   callerUntouched($pdo);
  }finally{callerEnd($pdo);}
 }
}
foreach(['before','after']as $position){
 [$committed,$before,$pdo]=callerBegin();
 try{
  $GLOBALS['member_fail_log_types']=[5];PurchaseOwnerFault::reset(['orm_nested_rollback_'.$position=>1]);$result=callerBuy();
  check($result['code']===2003 && ownerState()===$before,'Referral rollback fault cannot cause the purchase to end its caller: '.$position);callerUntouched($pdo);
 }finally{callerEnd($pdo);}
}
foreach(['caller_rollback_before','caller_rollback_after']as $stage){
 [$committed,$before,$pdo]=callerBegin();
 try{
  $GLOBALS['member_fail_log_types']=[8];PurchaseOwnerFault::reset([$stage=>'always']);$result=callerBuy();
  check($result['code']===2005 && $result['info']['caller_rollback_required']===true && !$result['info']['retryable'],'Unacknowledged partial rollback requires caller abort: '.$stage);
  check($pdo->inTransaction() && memberRow(1)['user_name']==='outer-sentinel','Uncertain cleanup preserves caller transaction and sentinel');
  check(memberRow(1)['user_points']===($stage==='caller_rollback_before'?80:100),'Observe actual storage on either side of rollback acknowledgement');
  check((PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===0 && (PurchaseOwnerFault::$calls['caller_rollback_before']??0)===1,'Uncertain caller cleanup has one bounded partial rollback and no full fallback');
  $state=ownerState();$calls=PurchaseOwnerFault::$calls;
  check(callerBuy()['code']===2005 && ownerBuy()['code']===2005 && ownerState()===$state && PurchaseOwnerFault::$calls===$calls,'Unknown scope fences both legacy and resolved purchases in the same request');
 }finally{callerEnd($pdo);}
 check(ownerState()===$committed,'Explicit outer-owner abort restores all rows after an uncertain scope');
}
foreach(['before','after']as $position){
 [$committed,$before,$pdo]=callerBegin();
 try{
  PurchaseOwnerFault::reset(['caller_release_'.$position=>1]);$result=callerBuy();
  check($result['code']===($position==='before'?2003:2005),'Release acknowledgement has a controlled result reflecting whether compensation was confirmed');
  check($pdo->inTransaction() && memberRow(1)['user_name']==='outer-sentinel','Release failure cannot end the outer transaction');
  check(memberRow(1)['user_points']===($position==='before'?100:80),'Release failure does not invent a confirmed financial rollback');
  check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===100,'Release failure does not publish an uncommitted debit');
 }finally{callerEnd($pdo);}
}
[$committed,$before,$pdo]=callerBegin();
try{
 $GLOBALS['member_fail_log_types']=[8];PurchaseOwnerFault::reset(['caller_release_before'=>'always']);$result=callerBuy();
 check($result['code']===2003 && ownerState()===$before,'A retained savepoint after confirmed rollback has no financial effects');callerUntouched($pdo);
}finally{callerEnd($pdo);}

ownerSeed();$before=ownerState();$pdo=Db::connect()->getPdo();$pdo->beginTransaction();
try{
 Db::name('User')->where('user_id',1)->update(['user_name'=>'outer-sentinel']);$saved=ownerState();
 check(callerBuy()['code']===2003 && $pdo->inTransaction() && ownerState()===$saved && callerDepth()===0,'Unmanaged raw PDO caller is rejected before adding ORM nesting or charges');
}finally{callerEnd($pdo);}
ownerSeed();Db::startTrans();$pdo=Db::connect()->getPdo();$pdo->commit();$before=ownerState();
try{
 check(callerBuy()['code']===2003 && ownerState()===$before && callerDepth()===1 && !$pdo->inTransaction(),'Stale ORM depth is rejected before a legacy owner begins');
}finally{Db::rollback();}

[$committed,$before,$pdo]=callerBegin();$originalConnection=Db::connect();
try{
 $scope=new PurchaseTransaction(1,1,true);$scope->begin();Db::name('User')->where('user_id',1)->setDec('user_points',1);
 $manager->connect(null,true);$result=$scope->rollback(['code'=>2003,'msg'=>'ordinary failure']);
 check($result['code']===2005 && $result['info']['caller_rollback_required'],'Connection replacement reports caller ownership loss');
 check($pdo->inTransaction() && (int)$pdo->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===99,'Replacement neither closes nor rolls back the retained caller PDO');
 check((int)$observer->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===100,'Replacement never publishes the retained caller write');
 check(callerBuy()['code']===2005,'Replacement fences another purchase through the new facade');
}finally{callerEnd($pdo);$originalConnection->close();}

[$committed,$before,$pdo]=callerBegin();
try{
 $scope=new PurchaseTransaction(1,1,true);$scope->begin();Db::name('User')->where('user_id',1)->setDec('user_points',1);
 $target=(new ReflectionProperty(app\common\util\FinancialTransaction::class,'savepoint'))->getValue($scope);
 $pdo->exec('RELEASE SAVEPOINT '.$target);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_SILENT);
 $result=$scope->rollback(['code'=>2003,'msg'=>'ordinary failure']);
 check($result['code']===2005 && $pdo->inTransaction() && memberRow(1)['user_points']===99,'A real false PDO return cannot be treated as successful partial rollback');
 check($result['info']['caller_rollback_required'] && callerBuy()['code']===2005,'Silent-driver cleanup failure still fences purchases and requires caller abort');
}finally{$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);callerEnd($pdo);}

[$committed,$before,$pdo]=callerBegin();
try{
 $scope=new PurchaseTransaction(1,1,true);$scope->begin();Db::name('User')->where('user_id',1)->setDec('user_points',1);$pdo->commit();
 $result=$scope->rollback(['code'=>2003,'msg'=>'ordinary failure']);
 check($result['code']===2005 && $result['info']['caller_rollback_required'] && memberRow(1)['user_points']===99,'Unexpected physical caller completion is reported as changed, never as rolled back');
 check(callerBuy()['code']===2005,'Changed physical caller fences the current request');
}finally{callerEnd($pdo);}
// Standalone ORM use has no HTTP Request; unknown results are scoped to its existing container.
ownerSeed();think\Container::getInstance()->delete('request');$before=ownerState();
PurchaseOwnerFault::reset(['pdo_commit_after'=>1]);$result=callerBuy();
check($result['code']===2004 && memberRow(1)['user_points']===80,'Plain ORM compatibility preserves an unknown committed result without an HTTP binding');
$calls=PurchaseOwnerFault::$calls;check(callerBuy()['code']===2005 && PurchaseOwnerFault::$calls===$calls,'Plain ORM container context also blocks automatic repeated payment');
ownerRequest();PurchaseOwnerFault::reset();
printf("Purchase caller acknowledgements: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
