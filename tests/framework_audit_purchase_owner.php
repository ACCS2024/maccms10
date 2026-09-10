<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/purchase_owner_faults.php';
$ownerMysql = getenv('MEMBERSHIP_AUDIT_MYSQL') === '1';
$ownerTemporary = sys_get_temp_dir().'/maccms-purchase-owner-'.bin2hex(random_bytes(12));
if (!mkdir($ownerTemporary,0700)) { throw new RuntimeException('Cannot create owner fixture directory'); }
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS', $ownerMysql ? PurchaseOwnerMysql::class : PurchaseOwnerSqlite::class);
define('MEMBERSHIP_AUDIT_DATABASE', $ownerMysql ? 'maccms_audit_owner_purchase' : $ownerTemporary.'/owner.sqlite');
if ($ownerMysql) {
    $server = new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1').';charset=utf8mb4',
        'root', getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_owner_purchase CHARACTER SET utf8mb4');
    $server = null;
}
require __DIR__.'/fixtures/security_audit_membership_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($ownerTemporary));
use think\facade\Db;
use app\common\util\ContentPurchase;
use app\common\util\PurchaseTransaction;
if ($mysql) {
    Db::execute("SET SESSION sql_mode=''");
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach (['ulog','vod'] as $table) {
        if (!preg_match('/CREATE TABLE `mac_'.$table.'` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
            throw new RuntimeException('Owner fixture installation schema missing');
        }
        Db::execute('DROP TABLE IF EXISTS audit_'.$table);
        Db::execute(str_replace('`mac_'.$table.'`','`audit_'.$table.'`',$match[0]));
    }
} else {
    Db::execute('ALTER TABLE audit_user ADD COLUMN user_status INTEGER NOT NULL DEFAULT 1');
    Db::execute('CREATE TABLE audit_ulog (ulog_id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,ulog_mid INTEGER,ulog_type INTEGER,ulog_rid INTEGER,ulog_sid INTEGER,ulog_nid INTEGER,ulog_points INTEGER,ulog_time INTEGER)');
}
function ownerRequest():void{think\Container::getInstance()->instance('request',new think\Request());}
function ownerSeed(int $balance=100):void{
    ownerRequest();PurchaseOwnerFault::reset();membershipSeed($balance);Db::execute('DELETE FROM audit_ulog');
    Db::name('User')->where('user_id','>',0)->update(['user_status'=>1]);
}
function ownerState():array{return [membershipState(),Db::name('Ulog')->order('ulog_id')->select()->toArray()];}
function ownerQuote(array $user):array{return ['code'=>1,'record'=>['ulog_mid'=>1,'ulog_type'=>4,'ulog_rid'=>7,'ulog_sid'=>1,'ulog_nid'=>2,'ulog_points'=>20]];}
function ownerBuy():array{return ContentPurchase::buyVideo(1,'ownerQuote');}
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
foreach(['orm_nested_begin_before','orm_nested_begin_after','orm_nested_commit_before','orm_nested_commit_after','orm_nested_rollback_before','orm_nested_rollback_after']as $stage){
    ownerSeed();$before=ownerState();if(str_contains($stage,'rollback'))$GLOBALS['member_fail_log_types']=[5];PurchaseOwnerFault::reset([$stage=>1]);$result=ownerBuy();
    check($result['code']===($stage==='orm_nested_commit_after'?2005:2003)&&ownerState()===$before,'Nested referral errors unwind all owner state, and externally ended transactions are uncertain: '.$stage);
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
