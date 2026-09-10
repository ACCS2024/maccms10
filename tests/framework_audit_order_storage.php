<?php
/** Actual locked payment authority and storage values, including ordinary competing edits and SQL truncation. */
declare(strict_types=1);
require __DIR__.'/fixtures/financial_before_begin.php';
$mysql=getenv('MEMBERSHIP_AUDIT_MYSQL')==='1';
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS',$mysql?FinancialBeforeBeginMysql::class:FinancialBeforeBeginSqlite::class);
define('MEMBERSHIP_AUDIT_DATABASE',$mysql?'maccms_audit_order_storage':':memory:');
if($mysql){
    $server=new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'');
    $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_order_storage CHARACTER SET utf8mb4');
}
require __DIR__.'/fixtures/security_audit_membership_db.php';
use think\facade\Db;
use app\common\model\Order;
if($mysql){Db::execute("SET SESSION sql_mode=''");}
function storageOrderSeed(bool $member=false,int $points=20):void {
    membershipSeed();membershipOrderSeed($points);
    unset($GLOBALS['financial_before_begin']);
    if(!$member){Db::name('Order')->where('order_id',1)->update(['order_remarks'=>'']);}
}
function storageOrderRun():array {return (new Order())->notify('member-once','weixin','10.00');}
foreach(['user_id'=>2,'order_points'=>40,'order_code'=>'different-order','order_remarks'=>'']as $field=>$value){
    storageOrderSeed(true);$hookCalls=0;
    $GLOBALS['financial_before_begin']=static function()use($field,$value,&$hookCalls):void {
        ++$hookCalls;Db::name('Order')->where('order_id',1)->update([$field=>$value]);$GLOBALS['storage_competing_state']=membershipState();
    };
    $result=storageOrderRun();check($hookCalls===1,'Actual competing edit ran before payment BEGIN: '.$field);
    if($field==='order_code'){
        check($result['code']!==1 && membershipState()===$GLOBALS['storage_competing_state'],'A renamed order cannot be paid through its old code');
    }else{
        check($result['code']===1,'Current locked order can settle after a valid competing edit: '.$field);
        $buyer=$field==='user_id'?2:1;
        check((int)Db::name('Plog')->where('plog_type',1)->value('user_id')===$buyer,'Receipt belongs to the current order beneficiary');
        check((int)Db::name('Plog')->where('plog_type',1)->value('plog_points')===($field==='order_points'?40:20),'Receipt uses current order points');
        check(memberRow(1)['user_points']===($field==='user_id'?100:120),'Buyer balance reflects the current charge and intent');
        check((int)memberRow(1)['group_id']===($field==='order_points'?3:2),'Old membership intent cannot upgrade the wrong user');
        if($field==='user_id'){check((int)memberRow(2)['group_id']===3 && memberRow(2)['user_points']===0,'Membership belongs to the current beneficiary');}
        if($field==='order_remarks'){check(Db::name('Plog')->count()===1,'Removed membership intent produces only the current recharge');}
    }
    check(!Db::connect()->getPdo()->inTransaction(),'Competing payment always ends its physical transaction');
}
foreach(['delete','missing-user','invalid-status']as $case){
    storageOrderSeed();$GLOBALS['financial_before_begin']=static function()use($case):void {
        if($case==='delete'){Db::name('Order')->where('order_id',1)->delete();}
        else{Db::name('Order')->where('order_id',1)->update($case==='missing-user'?['user_id'=>999]:['order_status'=>2]);}
        $GLOBALS['storage_competing_state']=membershipState();
    };
    check(storageOrderRun()['code']!==1 && membershipState()===$GLOBALS['storage_competing_state'],'Missing or ineligible current order cannot be settled: '.$case);
}
// Values returned by a successful INSERT/UPDATE must equal the actual stored financial fields.
foreach([
    ['user','UPDATE','user_points','NEW.user_points+1'],
    ['plog','INSERT','user_id','99'],['plog','INSERT','plog_type','2'],
    ['plog','INSERT','plog_points','1'],['plog','INSERT','plog_remarks',"'ordinary changed remark'"],
    ['order','UPDATE','order_status','0'],['order','UPDATE','order_pay_type',"'changed'"],
    ['order','UPDATE','order_pay_time','0'],['order','UPDATE','user_id','2'],
    ['order','UPDATE','order_points','1'],['order','UPDATE','order_price','11'],
    ['order','UPDATE','order_code',"'changed-code'"],['order','UPDATE','order_remarks',"'changed'"],
]as [$table,$event,$field,$value]){
    storageOrderSeed();$before=membershipState();$id=$table.'_id';
    $body=$mysql?'FOR EACH ROW SET NEW.'.$field.'='.$value
        :'BEGIN UPDATE audit_'.$table.' SET '.$field.'='.$value.' WHERE '.$id.'=NEW.'.$id.'; END';
    Db::execute('CREATE TRIGGER audit_payment_storage '.($mysql?'BEFORE':'AFTER').' '.$event.' ON audit_'.$table.' '.$body);
    try{
        check(storageOrderRun()['code']!==1 && membershipState()===$before,'Altered stored payment field rolls back the whole operation: '.$table.'.'.$field);
        check(!Db::connect()->getPdo()->inTransaction(),'Stored-value rejection ends the original transaction');
    }finally{Db::execute('DROP TRIGGER audit_payment_storage');}
}
foreach([null,[],['ordinary'],new stdClass(),true,123,''," \t",str_repeat('x',31),"ordinary\ncode","\xff"]as $code){
    storageOrderSeed();$before=membershipState();$hookCalls=0;$GLOBALS['financial_before_begin']=static function()use(&$hookCalls):void{++$hookCalls;};
    check((new Order())->notify($code,'weixin','10.00')['code']===1001 && membershipState()===$before && $hookCalls===0,'Malformed or oversized order code is rejected without beginning a transaction');
}
foreach([null,[],new stdClass(),true,123,'',str_repeat('x',11),"ordinary\n","\xff"]as $channel){
    storageOrderSeed();$before=membershipState();$hookCalls=0;$GLOBALS['financial_before_begin']=static function()use(&$hookCalls):void{++$hookCalls;};
    check((new Order())->notify('member-once',$channel,'10.00')['code']===1001 && membershipState()===$before && $hookCalls===0,'Malformed or oversized payment channel is rejected before BEGIN');
}
foreach([str_repeat('x',30),str_repeat('单',30)]as $code){
    storageOrderSeed();Db::name('Order')->where('order_id',1)->update(['order_code'=>$code]);
    check((new Order())->notify($code,str_repeat('渠',10),'10.00')['code']===1,'Column-capacity UTF-8 callback fields remain supported');
}
// Old schemas may lack the unique order index. Reject ambiguity without performing a web-request migration.
storageOrderSeed();
if($mysql){Db::execute('ALTER TABLE audit_order DROP INDEX order_code');}
Db::name('Order')->insert(['order_id'=>2,'order_code'=>'member-once','user_id'=>2,'order_points'=>20,'order_price'=>'10.00']);$before=membershipState();
try{check(storageOrderRun()['code']!==1 && membershipState()===$before,'Ambiguous legacy order code credits neither beneficiary');}
finally{Db::name('Order')->where('order_id',2)->delete();if($mysql){Db::execute('ALTER TABLE audit_order ADD UNIQUE INDEX order_code(order_code)');}}
if($mysql){
    storageOrderSeed(false,300);Db::execute('ALTER TABLE audit_plog MODIFY plog_points TINYINT UNSIGNED NOT NULL DEFAULT 0');$before=membershipState();
    try{check(storageOrderRun()['code']!==1 && membershipState()===$before,'Non-strict legacy ledger clipping cannot report successful payment');}
    finally{Db::execute('ALTER TABLE audit_plog MODIFY plog_points INT UNSIGNED NOT NULL DEFAULT 0');}
    storageOrderSeed();Db::execute('ALTER TABLE audit_order MODIFY order_pay_type VARCHAR(3) NOT NULL DEFAULT \'\'');$before=membershipState();
    try{check(storageOrderRun()['code']!==1 && membershipState()===$before,'Non-strict payment channel clipping rolls back rather than losing provenance');}
    finally{Db::execute('ALTER TABLE audit_order MODIFY order_pay_type VARCHAR(10) NOT NULL DEFAULT \'\'');}
}
printf("Order authority and storage: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
