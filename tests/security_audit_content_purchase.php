<?php
/** Purchase coordinator: real balances/ledgers/receipts, failures and separate-connection concurrency. */
require __DIR__.'/fixtures/security_audit_membership_db.php';
use think\facade\Db;
use app\common\util\ContentPurchase;
if ($mysql) { Db::execute("SET SESSION sql_mode=''"); }
if (!$mysql) { Db::execute('ALTER TABLE audit_user ADD COLUMN user_status INTEGER NOT NULL DEFAULT 1'); }
$ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
if (!preg_match('/CREATE TABLE `mac_ulog` \([\s\S]*?\) ENGINE[^;]*;/',$ddl,$match)) { throw new RuntimeException('Missing Ulog installation schema'); }
Db::execute('DROP TABLE IF EXISTS audit_ulog');
if ($mysql) { Db::execute(str_replace('`mac_ulog`','`audit_ulog`',$match[0])); }
else { Db::execute('CREATE TABLE audit_ulog (ulog_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    ulog_mid INTEGER, ulog_type INTEGER, ulog_rid INTEGER, ulog_sid INTEGER CHECK(ulog_sid BETWEEN 0 AND 255),
    ulog_nid INTEGER CHECK(ulog_nid BETWEEN 0 AND 65535), ulog_points INTEGER CHECK(ulog_points BETWEEN 0 AND 65535), ulog_time INTEGER)'); }
function purchaseSeed(int $balance=100): void {
    membershipSeed($balance); Db::execute('DELETE FROM audit_ulog');
    Db::name('User')->where('user_id','>',0)->update(['user_status'=>1]);
    $GLOBALS['user']=['user_id'=>999,'user_points'=>999999];
}
function purchaseRecord(array $overrides=[]): array {
    return $overrides+['user_id'=>999,'ulog_mid'=>1,'ulog_type'=>4,'ulog_rid'=>7,'ulog_sid'=>1,'ulog_nid'=>2,'ulog_points'=>20];
}
function purchaseState(): array { return [membershipState(),Db::name('Ulog')->order('ulog_id')->select()->toArray()]; }
function purchaseReject(string $message,array $record=[],int $userId=1): void {
    $before=purchaseState();$result=ContentPurchase::buy($userId,purchaseRecord($record));
    check($result['code']>1 && purchaseState()===$before,$message);
}
purchaseSeed();
check(ContentPurchase::buy(1,purchaseRecord())['code']===1,'A valid purchase must commit under its explicit verified owner');
check(memberRow(1)['user_points']===80 && [memberRow(2)['user_points'],memberRow(3)['user_points'],memberRow(4)['user_points']] === [2,1,1],
    'One purchase debits the buyer and rewards its actual ancestors, independent of GLOBALS or submitted user_id');
check(Db::name('Plog')->count()===4 && Db::name('Ulog')->count()===1 && (int)Db::name('Ulog')->value('user_id')===1,
    'One successful purchase must have one actual-owner receipt plus buyer/referral ledgers');
$stored=purchaseState();
for ($i=0;$i<4;$i++) {
    check(ContentPurchase::buy(1,purchaseRecord())['code']===1 && purchaseState()===$stored,'Repeated entitlement must not debit or reward again');
}
purchaseSeed(10);$before=purchaseState();$result=ContentPurchase::buy(1,purchaseRecord());
check($result['code']===2002 && $result['info']===['need_points'=>20,'current_points'=>10] && purchaseState()===$before,
    'Insufficient funds must use the locked current balance, not optimistic request data');
purchaseSeed(0);
check(ContentPurchase::buy(1,purchaseRecord(['ulog_points'=>0]))['code']===1 && Db::name('Ulog')->count()===1
    && Db::name('Plog')->count()===0 && memberRow(1)['user_points']===0,'Free purchase creates its receipt without debit or referral payouts');
foreach ([['ulog_mid'=>2,'ulog_type'=>1],['ulog_mid'=>12,'ulog_type'=>1],['ulog_type'=>5],['ulog_sid'=>0,'ulog_nid'=>0]] as $record) {
    purchaseSeed();check(ContentPurchase::buy(1,purchaseRecord($record))['code']===1,'Supported reading/download/whole-content entitlement coordinates remain supported');
}
purchaseSeed();
foreach ([0,999] as $id) { purchaseReject('Missing buyer cannot create financial state',[],$id); }
Db::name('User')->where('user_id',1)->update(['user_status'=>0]);purchaseReject('Disabled buyer cannot purchase');
foreach (['ulog_mid','ulog_type','ulog_rid','ulog_sid','ulog_nid','ulog_points'] as $field) {
    foreach ([null,[],-1,1.0,'1e1','4294967296'] as $bad) { purchaseReject('Malformed priced record must not be coerced',[$field=>$bad]); }
}
foreach ([['ulog_mid'=>1,'ulog_type'=>1],['ulog_mid'=>2,'ulog_type'=>4],['ulog_mid'=>3],['ulog_sid'=>256],['ulog_nid'=>65536],['ulog_points'=>65536]] as $bad) {
    purchaseReject('Unsupported type/coordinates/capacity must be rejected',$bad);
}
foreach ([['mid'=>1,'type'=>4,'id'=>7],['mid'=>'12','type'=>'1','id'=>'7','sid'=>'1','nid'=>'2']] as $parameters) {
    check(ContentPurchase::parameters($parameters)!==null,'Legacy numeric string parameters remain usable');
}
foreach ([[],['mid'=>1,'type'=>1,'id'=>7],['mid'=>[1],'type'=>4,'id'=>7],['mid'=>1,'type'=>4,'id'=>'7x']] as $parameters) {
    check(ContentPurchase::parameters($parameters)===null,'Malformed or crossed resource/model input cannot select a different price table');
}
foreach ([8,4,5,6] as $type) {
    purchaseSeed();$GLOBALS['member_fail_log_types']=[$type];
    purchaseReject('A returned ledger validation failure at type '.$type.' must roll back the complete charge');
    purchaseSeed();$GLOBALS['member_throw_log_types']=[$type];
    purchaseReject('A Throwable from ledger type '.$type.' must roll back all state');
}
foreach ([['user','UPDATE'],['ulog','INSERT']] as [$table,$event]) {
    purchaseSeed();
    $body=$mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated purchase failure'":"BEGIN SELECT RAISE(ABORT, 'Isolated purchase failure'); END";
    Db::execute('CREATE TRIGGER audit_purchase_failure BEFORE '.$event.' ON audit_'.$table.' '.$body);
    try { purchaseReject('A '.$table.' storage error must roll back every financial effect'); }
    finally { Db::execute('DROP TRIGGER audit_purchase_failure'); }
    check(ContentPurchase::buy(1,purchaseRecord())['code']===1,'Purchase can be retried after its storage fault is removed');
}
purchaseSeed();$before=purchaseState();
Db::startTrans();check(ContentPurchase::buy(1,purchaseRecord())['code']===1,'Purchase supports a caller-owned transaction');
Db::rollback();check(purchaseState()===$before,'Caller rollback retains final authority over the full purchase');
if ($mysql) {
    foreach (['user','plog','ulog'] as $table) {
        purchaseSeed();Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
        try { purchaseReject('A nontransactional '.$table.' cannot permit partial financial writes'); }
        finally { Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB'); }
    }
    foreach (['plog','ulog'] as $table) {
        purchaseSeed(1000);$column=$table.'_points';Db::execute('ALTER TABLE audit_'.$table.' MODIFY '.$column.' TINYINT UNSIGNED NOT NULL DEFAULT 0');
        try { purchaseReject('Silent '.$table.' clipping must roll back debit, rewards and receipt',['ulog_points'=>300]); }
        finally { Db::execute('ALTER TABLE audit_'.$table.' MODIFY '.$column.' SMALLINT UNSIGNED NOT NULL DEFAULT 0'); }
    }
    $temp=audit_temp_dir('purchase-concurrency');
    try {
        foreach (['same','different','limited'] as $scenario) {
            purchaseSeed($scenario==='limited'?30:1000);$barrier=$temp.'/'.$scenario;
            $workers=[];
            for ($i=0;$i<4;$i++) {
                $record=purchaseRecord($scenario==='same'?[]:['ulog_rid'=>100+$i]);
                $args=['user_id'=>1,'record'=>$record,'barrier'=>$barrier];
                $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/security_audit_content_purchase_worker.php',json_encode($args,JSON_THROW_ON_ERROR)],
                    [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
                fclose($pipes[0]);$workers[]=[$process,$pipes];
            }
            file_put_contents($barrier,'ready');$results=[];
            foreach ($workers as [$process,$pipes]) {
                $body=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
                check(proc_close($process)===0 && $errors==='','Concurrent buyer produced PHP diagnostics: '.$errors);
                $results[]=json_decode($body,true,32,JSON_THROW_ON_ERROR);
            }
            $expected=$scenario==='different'?4:1;
            check(memberRow(1)['user_points']===($scenario==='limited'?30:1000)-20*$expected
                && Db::name('Ulog')->count()===$expected && Db::name('Plog')->count()===4*$expected,
                'Concurrent '.$scenario.' purchases must persist exactly the affordable distinct entitlements');
            check(memberRow(2)['user_points']===2*$expected && memberRow(3)['user_points']===$expected && memberRow(4)['user_points']===$expected,
                'Concurrent referral income must correspond exactly to committed distinct purchases');
            $codes=array_column($results,'code');sort($codes);
            check($codes===($scenario==='limited'?[1,2002,2002,2002]:[1,1,1,1]),'Concurrent responses must agree with the actual committed purchase state');
        }
    } finally { audit_remove_temp($temp); }
}

// Exercise both real controller methods against actual MySQL authentication and the coordinator.
// Only content metadata retrieval is replaced here; resource authorization is a subsequent suite.
function request() { return \think\Container::getInstance()->make('request'); }
function json($data) { return $data; }
class PurchaseContentFixture {
    public function infoData($where,...$args) {
        return ['code'=>1,'info'=>['vod_points'=>40,'vod_points_play'=>20,'vod_points_down'=>30,
            'art_points'=>40,'art_points_detail'=>20,'manga_points'=>40,'manga_points_detail'=>20]];
    }
}
if ($mysql) {
    foreach (['Vod','Art','Manga'] as $model) { class_alias(PurchaseContentFixture::class,'app\\common\\model\\'.$model); }
    $GLOBALS['config']['app'] += ['api_jwt_enabled'=>'1','api_jwt_secret'=>str_repeat('isolated-jwt-',4)];
    $GLOBALS['config']['user'] += ['vod_points_type'=>'0','art_points_type'=>'0','manga_points_type'=>'0'];
    foreach (['index','api'] as $entry) {
        purchaseSeed();
        Db::name('User')->where('user_id',1)->update(['user_random'=>str_repeat('a',32)]);
        $token=\app\common\util\JwtService::encode(1,str_repeat('a',32));
        $request=(new \think\Request())->withServer(['REQUEST_METHOD'=>'POST'])->withHeader(['Authorization'=>'Bearer '.$token])
            ->withPost(['mid'=>'1','type'=>'4','id'=>'7','sid'=>'1','nid'=>'2','ulog_points'=>'0','user_id'=>'999']);
        \think\Container::getInstance()->instance('request',$request);
        $GLOBALS['user']=Db::name('User')->where('user_id',1)->find();
        if ($entry==='index') {
            $controller=(new ReflectionClass(\app\index\controller\User::class))->newInstanceWithoutConstructor();
            $result=$controller->ajax_buy_popedom();
        } else {
            $controller=(new ReflectionClass(\app\api\controller\Payment::class))->newInstanceWithoutConstructor();
            $result=$controller->buy_popedom($request);
        }
        check($result['code']===1 && memberRow(1)['user_points']===80 && (int)Db::name('Ulog')->value('user_id')===1,
            'Actual '.$entry.' controller must use its verified owner and server price');
        $before=purchaseState();
        $result=$entry==='index'?$controller->ajax_buy_popedom():$controller->buy_popedom($request);
        check($result['code']===1 && purchaseState()===$before,'Actual '.$entry.' controller must route repeat purchases through locked receipt deduplication');
        $request=(new \think\Request())->withServer(['REQUEST_METHOD'=>'POST'])->withHeader(['Authorization'=>'Bearer '.$token])
            ->withPost(['mid'=>[1],'type'=>'4','id'=>'7']);
        \think\Container::getInstance()->instance('request',$request);
        $result=$entry==='index'?$controller->ajax_buy_popedom():$controller->buy_popedom($request);
        check($result['code']>1 && purchaseState()===$before,'Actual '.$entry.' controller cannot coerce malformed model input');
    }
}
printf("Content purchase transactions: %d checks passed on PHP %s (%s).\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
