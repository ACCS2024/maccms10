<?php
/** Durable request replay, actual financial storage and simultaneous MySQL workers. */
declare(strict_types=1);
define('CASH_WRITE_AUDIT', true);
$worker=($argv[1]??'')==='worker';
if($worker)define('PURCHASE_CSRF_EXISTING_DB',true);
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
use app\common\model\Cash;
function receiptConfig():void {
    $GLOBALS['config']['user']=array_replace($GLOBALS['config']['user'],['cash_status'=>1,'cash_ratio'=>100,'cash_min'=>'0.01']);
}
function receiptBody(array $changes=[]):array {
    return $changes+['request_id'=>str_repeat('a',64),'cash_money'=>'0.29','cash_bank_name'=>'Ordinary bank','cash_bank_no'=>'123456','cash_payee_name'=>'Ordinary name'];
}
function receiptSeed():void { purchaseCsrfSeed();receiptConfig(); }
function receiptState():array {
    return purchaseCsrfState()+['cash'=>Db::name('Cash')->order('cash_id')->select()->toArray(),
        'receipts'=>Db::name('CashRequest')->order('user_id,request_id')->select()->toArray()];
}
receiptConfig();
if($worker) {
    if(!$mysql)throw new RuntimeException('Cash concurrency worker requires dedicated MySQL');
    fwrite(STDOUT,"READY\n");
    if(trim((string)fgets(STDIN))!=='GO')exit(2);
    fwrite(STDOUT,"START\n");
    echo json_encode((new Cash())->saveRequestForUser(1,receiptBody()),JSON_THROW_ON_ERROR)."\n";
    exit;
}
receiptSeed();$cash=new Cash();
foreach([null,[],true,'','A'.str_repeat('a',63),str_repeat('a',63),str_repeat('a',65)] as $key) {
    $before=receiptState();check($cash->saveRequestForUser(1,receiptBody(['request_id'=>$key]))['code']!==1&&receiptState()===$before,'Malformed request IDs must leave funds and receipts unchanged');
}
$first=$cash->saveRequestForUser(1,receiptBody());$state=receiptState();
check($first['code']===1&&$state['cash'][0]['cash_id']===$first['info']['cash_id']&&count($state['receipts'])===1,'New withdrawal must publish one atomic receipt and cash row');
for($i=0;$i<5;$i++)check($cash->saveRequestForUser(1,receiptBody())===$first&&receiptState()===$state,'Identical request must return the original acknowledgement without reserving twice');
check($cash->saveRequestForUser(1,receiptBody(['cash_money'=>0.29,'cash_bank_no'=>' 123456 ']))===$first&&receiptState()===$state,'Canonical equivalent transport representations must share the same request');
$GLOBALS['config']['user']['cash_status']=0;$GLOBALS['config']['user']['cash_ratio']=[];$GLOBALS['config']['user']['cash_min']='999';
check($cash->saveRequestForUser(1,receiptBody())===$first&&receiptState()===$state,'A replay must retain its original result when current withdrawal configuration changes');
receiptConfig();
foreach(['cash_money'=>'0.30','cash_bank_name'=>'Changed bank','cash_bank_no'=>'987','cash_payee_name'=>'Changed name'] as $field=>$value) {
    $result=$cash->saveRequestForUser(1,receiptBody([$field=>$value]));
    check($result['code']===1009&&$result['info']['retryable']===false&&receiptState()===$state,'A request ID cannot be reused for different money or payee information');
}
$cash->delData(['user_id'=>1]);$state=receiptState();
check($state['cash']===[]&&count($state['receipts'])===1,'Cancellation must retain the durable request receipt');
check($cash->saveRequestForUser(1,receiptBody())===$first&&receiptState()===$state,'Deleting the visible record must not make its request ID reusable');
receiptSeed();$first=$cash->saveRequestForUser(1,receiptBody());$cash->auditData(['user_id'=>1]);$state=receiptState();
check($cash->saveRequestForUser(1,receiptBody())===$first&&receiptState()===$state,'Settled withdrawal replay must not reserve funds again');
Db::name('User')->where('user_id',2)->update(['user_points'=>100]);
$second=$cash->saveRequestForUser(2,receiptBody());
check($second['code']===1&&$second['info']['cash_id']!==$first['info']['cash_id']&&Db::name('CashRequest')->count()===2,'A request key is scoped to its verified account');
foreach(['reject','alter','balance','cash'] as $fault) {
    receiptSeed();$before=receiptState();
    $body=match($fault){
        'reject'=>$mysql?"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='receipt unavailable'":"SELECT RAISE(ABORT,'receipt unavailable');",
        'alter'=>$mysql?'SET NEW.cash_id=0':'UPDATE audit_cash_request SET cash_id=0 WHERE user_id=NEW.user_id AND request_id=NEW.request_id;',
        'balance'=>'UPDATE audit_user SET user_points=user_points+1 WHERE user_id=NEW.user_id'.($mysql?'':';'),
        'cash'=>'UPDATE audit_cash SET cash_points=cash_points+1 WHERE cash_id=NEW.cash_id'.($mysql?'':';'),
    };
    Db::execute('CREATE TRIGGER receipt_failure '.($mysql?'BEFORE':'AFTER').' INSERT ON audit_cash_request '.($mysql?'FOR EACH ROW '.$body:'BEGIN '.$body.' END'));
    try{check($cash->saveRequestForUser(1,receiptBody())['code']!==1&&receiptState()===$before,'Receipt failure or altered storage must roll back the entire reservation: '.$fault);}
    finally{Db::execute('DROP TRIGGER receipt_failure');}
}
receiptSeed();$before=receiptState();Db::startTrans();Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);
check($cash->saveRequestForUser(1,receiptBody())['code']!==1&&Db::name('User')->where('user_id',1)->value('user_name')==='caller-sentinel','Receipt writes must not acknowledge or commit a caller-owned transaction');
Db::rollback();check(receiptState()===$before,'Caller must retain control of its transaction');
if($mysql) {
    receiptSeed();$before=receiptState();Db::execute('ALTER TABLE audit_cash_request ENGINE=MyISAM');
    try{check($cash->saveRequestForUser(1,receiptBody())['code']!==1&&receiptState()===$before,'A nontransactional receipt table must prevent all cash effects');}
    finally{Db::execute('ALTER TABLE audit_cash_request ENGINE=InnoDB');}
    receiptSeed();$workers=[];$owner=Db::connect()->getPdo();
    $line=static function($stream):string {
        $read=[$stream];$write=$except=[];
        if(stream_select($read,$write,$except,15)!==1)throw new RuntimeException('Cash worker timed out');
        $value=fgets($stream);if($value===false)throw new RuntimeException('Cash worker ended unexpectedly');return trim($value);
    };
    try {
        $owner->beginTransaction();$owner->query('SELECT user_id FROM audit_user WHERE user_id=1 FOR UPDATE')->fetchAll();
        for($i=0;$i<2;$i++) {
            $process=proc_open([PHP_BINARY,__FILE__,'worker'],[0=>['pipe','r'],1=>['pipe','w'],2=>['redirect',1]],$pipes);
            if(!is_resource($process))throw new RuntimeException('Cash worker cannot start');
            $workers[]=[$process,$pipes];check($line($pipes[1])==='READY','Independent cash worker must initialize its real connection');
        }
        foreach($workers as [$process,$pipes]){fwrite($pipes[0],"GO\n");check($line($pipes[1])==='START','Both requests must start while the account row is locked');}
        $owner->commit();$responses=[];
        foreach($workers as [$process,$pipes])$responses[]=json_decode($line($pipes[1]),true,512,JSON_THROW_ON_ERROR);
        check($responses[0]['code']===1&&$responses[0]===$responses[1],'Simultaneous workers must acknowledge the same committed withdrawal');
        check(Db::name('Cash')->count()===1&&Db::name('CashRequest')->count()===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===71,'Concurrent retries must reserve exactly 29 points once');
    } finally {
        if($owner->inTransaction())$owner->rollBack();
        foreach($workers as [$process,$pipes]){foreach($pipes as $pipe)fclose($pipe);$status=proc_get_status($process);if($status['running'])proc_terminate($process,9);proc_close($process);}
    }
}
echo 'Cash request receipts: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
