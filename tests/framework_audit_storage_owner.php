<?php
/** Every storage transition is exercised against actual original-PDO and ORM acknowledgement faults. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_storage_providers.php';
require __DIR__.'/fixtures/security_audit_storage_intent_db.php';
require __DIR__.'/fixtures/purchase_owner_faults.php';
use app\common\util\StorageIntent;
use app\common\util\StoragePublicUrl;
use app\common\util\StorageOutcomeUnknown;
use think\facade\Db;
class StorageOwnerSqlite extends PurchaseOwnerSqlite {
    public function __construct(array $config=[]) {$config['type']='sqlite';parent::__construct($config);}
}
class StorageOwnerMysql extends PurchaseOwnerMysql {
    public function __construct(array $config=[]) {$config['type']='mysql';parent::__construct($config);}
}
if (!$mysql) {
    $storageDatabase=ROOT_PATH.'owner.sqlite';
    Db::connect()->getPdo()->exec('VACUUM INTO '.Db::connect()->getPdo()->quote($storageDatabase));
    $database['connections']['storage']['database']=$storageDatabase;
}
Db::connect()->close();
$database['connections']['storage']['type']=$mysql?'\\StorageOwnerMysql':'\\StorageOwnerSqlite';
$manager=new think\DbManager();$manager->setConfig($database);
think\Container::getInstance()->instance('think\\DbManager',$manager);
$observer=$mysql?new PDO('mysql:host='.(getenv('STORAGE_AUDIT_HOST')?:'127.0.0.1').';dbname=maccms_audit_storage;charset=utf8mb4','root',getenv('STORAGE_AUDIT_PASSWORD')?:''):new PDO('sqlite:'.$storageDatabase);
$observer->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
function storageOwnerReset(): void {
    PurchaseOwnerFault::reset();
    think\Container::getInstance()->instance('request',(new think\Request())->withServer(['REQUEST_METHOD'=>'POST','REQUEST_TIME'=>time()]));
    Db::connect()->query('SELECT 1',[],true);
}
function storageOwnerState(PDO $pdo,string $path): array {
    $statement=$pdo->prepare('SELECT * FROM storage_audit_storage_intent WHERE local_path=?');$statement->execute([$path]);return $statement->fetchAll(PDO::FETCH_ASSOC);
}
$cases=['normal','orm_begin_before','pdo_begin_before','pdo_begin_after','orm_begin_after',
    'orm_rollback_before','pdo_rollback_before','pdo_rollback_after','orm_rollback_after',
    'orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after','rollback_unrecoverable','caller_raw','caller_orm'];
foreach(['prepare','claim','finish'] as $phase)foreach($cases as $case) {
    storageOwnerReset();$policy=StoragePublicUrl::current('s3');$path=storageFile('owner');$intent=null;
    if($phase!=='prepare')$intent=StorageIntent::prepare($path,$policy);
    if($phase==='finish')StorageIntent::claim($intent['intent_id'],$policy);
    $connection=Db::connect();$pdo=$connection->getPdo();$before=storageOwnerState($observer,$path);
    $operation=static function()use($phase,$path,$policy,$intent):array {
        return match($phase){'prepare'=>StorageIntent::prepare($path,$policy),'claim'=>StorageIntent::claim($intent['intent_id'],$policy),
            'finish'=>StorageIntent::finish($intent['intent_id'],$policy,$policy->expected($path),'remote_confirmed')};
    };
    $rollback=str_contains($case,'rollback');$caller=str_starts_with($case,'caller_');
    if($rollback) {
        $event=$phase==='prepare'?'INSERT':'UPDATE';
        Db::execute('CREATE TRIGGER owner_reject BEFORE '.$event.' ON storage_audit_storage_intent '.($mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='ordinary fixture rejection'":"BEGIN SELECT RAISE(ABORT,'ordinary fixture rejection'); END"));
    }
    if($caller){if($case==='caller_raw')$pdo->beginTransaction();else Db::startTrans();Db::name('User')->where('user_id',1)->update(['user_portrait'=>'caller-sentinel']);}
    PurchaseOwnerFault::reset($case==='rollback_unrecoverable'?['pdo_rollback_before'=>'always']:
        (str_starts_with($case,'orm_')||str_starts_with($case,'pdo_')?[$case=>1]:[]));
    $error=null;$result=null;try{$result=$operation();}catch(Throwable $caught){$error=$caught;}
    try {
        check($case==='normal'?is_array($result):$error instanceof Throwable,'Storage transition result did not match fault: '.$phase.'/'.$case);
        check($GLOBALS['storage_provider_calls']===0,'A DB transition invoked a provider');
        $unknown=str_contains($case,'commit')||$case==='rollback_unrecoverable';
        if($unknown) {
            check($error instanceof StorageOutcomeUnknown&&$error->details['retryable']===false&&$error->details['phase']===$phase,'Uncertain storage transition returned an ordinary retryable exception');
            check(!empty($error->details['reference'])&&preg_match('/^[a-f0-9]{32}$/D',$error->details['intent_id'])===1,'Storage uncertainty lost its diagnostic/intent identity');
            $calls=PurchaseOwnerFault::$calls;
            try{$operation();throw new RuntimeException('Storage retry succeeded');}catch(StorageOutcomeUnknown $blocked){check($blocked->details['outcome']==='request_blocked','Uncertain storage request was not blocked');}
            check(PurchaseOwnerFault::$calls===$calls,'Blocked storage request attempted another transaction');
            if($case==='rollback_unrecoverable') {
                check($pdo->inTransaction()&&(PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1&&(PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,'Unknown rollback discarded the original transaction or exceeded bounded cleanup');
            } else {check(!$pdo->inTransaction(),'Commit acknowledgement failure left an active original transaction');}
        } elseif($caller) {
            check($pdo->inTransaction()&&Db::name('User')->where('user_id',1)->value('user_portrait')==='caller-sentinel'&&PurchaseOwnerFault::$calls===[],'Storage altered or ended its caller transaction');
        } else {
            check(!$pdo->inTransaction(),'Known failure retained an active transaction');
            if($case!=='normal')check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1,'Known failure did not use exactly one ORM cleanup');
        }
        $actual=storageOwnerState($observer,$path);
        if($case==='normal'||str_ends_with($case,'commit_after')) {
            check(count($actual)===1&&$actual[0]['transfer_state']===match($phase){'prepare'=>'prepared','claim'=>'attempting','finish'=>'remote_confirmed'},'Observer did not see the expected committed transition');
        } else {check($actual===$before,'A failed/uncommitted transition changed independently visible storage');}
        check(is_file($path),'Storage metadata transition deleted its input');
    } finally {
        PurchaseOwnerFault::reset();if($pdo->inTransaction())$pdo->rollBack();$connection->close();
        if($rollback)Db::execute('DROP TRIGGER owner_reject');
    }
}
echo 'Storage owner transitions: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
