<?php
/** Actual SQLite COMMIT before/after faults. No fake persistence or provider transport. */
declare(strict_types=1);
putenv('STORAGE_AUDIT_MYSQL=0');
require __DIR__.'/security_audit_storage_providers.php';
require __DIR__.'/security_audit_storage_intent_db.php';
use think\facade\Db;
use app\common\util\StorageIntent;
use app\common\util\StoragePublicUrl;
use app\common\util\StorageTransfer;
$case=$argv[1]??'';
if (!in_array($case,['before-create','after-create','before-claim','after-claim','before-result','after-result'],true))throw new RuntimeException('Unknown commit case');
class StorageCommitSqlite extends think\db\connector\Sqlite {
    public function __construct(array $settings=[]) {$settings['type']='sqlite';parent::__construct($settings);}
    public function commit():void {
        $step=++$GLOBALS['storage_commit_count'];
        if ($step===$GLOBALS['storage_commit_target']) {
            if(str_starts_with($GLOBALS['storage_commit_case'],'after-'))parent::commit();
            throw new RuntimeException('Controlled COMMIT acknowledgement failure');
        }
        parent::commit();
    }
}
$shared=ROOT_PATH.'commits.sqlite';Db::execute('VACUUM INTO ?',[$shared]);
$database['connections']['storage']['database']=$shared;$database['connections']['storage']['type']='\\StorageCommitSqlite';
$manager=new think\DbManager();$manager->setConfig($database);think\Container::getInstance()->instance('think\\DbManager',$manager);
$GLOBALS['storage_commit_count']=0;$GLOBALS['storage_commit_target']=str_ends_with($case,'create')?1:(str_ends_with($case,'claim')?2:3);$GLOBALS['storage_commit_case']=$case;
$path=storageFile();$result=null;$thrown=false;
try {$row=StorageIntent::prepare($path,StoragePublicUrl::current('upyun'));$result=StorageTransfer::attempt($row['intent_id']);}
catch(Throwable $error){$thrown=true;}
$rows=Db::name('StorageIntent')->select()->toArray();
$expected=match($case){'before-create'=>null,'after-create','before-claim'=>'prepared','after-claim','before-result'=>'attempting','after-result'=>'remote_confirmed'};
check(count($rows)===($expected===null?0:1) && ($expected===null||$rows[0]['transfer_state']===$expected),'COMMIT fault did not exercise expected persisted state');
check($GLOBALS['storage_provider_calls']===(str_ends_with($case,'result')?1:0),'Provider called before an acknowledged independent claim');
check(is_file($path) && ($expected===null||$rows[0]['reference_state']==='pending'),'Unknown COMMIT discarded local source or committed an unverified reference');
check(str_ends_with($case,'result')?(!$thrown&&$result['outcome']==='unrecorded'&&$result['file']===$path):$thrown,'Unknown COMMIT was acknowledged as normal success');
echo json_encode(['case'=>$case,'checks'=>$checks,'state'=>$expected,'provider_calls'=>$GLOBALS['storage_provider_calls']],JSON_THROW_ON_ERROR);
