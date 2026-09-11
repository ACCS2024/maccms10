<?php
/** Private file evidence survives uncertainty in any independently committed transfer transition. */
declare(strict_types=1);
$phase=$argv[1]??'';$fault=$argv[2]??'';
$entrance=$argv[3]??'admin';
if (!in_array($entrance,['admin','index'],true)) { throw new RuntimeException('Unknown fixture entrance'); }
putenv('UPLOAD_AUDIT_ENTRANCE='.$entrance);
if(!in_array($phase,['prepare','claim','finish'],true)||!in_array($fault,['orm_commit_before','pdo_commit_before','pdo_commit_after','orm_commit_after','rollback_unrecoverable'],true))throw new RuntimeException('Unknown storage attachment worker');
require dirname(__DIR__,2).'/vendor/autoload.php';require __DIR__.'/purchase_owner_faults.php';
class StorageAttachmentSqlite extends PurchaseOwnerSqlite {
    public function __construct(array $config=[]) {$config['type']='sqlite';parent::__construct($config);}
}
$databaseDirectory=sys_get_temp_dir().'/storage-attachment-db-'.bin2hex(random_bytes(12));
if(!mkdir($databaseDirectory,0700))throw new RuntimeException('Cannot create fixture database');
define('UPLOAD_AUDIT_SQLITE_DRIVER','\\StorageAttachmentSqlite');define('UPLOAD_AUDIT_SQLITE_DATABASE',$databaseDirectory.'/fixture.sqlite');
putenv('REMOTE_UPLOAD_AUDIT_MYSQL=0');require __DIR__.'/security_audit_remote_upload_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($databaseDirectory));
use app\common\util\LocalAttachment;
use app\common\util\StorageOutcomeUnknown;
use think\facade\Db;
if ($entrance==='admin') { uploadIdentityAdmin(); } else { uploadIdentityMember(); }
uploadIdentityRequest(['flag'=>$entrance==='admin'?'vod':'user','thumb'=>'1']);
$assetConfig=['mode'=>'s3','watermark'=>0,'thumb'=>1,'thumb_size'=>'10x10,20x20','thumb_type'=>1];$bytes=file_get_contents('source.png');
remoteUploadConfig($assetConfig);
$operation=static fn()=>LocalAttachment::storeDownloadedImage($bytes,$assetConfig,'vod');
$pdo=Db::connect()->getPdo();$stages=glob(sys_get_temp_dir().'/maccms-attachment-*');
$oldPortrait=Db::name('User')->where('user_id',1)->value('user_portrait');
if($fault==='rollback_unrecoverable') {
    $state=['prepare'=>'prepared','claim'=>'attempting','finish'=>'remote_confirmed'][$phase];
    Db::execute('CREATE TRIGGER storage_worker_reject BEFORE '.($phase==='prepare'?'INSERT':'UPDATE')." ON upload_audit_storage_intent WHEN NEW.transfer_state='".$state."' BEGIN SELECT RAISE(ABORT,'ordinary rejected transition'); END");
}
PurchaseOwnerFault::reset($fault==='rollback_unrecoverable'?['pdo_rollback_before'=>'always']:[$fault=>['prepare'=>1,'claim'=>4,'finish'=>5][$phase]]);
try {
    $error=null;try{$operation();}catch(Throwable $caught){$error=$caught;}
    check($error instanceof StorageOutcomeUnknown,'Storage uncertainty was swallowed as a successful local fallback');
    $new=array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages));check(count($new)===1,'Uncertain storage lost its own stage');
    $manifest=json_decode(file_get_contents($new[0].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
    check($manifest['state']==='storage_outcome_unknown'&&$manifest['storage_transaction']['phase']===$phase&&$manifest['storage_transaction']['retryable']===false,'Stage lost storage uncertainty and phase');
    foreach($manifest['files'] as $row)check(is_file($row['annex_file'])&&filesize($row['annex_file'])===$row['annex_size'],'Uncertain storage deleted an input or derivative');
    $observer=new PDO('sqlite:'.UPLOAD_AUDIT_SQLITE_DATABASE);
    check((int)$observer->query('SELECT COUNT(*) FROM upload_audit_annex')->fetchColumn()===0,'Unknown transfer committed business references');
    check($observer->query('SELECT user_portrait FROM upload_audit_user WHERE user_id=1')->fetchColumn()===$oldPortrait&&is_file('upload/user/1/1.jpg'),'Unknown transfer changed an existing avatar');
    check($GLOBALS['storage_provider_calls']===($phase==='finish'?1:0),'Provider was invoked before its claim was durably acknowledged or after uncertainty');
    $rows=$observer->query('SELECT * FROM upload_audit_storage_intent ORDER BY local_path')->fetchAll(PDO::FETCH_ASSOC);
    $after=str_ends_with($fault,'commit_after');
    check(count($rows)===($phase==='prepare'?($after?1:0):3),'Independent observer saw an unexpected number of prepared records');
    foreach($rows as $row)check($row['reference_state']==='pending','Unknown transfer had committed references');
    $target=array_values(array_filter($rows,static fn($row)=>$row['intent_id']===$manifest['storage_transaction']['intent_id']));
    if($target)check($target[0]['transfer_state']===($phase==='prepare'?'prepared':($phase==='claim'?($after?'attempting':'prepared'):($after?'remote_confirmed':'attempting'))),'Independent observer saw the wrong transition state');
    $calls=PurchaseOwnerFault::$calls;$external=$GLOBALS['storage_provider_calls'];
    try{$operation();throw new RuntimeException('Second attachment unexpectedly succeeded');}catch(StorageOutcomeUnknown $blocked){check($blocked->details['outcome']==='request_blocked','Storage uncertainty did not fence its request');}
    check(PurchaseOwnerFault::$calls===$calls&&$GLOBALS['storage_provider_calls']===$external,'Retry after storage uncertainty attempted a DB or provider operation');
    $reply=(new app\common\model\Upload())->upload([],$entrance==='admin');
    check($reply['code']===2005&&$reply['data']['retryable']===false&&$reply['data']['reference']===$error->details['reference'],
        'Upload response lost non-retryable storage uncertainty or diagnostic identity');
    check(array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages))===$new,'Blocked retry created another stage');
    echo json_encode(['phase'=>$phase,'fault'=>$fault,'checks'=>$checks,'result'=>'passed'],JSON_THROW_ON_ERROR)."\n";
} finally {PurchaseOwnerFault::reset();if($pdo->inTransaction())$pdo->rollBack();Db::connect()->close();}
