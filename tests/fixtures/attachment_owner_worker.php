<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/purchase_owner_faults.php';
class AttachmentOwnerSqlite extends PurchaseOwnerSqlite
{
    public function __construct(array $config=[])
    {
        $config['type']='sqlite';parent::__construct($config);
    }
}
$case=$argv[1]??'';
if (!preg_match('/^(normal|caller_raw|caller_orm|rollback_unrecoverable|(?:orm|pdo)_(?:begin|rollback|commit)_(?:before|after))$/D',$case)) {
    throw new RuntimeException('Unknown attachment owner case');
}
$databaseDirectory=sys_get_temp_dir().'/attachment-owner-db-'.bin2hex(random_bytes(12));
if (!mkdir($databaseDirectory,0700)) { throw new RuntimeException('Cannot create attachment owner database'); }
define('UPLOAD_AUDIT_SQLITE_DRIVER','\\'.AttachmentOwnerSqlite::class);
define('UPLOAD_AUDIT_SQLITE_DATABASE',$databaseDirectory.'/fixture.sqlite');
putenv('REMOTE_UPLOAD_AUDIT_MYSQL=0');
require __DIR__.'/download_asset_io.php';
require __DIR__.'/security_audit_remote_upload_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($databaseDirectory));
use think\facade\Db;
use app\common\model\Image;
uploadIdentityRequest([], 'GET', false);
$source='https://1.1.1.1/ordinary-owner-picture';
$GLOBALS['download_asset_bytes']=[$source=>file_get_contents('source.png')];$GLOBALS['download_asset_calls']=0;
$assetConfig=['mode'=>'local','watermark'=>0,'thumb'=>1,'thumb_size'=>'10x10,20x20','thumb_type'=>1];
$connection=Db::connect();$connection->query('SELECT 1',[],true);$original=$connection->getPdo();
$before=uploadIdentitySnapshot();$stages=glob(sys_get_temp_dir().'/maccms-attachment-*');
$caller=str_starts_with($case,'caller_');
if ($caller) {
    if ($case==='caller_raw') { $original->beginTransaction(); } else { Db::startTrans(); }
    Db::name('User')->where('user_id',1)->update(['user_name'=>'caller-sentinel']);
}
$rollback=str_contains($case,'rollback');
if ($rollback) { $GLOBALS['attachment_io_fault']='second-publish';$GLOBALS['attachment_publish_count']=0; }
PurchaseOwnerFault::reset($case==='rollback_unrecoverable'?['pdo_rollback_before'=>'always']:
    (str_starts_with($case,'orm_')||str_starts_with($case,'pdo_')?[$case=>1]:[]));
try {
    $result=(new Image())->down_load($source,$assetConfig);
    check(($result===$source.'#err')===($case!=='normal'),'Attachment response does not match the actual owner outcome');
    $new=array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages));
    check($GLOBALS['storage_provider_calls']===0,'Local acknowledgement fixture must not call an external provider');
    if ($caller) {
        check($original->inTransaction()&&Db::name('User')->where('user_id',1)->value('user_name')==='caller-sentinel',
            'Attachment must neither end nor overwrite the caller transaction');
        check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===0,'Rejected caller must never reach owner rollback');
        check($new===[],'Rejected caller left private upload evidence');
        if ($case==='caller_raw') { $original->rollBack(); } else { Db::rollback(); }
        check(uploadIdentitySnapshot()===$before,'Caller rollback must restore its own ordinary update');
    } elseif ($case==='normal') {
        check(!$original->inTransaction()&&Db::name('Annex')->count()===3&&is_file($result),'Normal attachment must commit every file and metadata row');
        check($new===[],'Normal attachment must clean its private stage');
    } elseif (str_contains($case,'commit')||$case==='rollback_unrecoverable') {
        check(count($new)===1,'Uncertain attachment must keep exactly its own manifest');
        $manifest=json_decode(file_get_contents($new[0].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
        check($manifest['state']===($case==='rollback_unrecoverable'?'rollback_outcome_unknown':'commit_outcome_unknown'),
            'The manifest must distinguish commit and rollback uncertainty');
        $rows=$original->query('SELECT annex_file FROM upload_audit_annex')->fetchAll(PDO::FETCH_COLUMN);
        $committed=str_ends_with($case,'commit_after');
        check(count($rows)===($committed||$case==='rollback_unrecoverable'?3:0),'Original PDO must show the actual metadata outcome');
        if ($case==='rollback_unrecoverable') {
            check($original->inTransaction(),'Unconfirmed cleanup must not pretend that closing ORM ended the retained PDO');
            check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1&&(PurchaseOwnerFault::$calls['pdo_rollback_before']??0)===2,
                'Unrecoverable cleanup must use one ORM call and one original-PDO fallback');
            check(count(array_filter($rows,'is_file'))>=1,'Failed rollback deleted files still referenced by the original transaction');
        } else {
            check(!$original->inTransaction(),'Commit-failure cleanup should end the original fixture transaction');
            foreach ($manifest['files'] as $file) {
                check(is_file($file['annex_file'])&&filesize($file['annex_file'])===$file['annex_size'],
                    'Uncertain commit must retain every possibly referenced file');
            }
        }
        $calls=PurchaseOwnerFault::$calls;$contents=file_get_contents($new[0].'/manifest.json');
        check((new Image())->down_load($source,$assetConfig)===$source.'#err','Another upload in the uncertain request must be rejected');
        check(PurchaseOwnerFault::$calls===$calls&&file_get_contents($new[0].'/manifest.json')===$contents,
            'The request fence must preserve evidence and avoid another transaction');
        check(array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages))===$new,
            'The request fence must not create another staging directory');
    } else {
        check(!$original->inTransaction(),'Recoverable BEGIN/ROLLBACK failure must end the original PDO transaction');
        check(uploadIdentitySnapshot()===$before&&$new===[],'Confirmed rollback must restore metadata and clean only its own files');
        check((PurchaseOwnerFault::$calls['orm_rollback_before']??0)===1,'Owner cleanup must not repeat ORM rollback');
    }
    echo json_encode(['case'=>$case,'checks'=>$checks,'result'=>'passed'],JSON_THROW_ON_ERROR)."\n";
} finally {
    PurchaseOwnerFault::reset();unset($GLOBALS['attachment_io_fault']);
    if ($original->inTransaction()) { $original->rollBack(); }
    $connection->close();
}
