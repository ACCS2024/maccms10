<?php
/** Dedicated remote-manual database; provider calls are the only substituted external side effect. */
declare(strict_types=1);
define('UPLOAD_AUDIT_REMOTE', true);
define('UPLOAD_AUDIT_TRACE_SQL', true);
putenv('UPLOAD_AUDIT_MYSQL='.(getenv('REMOTE_UPLOAD_AUDIT_MYSQL') === '1' ? '1' : '0'));
putenv('UPLOAD_AUDIT_HOST='.(getenv('REMOTE_UPLOAD_AUDIT_HOST') ?: '127.0.0.1'));
putenv('UPLOAD_AUDIT_PASSWORD='.(getenv('REMOTE_UPLOAD_AUDIT_PASSWORD') ?: ''));
require __DIR__.'/security_audit_remote_providers.php';
require __DIR__.'/security_audit_upload_identity_db.php';
require __DIR__.'/security_audit_local_attachment_io.php';
require dirname(__DIR__,2).'/migration/lib/StorageIntentMigration.php';
use think\facade\Db;
use think\facade\Config;

function remoteUploadSchema(): void {
    Db::execute('DROP TABLE IF EXISTS upload_audit_storage_intent');
    if ($GLOBALS['mysql']) {
        (new StorageIntentMigration(Db::connect()->getPdo(),'upload_audit_'))->apply();
    } else {
        $columns=[];
        foreach(StorageIntentMigration::COLUMNS as $name=>$type)$columns[]=$name.' '.(str_contains($type,'int')?'INTEGER':'TEXT').' NOT NULL';
        Db::execute('CREATE TABLE upload_audit_storage_intent ('.implode(',',$columns).',PRIMARY KEY(intent_id),UNIQUE(local_path))');
    }
}
remoteUploadSchema();
mkdir('remote-fixture',0700);mkdir('extend/qiniu',0700,true);mkdir('extend/upyun/vendor',0700,true);
file_put_contents('extend/qiniu/autoload.php','<?php');file_put_contents('extend/upyun/vendor/autoload.php','<?php');
$remoteSettings=['bucket'=>'audit-bucket','region'=>'us-east-1','domain'=>'https://objects.fixture.invalid',
    'url'=>'https://objects.fixture.invalid/files','accesskey'=>'fixture-key','secretkey'=>'fixture-secret',
    'username'=>'fixture-user','pwd'=>'fixture-password','host'=>'fixture','port'=>21,'user'=>'fixture','path'=>'/',
    'public_url_prefix'=>'https://images.fixture.invalid/objects','type'=>'ali','openid'=>'fixture','key'=>'fixture'];
foreach(app\common\util\StoragePublicUrl::PROVIDERS as $provider)$GLOBALS['config']['upload']['api'][$provider]=$remoteSettings;
$GLOBALS['storage_provider_calls']=0;$GLOBALS['storage_provider_mode']='success';
$GLOBALS['remote_write_paths']=[];
function remoteUploadConfig(array $changes=[]): void {
    Config::set(['site'=>['install_dir'=>MAC_PATH], 'upload'=>array_replace(['mode'=>'s3','keep_local'=>0,'thumb'=>1,
        'thumb_size'=>'10x10,20x20','thumb_type'=>1,'watermark'=>0],$changes)],'maccms');
}
function remoteUploadAttempt(array $parameters=[],bool $admin=true): array {
    uploadIdentityRequest(array_replace(['flag'=>$admin?'vod':'user','thumb'=>'1'],$parameters));
    return (new app\common\model\Upload())->upload([],$admin);
}
$GLOBALS['storage_provider_callback']=static function (string $path): void {
    check(!Db::connect()->getPdo()->inTransaction(),'Network call held a database transaction');
    $rows=Db::name('StorageIntent')->where('local_path',$path)->where('transfer_state','attempting')->where('reference_state','pending')->select()->toArray();
    $row=$rows[0]??null;
    check(is_array($row),'Provider invoked without its independently persisted attempt');
    $path=$row['local_path'];$GLOBALS['remote_write_paths'][]=$path;
    check(Db::name('Annex')->where('annex_file',$path)->count()===0,'Business metadata was committed before the external transfer');
    copy(ROOT_PATH.$path,ROOT_PATH.'remote-fixture/'.$row['intent_id']);
    if (isset($GLOBALS['remote_provider_hook']))($GLOBALS['remote_provider_hook'])($row);
};
// Keep intentional failed-upload evidence only until this isolated fixture exits.
$GLOBALS['upload_identity_before_cleanup']=static function (): void {
    foreach(glob(sys_get_temp_dir().'/maccms-attachment-*') as $stage) {
        $manifest=@json_decode((string)@file_get_contents($stage.'/manifest.json'),true);
        if(is_array($manifest) && ($manifest['root']??null)===realpath(ROOT_PATH))audit_remove_temp($stage);
    }
};
