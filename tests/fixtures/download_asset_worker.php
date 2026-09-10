<?php
/** Ordinary local permissions and lost COMMIT acknowledgements in a real SQLite transaction. */
declare(strict_types=1);
$case=$argv[1]??'';
if(!in_array($case,['permissions','commit-before','commit-after','remote-commit-before','remote-commit-after'],true))throw new RuntimeException('Unknown download worker');
putenv('REMOTE_UPLOAD_AUDIT_MYSQL=0');
chdir(sys_get_temp_dir());
if($case==='permissions'&&posix_geteuid()===0) {
    if(!posix_setgid(65534)||!posix_setuid(65534))throw new RuntimeException('Permission fixture requires unprivileged execution');
}
require dirname(__DIR__,2).'/vendor/autoload.php';
$downloadDatabaseDirectory = sys_get_temp_dir().'/download-commit-db-'.bin2hex(random_bytes(12));
if (!mkdir($downloadDatabaseDirectory,0700)) { throw new RuntimeException('Cannot create durable fixture database'); }
define('UPLOAD_AUDIT_SQLITE_DATABASE',$downloadDatabaseDirectory.'/fixture.sqlite');
class DownloadAssetCommitSqlite extends think\db\connector\Sqlite {
    public function __construct(array $config=[]) {$config['type']='sqlite';parent::__construct($config);}
    public function commit(): void {
        if(isset($GLOBALS['download_commit_case']) && (int)$this->query('SELECT COUNT(*) AS total FROM upload_audit_annex',[],true)[0]['total']>0) {
            if(str_ends_with($GLOBALS['download_commit_case'],'commit-after'))parent::commit();
            throw new RuntimeException('Ordinary fixture lost commit acknowledgement');
        }
        parent::commit();
    }
}
define('UPLOAD_AUDIT_SQLITE_DRIVER','\\DownloadAssetCommitSqlite');
require __DIR__.'/download_asset_io.php';
require __DIR__.'/security_audit_remote_upload_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($downloadDatabaseDirectory));
use think\facade\Db;
$source='https://1.1.1.1/ordinary-worker-picture';$GLOBALS['download_asset_bytes']=[$source=>file_get_contents('source.png')];$GLOBALS['download_asset_calls']=0;
uploadIdentityRequest([], 'GET', false);
$remote=str_starts_with($case,'remote-');
$assetConfig=['mode'=>$remote?'s3':'local','watermark'=>0,'thumb'=>1,'thumb_size'=>'10x10,20x20','thumb_type'=>1];
$before=uploadIdentitySnapshot();$stages=glob(sys_get_temp_dir().'/maccms-attachment-*');
if($case==='permissions') {
    $directory='upload/vod/'.date('Ymd').'-1';mkdir($directory,0755,true);chmod($directory,0555);$before=uploadIdentitySnapshot();
} else {$GLOBALS['download_commit_case']=$case;}
try {
    $result=(new app\common\model\Image())->down_load($source,$assetConfig);
    check($result===$source.'#err','Uncertain/failed asset returned success');
    $new=array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages));
    if($case==='permissions') {
        check(uploadIdentitySnapshot()===$before&&$new===[],'Permission failure left files/metadata/stage');
        check($GLOBALS['storage_provider_calls']===0,'Permission failure reached a provider');
    } else {
        check(count($new)===1,'Uncertain commit lost its own journal');
        $manifest=json_decode(file_get_contents($new[0].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
        check($manifest['state']==='commit_outcome_unknown'&&$manifest['scope']==='download','Uncertain commit lost download scope/state');
        check(Db::name('Annex')->count()===(str_ends_with($case,'commit-after')?3:0),'Fixture did not exercise the intended commit outcome');
        foreach($manifest['files'] as $row)check(is_file($row['annex_file'])&&filesize($row['annex_file'])===$row['annex_size'],'Uncertain commit deleted a possibly referenced file');
        check($GLOBALS['storage_provider_calls']===($remote?3:0),'Commit fixture used the wrong provider path');
        if($remote)foreach(Db::name('StorageIntent')->select()->toArray() as $intent) {
            check($intent['reference_state']===(str_ends_with($case,'commit-after')?'committed':'pending')&&is_file('remote-fixture/'.$intent['intent_id']),'Unknown commit lost the actual reference/receipt outcome');
            check(($manifest['remote']['selected_urls'][$intent['local_path']]??null)===$intent['remote_url'],'Unknown commit lost its selected resource URL');
        }
    }
    echo json_encode(['case'=>$case,'checks'=>$checks,'result'=>'passed'],JSON_THROW_ON_ERROR)."\n";
} finally {if($case==='permissions')chmod($directory,0755);unset($GLOBALS['download_commit_case']);}
