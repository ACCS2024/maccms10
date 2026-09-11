<?php
/** Actual SQLite COMMIT outcomes are inspected through a second durable database connection. */
declare(strict_types=1);
$case=$argv[1]??'';
if(!in_array($case,['commit-before','commit-after','remote-commit-before','remote-commit-after','restore-commit-before','restore-commit-after'],true))throw new RuntimeException('Unknown cover worker');
putenv('REMOTE_UPLOAD_AUDIT_MYSQL=0');
require dirname(__DIR__,2).'/vendor/autoload.php';
$coverDatabaseDirectory=sys_get_temp_dir().'/cover-commit-db-'.bin2hex(random_bytes(12));
if(!mkdir($coverDatabaseDirectory,0700))throw new RuntimeException('Cannot create durable fixture database');
define('UPLOAD_AUDIT_SQLITE_DATABASE',$coverDatabaseDirectory.'/fixture.sqlite');
class CoverCommitSqlite extends think\db\connector\Sqlite {
    public function __construct(array $config=[]) {$config['type']='sqlite';parent::__construct($config);}
    public function commit(): void {
        if(isset($GLOBALS['cover_commit_case'])&&($GLOBALS['cover_restore']||(int)$this->query('SELECT COUNT(*) AS total FROM upload_audit_annex',[],true)[0]['total']>0)) {
            if(str_ends_with($GLOBALS['cover_commit_case'],'commit-after'))parent::commit();
            throw new RuntimeException('Ordinary fixture lost commit acknowledgement');
        }
        parent::commit();
    }
}
define('UPLOAD_AUDIT_SQLITE_DRIVER','\\CoverCommitSqlite');
require __DIR__.'/vod_cover_transport.php';
require __DIR__.'/security_audit_remote_upload_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($coverDatabaseDirectory));
use app\common\util\VodAiCover;
use app\common\util\VodCoverBinding;
use think\facade\Db;
function mac_filter_xss($value){return $value;}
$columns=[];foreach(VodCoverBinding::FIELDS as $field)$columns[]=$field.($field==='vod_id'?' INTEGER PRIMARY KEY':($field==='vod_pic_thumb_original'?' TEXT DEFAULT NULL':" TEXT NOT NULL DEFAULT ''"));
Db::execute('CREATE TABLE upload_audit_vod ('.implode(',',$columns).')');
$original=['vod_id'=>1,'vod_recycle_time'=>0,'vod_pic'=>'existing-original.png','vod_pic_thumb'=>'existing-original-thumb.png','vod_pic_original'=>'','vod_pic_thumb_original'=>null];
Db::name('Vod')->insert($original);
copy('source.png',$original['vod_pic']);copy('source.png',$original['vod_pic_thumb']);
uploadIdentityRequest([], 'POST', false);
$GLOBALS['cover_http_calls']=0;
$GLOBALS['cover_http_response']=json_encode(['data'=>[['b64_json'=>base64_encode(file_get_contents('source.png'))]]]);
remoteUploadConfig(['mode'=>str_starts_with($case,'remote-')?'s3':'local']);
think\facade\Config::set(['ai_cover'=>['enabled'=>1,'api_key'=>'fixture-key','api_base'=>'https://1.1.1.1/v1']],'maccms');
$GLOBALS['cover_restore']=str_starts_with($case,'restore-');
if($GLOBALS['cover_restore']) {
    check(VodAiCover::generateByVodId(1)['code']===1,'Restore fixture generation failed');
    $generated=Db::name('Vod')->where('vod_id',1)->find();
}
$stages=glob(sys_get_temp_dir().'/maccms-attachment-*');
$GLOBALS['cover_commit_case']=$case;
$result=$GLOBALS['cover_restore']?VodAiCover::revertByVodId(1):VodAiCover::generateByVodId(1);
check(in_array($result['code'],[2004,2005],true)&&$result['data']['retryable']===false&&!empty($result['data']['reference']),'Lost acknowledgement returned success or a retryable generic failure');
$reader=new PDO('sqlite:'.UPLOAD_AUDIT_SQLITE_DATABASE);$row=$reader->query('SELECT * FROM upload_audit_vod WHERE vod_id=1')->fetch(PDO::FETCH_ASSOC);
$committed=str_ends_with($case,'commit-after');
if($GLOBALS['cover_restore']) {
    check($row['vod_pic']===($committed?$original['vod_pic']:$generated['vod_pic'])&&$row['vod_pic_thumb']===($committed?$original['vod_pic_thumb']:$generated['vod_pic_thumb']),'Restore did not exercise the intended physical outcome');
    check($row['vod_pic_thumb_original']===($committed?null:$original['vod_pic_thumb']),'Restore backup marker partially persisted');
    check(VodAiCover::revertByVodId(1)['data']['outcome']==='request_blocked','Uncertain restore was retried in the same request');
} else {
    $new=array_values(array_diff(glob(sys_get_temp_dir().'/maccms-attachment-*'),$stages));check(count($new)===1,'Uncertain cover lost its private evidence');
    $manifest=json_decode(file_get_contents($new[0].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
    check($manifest['state']==='commit_outcome_unknown'&&$manifest['scope']==='ai_cover'&&$manifest['owner_id']===1,'Cover uncertainty lost its resource identity');
    check($row['vod_pic']===($committed?$manifest['selected_cover']['vod_pic']:$original['vod_pic'])&&$row['vod_pic_thumb']===($committed?$manifest['selected_cover']['vod_pic_thumb']:$original['vod_pic_thumb']),'Cover pointers do not match physical commit outcome');
    check((int)$reader->query('SELECT COUNT(*) FROM upload_audit_annex')->fetchColumn()===($committed?3:0),'Cover and Annex committed separately');
    foreach($manifest['files'] as $file)check(is_file($file['annex_file'])&&filesize($file['annex_file'])===$file['annex_size'],'Uncertain commit removed a potentially referenced replica');
    if(str_starts_with($case,'remote-'))foreach($reader->query('SELECT * FROM upload_audit_storage_intent')->fetchAll(PDO::FETCH_ASSOC) as $intent) {
        check($intent['scope']==='ai_cover'&&(int)$intent['owner_id']===1&&$intent['reference_state']===($committed?'committed':'pending'),'Remote references differ from business commit outcome');
        check(is_file('remote-fixture/'.$intent['intent_id']),'Uncertain remote cover lost its receipt object');
    }
}
$calls=$GLOBALS['cover_http_calls'];$failed=false;
try{$retry=VodAiCover::generateByVodId(1);$failed=$retry['code']!==1;}catch(Throwable $error){$failed=true;}
check($failed&&$GLOBALS['cover_http_calls']===$calls,'Uncertain request paid for a second generation');
check(is_file($original['vod_pic'])&&is_file($original['vod_pic_thumb']),'Uncertain cover deleted original files');
unset($GLOBALS['cover_commit_case']);
echo json_encode(['case'=>$case,'checks'=>$checks,'result'=>'passed'],JSON_THROW_ON_ERROR)."\n";
