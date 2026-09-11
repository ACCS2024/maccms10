<?php
/** Cover and derivative references use real image decoding, ORM/PDO and independently journaled fixture transfers. */
declare(strict_types=1);
require __DIR__.'/fixtures/vod_cover_transport.php';
require __DIR__.'/fixtures/security_audit_remote_upload_db.php';
use app\common\util\VodAiCover;
use app\common\util\VodCoverBinding;
use think\facade\Db;
use think\facade\Config;
function mac_filter_xss($value) { return $value; }
if ($mysql && getenv('VOD_COVER_AUDIT_STRICT') === '1') { Db::execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'"); }
class CoverAuditCache {
    public function get($key,$default=null) { return $default; }
    public function delete($key): bool {
        if (!empty($GLOBALS['cover_maintenance_fail'])) { throw new RuntimeException('fixture private cache address'); }
        return true;
    }
}
think\Container::getInstance()->instance('cache',new CoverAuditCache());
Db::execute('DROP TABLE IF EXISTS upload_audit_vod');
if ($mysql) {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    preg_match('/CREATE TABLE `mac_vod`.*?ENGINE=InnoDB[^;]*;/s',$ddl,$matches);
    check(isset($matches[0]),'Install video schema not found');
    Db::execute(str_replace('`mac_vod`','`upload_audit_vod`',$matches[0]));
} else {
    $columns=[];foreach(VodCoverBinding::FIELDS as $field) {
        $columns[]=$field.($field==='vod_id'?' INTEGER PRIMARY KEY':($field==='vod_pic_thumb_original'?' TEXT DEFAULT NULL':" TEXT NOT NULL DEFAULT ''"));
    }
    Db::execute('CREATE TABLE upload_audit_vod ('.implode(',',$columns).')');
}
$baseCover=['vod_id'=>1,'vod_recycle_time'=>0,'vod_pic'=>'upload/vod/original.png','vod_pic_thumb'=>'upload/vod/original-thumb.png',
    'vod_pic_original'=>'','vod_pic_thumb_original'=>null,'vod_en'=>'fixture-video','vod_name'=>'Ordinary sample',
    'vod_sub'=>'','vod_class'=>'Drama','vod_area'=>'','vod_year'=>'2026','vod_blurb'=>'A sample description','vod_content'=>''];
if ($mysql) {
    foreach (Db::query('SHOW COLUMNS FROM upload_audit_vod') as $column) {
        if ($column['Null'] === 'NO' && $column['Default'] === null && str_contains($column['Type'], 'text')) {
            $baseCover += [$column['Field']=>''];
        }
    }
}
mkdir('upload/vod',0700,true);copy('source.png','upload/vod/original.png');copy('source.png','upload/vod/original-thumb.png');
$oldBytes=hash_file('sha256','upload/vod/original.png');
function coverSeed(array $changes=[]): void {
    Db::name('Vod')->where('vod_id',1)->delete();
    Db::name('Vod')->insert(array_replace($GLOBALS['baseCover'],$changes));
    uploadIdentityRequest([], 'POST', false);
}
function coverConfig(array $changes=[]): void {
    remoteUploadConfig($changes);
    Config::set(['ai_cover'=>['enabled'=>1,'api_key'=>'ordinary-fixture-key','api_base'=>'https://1.1.1.1/v1']], 'maccms');
}
function coverRow(): ?array { return Db::name('Vod')->where('vod_id',1)->find(); }
function coverAnnex(): array { return Db::name('Annex')->order('annex_id')->select()->toArray(); }
function coverManifests(): array {
    $found=[];foreach(glob(sys_get_temp_dir().'/maccms-attachment-*') as $stage) {
        $data=@json_decode((string)@file_get_contents($stage.'/manifest.json'),true);
        if(is_array($data)&&($data['root']??null)===realpath(ROOT_PATH))$found[$stage]=$data;
    }return $found;
}
function coverGenerate(): array { return VodAiCover::generateByVodId(1,'Ordinary cinematic composition'); }
function coverReject(callable $operation,string $reason): void {
    $failed=false;try{$result=$operation();$failed=($result['code']??0)!==1;}catch(Throwable $error){$failed=true;}
    check($failed,'Cover operation falsely succeeded: '.$reason);
}
$GLOBALS['cover_http_calls']=0;
$GLOBALS['cover_http_response']=json_encode(['data'=>[['b64_json'=>base64_encode(file_get_contents('source.png'))]]]);
foreach(['local','s3'] as $mode)foreach([0,1] as $thumb) {
    coverSeed();coverConfig(['mode'=>$mode,'thumb'=>$thumb]);$before=coverAnnex();
    $result=coverGenerate();$row=coverRow();$new=array_slice(coverAnnex(),count($before));
    check($result['code']===1&&$result['data']['vod_pic']===$row['vod_pic'],'Generated cover response differs from the committed row');
    check(count($new)===($thumb?3:1),'A derivative is missing from Annex');
    check($row['vod_pic_original']===$baseCover['vod_pic']&&$row['vod_pic_thumb_original']===$baseCover['vod_pic_thumb'],'Original pair not backed up exactly');
    check($thumb?($row['vod_pic_thumb']!==$baseCover['vod_pic_thumb']):($row['vod_pic_thumb']===''),'Cover retained an unrelated thumbnail');
    foreach($new as $item) {
        $intent=Db::name('StorageIntent')->where('local_path',$item['annex_file'])->find();
        if($mode==='s3') {
            check($intent['scope']==='ai_cover'&&(int)$intent['owner_id']===1&&$intent['reference_state']==='committed','Cover transfer reference lost ownership or commit state');
            check((int)$intent['annex_id']===(int)$item['annex_id']&&!is_file($item['annex_file']),'Confirmed cover did not reconcile or clean up its new replica');
        } else { check(is_file($item['annex_file'])&&$intent===null,'Local cover created a remote intent or lost its file'); }
    }
    check(coverManifests()===[],'Successful cover retained a private stage');
    $second=coverGenerate();check($second['code']===1&&coverRow()['vod_pic_original']===$baseCover['vod_pic']&&coverRow()['vod_pic_thumb_original']===$baseCover['vod_pic_thumb'],'Second generation replaced the original backup');
    $restored=VodAiCover::revertByVodId(1);$row=coverRow();
    check($restored['code']===1&&$row['vod_pic']===$baseCover['vod_pic']&&$row['vod_pic_thumb']===$baseCover['vod_pic_thumb'],'Restore mixed old and generated images');
    check($row['vod_pic_original']===''&&$row['vod_pic_thumb_original']===null,'Restored backup marker not cleared');
}
coverSeed(['vod_pic'=>'','vod_pic_thumb'=>'']);coverConfig(['mode'=>'local','thumb'=>0]);coverGenerate();
check(coverRow()['vod_pic_thumb_original']==='','An intentionally empty original lost its marker');
check(VodAiCover::revertByVodId(1)['code']===1&&coverRow()['vod_pic']===''&&coverRow()['vod_pic_thumb']==='','Originally blank cover cannot be restored');
coverSeed(['vod_pic_original'=>'historical-original.png']);$before=coverRow();
check(VodAiCover::revertByVodId(1)['code']===0&&coverRow()===$before,'Historical unknown thumbnail was invented');
coverGenerate();check(coverRow()['vod_pic_original']==='historical-original.png'&&coverRow()['vod_pic_thumb_original']===null,'Generation fabricated a historical pair');
foreach(['false','throw'] as $failure) {
    coverSeed();coverConfig();$GLOBALS['storage_provider_mode']=$failure;
    try{$result=coverGenerate();}finally{$GLOBALS['storage_provider_mode']='success';}
    check($result['code']===1&&is_file($result['data']['vod_pic'])&&is_file($result['data']['vod_pic_thumb']),'Unconfirmed provider did not retain a usable local pair');
    foreach([$result['data']['vod_pic'],$result['data']['vod_pic_thumb']] as $path) {
        $intent=Db::name('StorageIntent')->where('local_path',$path)->find();
        check($intent['scope']==='ai_cover'&&$intent['reference_state']==='committed','Fallback pointer lost its cover reference');
    }
}
// Concurrent ordinary edits/deletion during provider work must survive an obsolete generation.
foreach(['edit','delete','recycle','metadata'] as $change) {
    coverSeed();coverConfig();$before=coverAnnex();$evidence=coverManifests();$applied=false;
    $GLOBALS['remote_provider_hook']=static function()use($change,&$applied):void {
        if($applied)return;$applied=true;
        if($change==='delete')Db::name('Vod')->where('vod_id',1)->delete();
        else Db::name('Vod')->where('vod_id',1)->update(match($change){'edit'=>['vod_pic'=>'editor-new.png'],'recycle'=>['vod_recycle_time'=>1],'metadata'=>['vod_name'=>'Updated title']});
    };
    try{coverReject('coverGenerate','concurrent '.$change);}finally{unset($GLOBALS['remote_provider_hook']);}
    check(coverAnnex()===$before,'Rejected stale generation committed Annex metadata');
    $row=coverRow();check(match($change){'delete'=>$row===null,'edit'=>$row['vod_pic']==='editor-new.png','recycle'=>(int)$row['vod_recycle_time']===1,'metadata'=>$row['vod_name']==='Updated title'},'Concurrent video change was overwritten');
    $new=array_diff_key(coverManifests(),$evidence);check(count($new)===1,'Remote generation failure lost recovery evidence');
    $manifest=reset($new);check($manifest['scope']==='ai_cover'&&$manifest['owner_id']===1&&$manifest['state']==='remote_reference_failed','Recovery evidence lost resource identity');
    foreach($manifest['files'] as $file) {
        check(is_file($file['annex_file']),'Rejected generation deleted a transferred source');
        check(Db::name('StorageIntent')->where('local_path',$file['annex_file'])->value('reference_state')==='pending','Failed generation marked a remote reference committed');
    }
}
// Ordinary preparation failures, invalid reply shapes and missing schema must not publish a cover.
coverSeed();coverConfig();$normal=$GLOBALS['cover_http_response'];
foreach(['ordinary non-image','',json_encode(['data'=>[['b64_json'=>['unexpected-shape']]]]),json_encode(['data'=>[['b64_json'=>base64_encode('ordinary non-image')]]])] as $reply) {
    $GLOBALS['cover_http_response']=$reply;$before=coverRow();$annex=coverAnnex();$calls=$GLOBALS['storage_provider_calls'];
    coverReject('coverGenerate','invalid response');check(coverRow()===$before&&coverAnnex()===$annex&&$GLOBALS['storage_provider_calls']===$calls,'Invalid response altered business or called storage');
}
$GLOBALS['cover_http_response']=$normal;
foreach([['thumb_size'=>'10x10,missing'],['watermark'=>1,'watermark_content'=>'Ordinary sample','watermark_font'=>'/missing-fixture-font.ttf']] as $badConfig) {
    coverConfig($badConfig);$before=coverRow();$annex=coverAnnex();$calls=$GLOBALS['storage_provider_calls'];
    coverReject('coverGenerate','processing failure');check(coverRow()===$before&&coverAnnex()===$annex&&$GLOBALS['storage_provider_calls']===$calls,'Failed processing published an incomplete set');
}
coverConfig(['mode'=>'local']);
foreach(['orm','raw'] as $outer) {
    if($outer==='orm')Db::startTrans();else Db::connect()->getPdo()->beginTransaction();
    $calls=$GLOBALS['cover_http_calls'];
    try{coverReject('coverGenerate','caller transaction');check(Db::connect()->getPdo()->inTransaction()&&$calls===$GLOBALS['cover_http_calls'],'Cover touched its caller transaction or sent a paid request');}
    finally{if($outer==='orm')Db::rollback();else Db::connect()->getPdo()->rollBack();}
}
foreach([[],true,'1.5','1e0',0,-1,'4294967296'] as $id)check(VodAiCover::generateByVodId($id)['code']===0&&VodAiCover::revertByVodId($id)['code']===0,'Noncanonical video identity accepted');
// A real database constraint failure must roll back both pointers and all Annex records.
foreach(['local','s3'] as $mode) {
    coverSeed();coverConfig(['mode'=>$mode]);$before=coverRow();$annex=coverAnnex();
    Db::execute($mysql?"CREATE TRIGGER cover_reject BEFORE UPDATE ON upload_audit_vod FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture unavailable'":"CREATE TRIGGER cover_reject BEFORE UPDATE ON upload_audit_vod BEGIN SELECT RAISE(ABORT,'fixture unavailable'); END");
    try{coverReject('coverGenerate','PDO rejection');check(coverRow()===$before&&coverAnnex()===$annex,'Rejected pointer update partially committed');}
    finally{Db::execute('DROP TRIGGER cover_reject');}
}
coverSeed();coverConfig(['mode'=>'local']);$before=coverRow();$annex=coverAnnex();
Db::execute($mysql?"CREATE TRIGGER cover_alter BEFORE UPDATE ON upload_audit_vod FOR EACH ROW SET NEW.vod_pic=LEFT(NEW.vod_pic,8)":"CREATE TRIGGER cover_alter AFTER UPDATE ON upload_audit_vod BEGIN UPDATE upload_audit_vod SET vod_pic=substr(NEW.vod_pic,1,8) WHERE vod_id=NEW.vod_id; END");
try{coverReject('coverGenerate','altered storage');check(coverRow()===$before&&coverAnnex()===$annex,'Exact readback did not roll back an altered pointer');}
finally{Db::execute('DROP TRIGGER cover_alter');}
Db::execute('ALTER TABLE upload_audit_vod RENAME COLUMN vod_pic_thumb_original TO fixture_saved_thumb');
$calls=$GLOBALS['cover_http_calls'];
try{coverReject('coverGenerate','missing backup migration');check($calls===$GLOBALS['cover_http_calls'],'Missing schema issued a paid generation');}
finally{Db::execute('ALTER TABLE upload_audit_vod RENAME COLUMN fixture_saved_thumb TO vod_pic_thumb_original');}
coverSeed();coverConfig(['mode'=>'local']);$GLOBALS['cover_maintenance_fail']=true;
try {
    $result=coverGenerate();check($result['code']===1&&$result['data']['maintenance_pending']===true&&coverRow()['vod_pic']===$result['data']['vod_pic'],'Cache/index outage changed confirmed generation into failure');
    $result=VodAiCover::revertByVodId(1);check($result['code']===1&&$result['data']['maintenance_pending']===true&&coverRow()['vod_pic']===$baseCover['vod_pic'],'Cache/index outage changed confirmed restore into failure');
} finally {unset($GLOBALS['cover_maintenance_fail']);}
check(hash_file('sha256','upload/vod/original.png')===$oldBytes&&is_file('upload/vod/original-thumb.png'),'A cover operation removed an existing original');
foreach(['commit-before','commit-after','remote-commit-before','remote-commit-after','restore-commit-before','restore-commit-after'] as $case) {
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/vod_cover_worker.php',$case],[0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    check(is_resource($process),'Cannot start cover transaction worker');
    $output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    $status=proc_close($process);$result=json_decode(trim($output),true);
    check($status===0&&is_array($result)&&$result['result']==='passed','Cover worker failed: '.$case.' '.$output.' '.$errors);
    $checks+=$result['checks'];
}
Db::execute('DROP TABLE upload_audit_vod');
echo 'AI cover transaction: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
