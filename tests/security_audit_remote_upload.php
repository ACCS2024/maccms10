<?php
/** Actual manual upload, image processing and ORM; only cloud transport is isolated. */
declare(strict_types=1);
putenv('UPLOAD_AUDIT_ENTRANCE=admin');
require __DIR__.'/fixtures/security_audit_remote_upload_db.php';
use app\common\util\StorageObjectUrl;
use app\common\util\UserPortrait;
use think\facade\Db;

uploadIdentityAdmin();
foreach([[],new stdClass(),false,1.5] as $badMode)check(app\common\util\RemoteAttachment::provider(['mode'=>$badMode])===null,'Malformed internal provider mode emitted a diagnostic or selected a remote adapter');
foreach(['s3','upyun','qiniu','ftp','alibaba','uomg','weibo',2,3,4,5] as $provider) {
    foreach(['success','false','throw','mixed'] as $outcome) {
        remoteUploadConfig(['mode'=>$provider]);$GLOBALS['storage_provider_mode']='success';
        $GLOBALS['config']['upload']['api']['ftp']['host']='fixture-'.$provider.'-'.$outcome;
        $calls=$GLOBALS['storage_provider_calls'];$count=Db::name('Annex')->count();$pathsBefore=count($GLOBALS['remote_write_paths']);
        $GLOBALS['remote_provider_hook']=static function () use($outcome,$calls):void {
            $GLOBALS['storage_provider_mode']=$outcome==='mixed'
                ? ($GLOBALS['storage_provider_calls']===$calls+2?'false':'success') : $outcome;
        };
        $result=remoteUploadAttempt();unset($GLOBALS['remote_provider_hook']);
        check($result['code']===1 && count($result['data']['thumb'])===2,'Remote manual upload lost its complete derivative set');
        // FTP deliberately caches a failed connection: later paths fall back locally without a repeated connection attempt.
        $expectedCalls=$provider==='ftp'||$provider===4 ? ($outcome==='success'?3:($outcome==='mixed'?2:1)) : 3;
        check($GLOBALS['storage_provider_calls']===$calls+$expectedCalls,'Provider call count does not match the actual success/failure contract');
        check(Db::name('Annex')->count()===$count+3,'Remote manual upload did not register all files');
        $last=array_slice(Db::name('Annex')->order('annex_id')->select()->toArray(),-3);
        $visible=[$result['data']['file'],...array_column($result['data']['thumb'],'file')];
        foreach($last as $index=>$annex) {
            $path=$annex['annex_file'];$intent=Db::name('StorageIntent')->where('local_path',$path)->find();
            check($intent['reference_state']==='committed' && (int)$intent['annex_id']===(int)$annex['annex_id'],'Final Annex was not committed with its intent');
            check((int)$annex['annex_size']===(int)$intent['source_bytes'] && $annex['annex_type']==='image','Exact derivative byte metadata was lost');
            $remote=$intent['transfer_state']==='remote_confirmed';
            check(is_file($path)===!$remote,'keep_local removed an unconfirmed file or retained a required-to-clean remote replica');
            $copy=$remote?'remote-fixture/'.$intent['intent_id']:$path;
            check(getimagesize($copy)[2]===IMAGETYPE_PNG,'Remote/local result does not contain the processed image');
            check($visible[$index]===($remote?$intent['remote_url']:$path),'Response does not identify its actual remote/local object');
        }
    }
}
$GLOBALS['storage_provider_mode']='success';remoteUploadConfig(['keep_local'=>1]);
$result=remoteUploadAttempt();$kept=array_slice(Db::name('Annex')->order('annex_id')->select()->toArray(),-3);
foreach($kept as $annex)check(is_file($annex['annex_file']),'keep_local=1 discarded a replica');
foreach(['alibaba','uomg','weibo'] as $provider) {
    remoteUploadConfig(['mode'=>$provider]);$GLOBALS['storage_provider_mode']='wrong-url';$result=remoteUploadAttempt();
    check($result['code']===1 && is_file($result['data']['file']),'Untrusted image-service URL was activated or lost its local fallback');
    $prefix=$GLOBALS['config']['upload']['api'][$provider]['public_url_prefix'];unset($GLOBALS['config']['upload']['api'][$provider]['public_url_prefix']);
    $calls=$GLOBALS['storage_provider_calls'];$result=remoteUploadAttempt();
    check($result['code']===1 && is_file($result['data']['file']) && $GLOBALS['storage_provider_calls']===$calls,'Missing trusted image-service prefix still invoked a remote provider');
    $GLOBALS['config']['upload']['api'][$provider]['public_url_prefix']=$prefix;
}
$GLOBALS['storage_provider_mode']='success';

// Entire preparation must complete before the first provider. Legacy/missing table retains local upload success.
Db::execute('ALTER TABLE upload_audit_storage_intent RENAME TO upload_audit_storage_saved');
$calls=$GLOBALS['storage_provider_calls'];remoteUploadConfig();$result=remoteUploadAttempt();
check($result['code']===1 && $GLOBALS['storage_provider_calls']===$calls,'Missing intent schema invoked a provider or broke local fallback');
foreach([$result['data']['file'],...array_column($result['data']['thumb'],'file')] as $path)check(is_file($path),'Old schema fallback lost a local derivative');
Db::execute('ALTER TABLE upload_audit_storage_saved RENAME TO upload_audit_storage_intent');

// One successfully prepared intent must not start a partial external batch if the next insert fails.
$trigger=$mysql
    ? "CREATE TRIGGER remote_prepare_fault BEFORE INSERT ON upload_audit_storage_intent FOR EACH ROW BEGIN IF NEW.local_path LIKE '%_10x10.png' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='prepare fixture'; END IF; END"
    : "CREATE TRIGGER remote_prepare_fault BEFORE INSERT ON upload_audit_storage_intent WHEN NEW.local_path LIKE '%_10x10.png' BEGIN SELECT RAISE(ABORT,'prepare fixture'); END";
Db::execute($trigger);$calls=$GLOBALS['storage_provider_calls'];
try {$result=remoteUploadAttempt();} finally {Db::execute('DROP TRIGGER remote_prepare_fault');}
check($result['code']===1 && $GLOBALS['storage_provider_calls']===$calls,'Partial intent preparation started an external batch');
foreach([$result['data']['file'],...array_column($result['data']['thumb'],'file')] as $path)check(is_file($path),'Partial prepare fallback lost a local file');

// Valid remote avatars commit an immutable local logical pointer and refresh the real owner cookie/reader.
uploadIdentityMember();$old=Db::name('User')->find(1)['user_portrait'];$oldBytes=file_get_contents($old);
$result=remoteUploadAttempt([],false);$pointer=Db::name('User')->find(1)['user_portrait'];
check($result['code']===1 && UserPortrait::isManagedPath(1,$pointer) && !is_file($pointer),'Remote avatar did not retain a controlled logical pointer');
check(UserPortrait::url(1)===$result['data']['file'] && $GLOBALS['upload_cookies']['user_portrait']===$result['data']['file'],'Avatar reader/cookie does not select the committed remote image');
check(file_get_contents($old)===$oldBytes,'Remote avatar deleted the old cache-visible avatar');
$avatar=Db::name('StorageIntent')->where('local_path',$pointer)->find();
check(getimagesize('remote-fixture/'.$avatar['intent_id'])[2]===IMAGETYPE_JPEG,'Remote avatar is not the explicit processed JPEG');
check(!isset($result['data']['_portrait_path']),'Internal logical-pointer metadata leaked into the client payload');

// Arbitrary User URLs and corrupted/uncommitted/mismatched mapping fields never activate a remote avatar.
foreach(['reference_state'=>'pending','remote_url'=>'https://attacker.invalid/image.jpg','owner_id'=>2,'source_bytes'=>1] as $column=>$bad) {
    $before=$avatar[$column];Db::name('StorageIntent')->where('intent_id',$avatar['intent_id'])->update([$column=>$bad]);UserPortrait::forget(1);
    check(UserPortrait::url(1)===MAC_PATH.'upload/user/1/1.jpg','Unattested avatar mapping activated through '.$column);
    Db::name('StorageIntent')->where('intent_id',$avatar['intent_id'])->update([$column=>$before]);
}
Db::name('User')->where('user_id',1)->update(['user_portrait'=>'https://attacker.invalid/image.jpg']);UserPortrait::forget(1);
check(UserPortrait::url(1)===MAC_PATH.'upload/user/1/1.jpg','Arbitrary historical User URL activated');
Db::name('User')->where('user_id',1)->update(['user_portrait'=>$pointer]);UserPortrait::forget(1);

// Actual Annex listing uses a bounded mapping query, escapes URLs in its template, and keeps long URLs out of VARCHAR(255).
uploadIdentityAdmin();$GLOBALS['config']['upload']['api']['s3']['domain']='https://objects.fixture.invalid/'.str_repeat('x',300);
$result=remoteUploadAttempt();$last=array_slice(Db::name('Annex')->order('annex_id')->select()->toArray(),-3);
check($result['code']===1 && strlen($result['data']['file'])>255 && strlen($last[0]['annex_file'])<255,'Long remote URL was clipped into the Annex filename');
$queries=[];Db::listen(static function($sql)use(&$queries):void{if(preg_match('/^SELECT /i',$sql)&&str_contains($sql,'storage_intent'))$queries[]=$sql;});
$listed=(new app\common\model\Annex())->listData([['annex_id','in',array_column($last,'annex_id')]],'annex_id asc')['list'];
check(count($queries)===1 && count($listed)===3,'Annex list did not batch remote mapping queries');
check($listed[0]['annex_url']===$result['data']['file'],'Annex list returned a local or unverified URL');
$GLOBALS['config']['upload']['api']['s3']['domain']='https://objects.fixture.invalid';
$queries=[];uploadIdentityRequest([], 'GET', false);UserPortrait::prefetch([1,2,4294967295]);
check(count($queries)===1 && UserPortrait::url(1)===$avatar['remote_url'],'Avatar list did not resolve remote mappings in one batch');
check(StorageObjectUrl::resolve([])===[],'Empty mapping read must be a no-op');
require __DIR__.'/fixtures/security_audit_remote_failures.php';
require __DIR__.'/fixtures/security_audit_remote_lists.php';
if($mysql)require __DIR__.'/fixtures/security_audit_remote_master.php';
require __DIR__.'/fixtures/security_audit_remote_concurrency.php';
foreach(['member-subdirectory','member-fallback',...array_merge(...array_map(fn($editor)=>['editor-success-'.$editor,'editor-failure-'.$editor],
    ['tinymce','ueditor','umeditor','kindeditor','ckeditor']))] as $case) {
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/security_audit_remote_clients.php',$case],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    check(proc_close($process)===0 && str_contains($errors,'remote client passed: '.$case),'Remote client failed: '.$case.' '.$errors.' '.$output);
    $payload=json_decode($output,true,512,JSON_THROW_ON_ERROR);
    $ok=($payload['code']??null)===1||($payload['state']??null)==='SUCCESS'||($payload['uploaded']??null)===1||($payload['error']??null)===0||isset($payload['location']);
    check($ok===!str_starts_with($case,'editor-failure-'),'Remote editor/member falsely acknowledged success: '.$case);
    if($ok && str_starts_with($case,'editor-success-')) {
        $url=$payload['location']??$payload['url']??$payload['fileUrl']??'';
        check(str_starts_with($url,'https://')&&!str_contains($url,'/site/'),'Editor subdirectory corrupted a remote URL');
    }
}
echo "Remote manual upload: $checks checks passed on PHP ".PHP_VERSION.' ('.($mysql?'MySQL':'SQLite').")\n";
