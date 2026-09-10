<?php
/** Immutable avatars: real ORM, images, failed writes, owner-bound reads and process interruption. */
declare(strict_types=1);
define('UPLOAD_AUDIT_TRACE_SQL', true);
require __DIR__.'/fixtures/security_audit_upload_identity_db.php';
require __DIR__.'/fixtures/security_audit_local_attachment_io.php';
use app\common\model\Upload;
use app\common\util\UserPortrait;
use think\facade\Db;
use think\facade\Config;

function avatarAttempt(array $params = [], bool $admin = false): array {
    uploadIdentityRequest($params);
    return (new Upload())->upload([], $admin);
}
function avatarDenied(callable $call, string $label): void {
    $before = uploadIdentitySnapshot();
    $stages = glob(sys_get_temp_dir().'/maccms-attachment-*'); sort($stages);
    $result = $call();
    check($result['code'] === 0 && uploadIdentitySnapshot() === $before, $label.' changed files/metadata or acknowledged success');
    $after = glob(sys_get_temp_dir().'/maccms-attachment-*'); sort($after);
    check($after === $stages, $label.' leaked its staging files');
}
function avatarTrigger(string $kind): void {
    $sql = $GLOBALS['mysql'] ? match($kind) {
        'reject-user'=>"CREATE TRIGGER avatar_fault BEFORE UPDATE ON upload_audit_user FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='avatar fixture'",
        'mutate-user'=>"CREATE TRIGGER avatar_fault BEFORE UPDATE ON upload_audit_user FOR EACH ROW SET NEW.user_portrait='truncated'",
        'reject-annex'=>"CREATE TRIGGER avatar_fault BEFORE INSERT ON upload_audit_annex FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='avatar fixture'",
        'mutate-annex'=>"CREATE TRIGGER avatar_fault BEFORE INSERT ON upload_audit_annex FOR EACH ROW SET NEW.annex_size=NEW.annex_size+1",
    } : match($kind) {
        'reject-user'=>"CREATE TRIGGER avatar_fault BEFORE UPDATE ON upload_audit_user BEGIN SELECT RAISE(ABORT,'avatar fixture'); END",
        'ignore-user'=>"CREATE TRIGGER avatar_fault BEFORE UPDATE ON upload_audit_user BEGIN SELECT RAISE(IGNORE); END",
        'mutate-user'=>"CREATE TRIGGER avatar_fault AFTER UPDATE ON upload_audit_user BEGIN UPDATE upload_audit_user SET user_portrait='truncated' WHERE user_id=NEW.user_id; END",
        'reject-annex'=>"CREATE TRIGGER avatar_fault BEFORE INSERT ON upload_audit_annex BEGIN SELECT RAISE(ABORT,'avatar fixture'); END",
        'ignore-annex'=>"CREATE TRIGGER avatar_fault BEFORE INSERT ON upload_audit_annex BEGIN SELECT RAISE(IGNORE); END",
        'mutate-annex'=>"CREATE TRIGGER avatar_fault AFTER INSERT ON upload_audit_annex BEGIN UPDATE upload_audit_annex SET annex_size=annex_size+1 WHERE annex_id=NEW.annex_id; END",
    };
    Db::execute($sql);
}
uploadIdentityMember(); uploadIdentityRequest();
$legacy = 'upload/user/1/1.jpg'; $old = hash_file('sha256', $legacy);
check(UserPortrait::url(1) === '/'.$legacy, 'Legacy fixed avatar stopped resolving');
$paths=[];
foreach (['local','remote'] as $mode) {
    Config::set(['site'=>['install_dir'=>'/'],'upload'=>['mode'=>$mode, 'watermark'=>1,'thumb'=>1]],'maccms');
    $result=avatarAttempt(); $path=uploadIdentityPath($result); $paths[]=$path;
    check($result['code']===1 && UserPortrait::isManagedPath(1,$path),'Normal avatar did not use its immutable owner path');
    check(Db::name('User')->find(1)['user_portrait']===$path && UserPortrait::url(1)==='/'.$path,'Database/read helper did not select the committed avatar');
    $row=Db::name('Annex')->where('annex_file',$path)->find();
    check($row && (int)$row['annex_size']===filesize($path) && $row['annex_type']==='image','Avatar metadata is not exact bytes/image');
    $image=getimagesize($path);
    check([$image[0],$image[1],$image[2]]===[30,20,IMAGETYPE_JPEG],'Avatar has incorrect dimensions/format');
    check($GLOBALS['upload_cookies']['user_portrait']==='/'.$path,'Own successful upload did not refresh the portrait cookie');
    check(hash_file('sha256',$legacy)===$old,'Upload overwrote the legacy avatar cached by another session');
}
check($paths[0]!==$paths[1] && is_file($paths[0]),'Repeated avatar upload replaced an earlier immutable image');
foreach (['reject-user','mutate-user','reject-annex','mutate-annex',...($mysql?[]:['ignore-user','ignore-annex'])] as $kind) {
    avatarTrigger($kind);
    try {avatarDenied(fn()=>avatarAttempt(),$kind);} finally {Db::execute('DROP TRIGGER avatar_fault');}
}
foreach (['short-write','corrupt-write'] as $fault) {
    $GLOBALS['attachment_io_fault']=$fault;
    try {avatarDenied(fn()=>avatarAttempt(),$fault);} finally {unset($GLOBALS['attachment_io_fault']);}
}
foreach (['',[], '0x20','90000x20'] as $size) {
    $GLOBALS['config']['user']['portrait_size']=$size;
    avatarDenied(fn()=>avatarAttempt(),'Invalid portrait dimension');
}
$GLOBALS['config']['user']['portrait_size']='30x20';
foreach (['not-image','mime-mismatch','scanner'] as $fault) {
    uploadIdentityRequest();
    if ($fault==='not-image') file_put_contents('incoming.png','invalid');
    if ($fault==='mime-mismatch') imagejpeg($canvas,'incoming.png');
    if ($fault==='scanner') file_put_contents('incoming.png','<script>fixture</script>',FILE_APPEND);
    avatarDenied(fn()=>(new Upload())->upload(),$fault);
}
Db::startTrans();
try {avatarDenied(fn()=>avatarAttempt(),'Nested transaction');} finally {Db::rollback();}
if ($mysql) {
    foreach (['user','annex'] as $table) {
        Db::execute('ALTER TABLE upload_audit_'.$table.' ENGINE=MyISAM');
        try {avatarDenied(fn()=>avatarAttempt(),'Nontransactional '.$table);} finally {Db::execute('ALTER TABLE upload_audit_'.$table.' ENGINE=InnoDB');}
    }
    $saved=Db::name('User')->where('user_id',1)->value('user_portrait');
    Db::name('User')->where('user_id',1)->update(['user_portrait'=>'legacy']);
    Db::execute('ALTER TABLE upload_audit_user MODIFY user_portrait VARCHAR(10) NOT NULL DEFAULT ""');
    try {avatarDenied(fn()=>avatarAttempt(),'Non-strict truncated User pointer');}
    finally {Db::execute('ALTER TABLE upload_audit_user MODIFY user_portrait VARCHAR(100) NOT NULL DEFAULT ""');Db::name('User')->where('user_id',1)->update(['user_portrait'=>$saved]);}
}
$cookie=$GLOBALS['upload_cookies']['user_portrait'];
uploadIdentityAdmin(',upload/upload,user/info,');
$result=avatarAttempt(['flag'=>'user','user_id'=>4294967295],true);
check($result['code']===1 && UserPortrait::isManagedPath(4294967295,uploadIdentityPath($result)),'UINT32 target lost avatar ownership');
check($GLOBALS['upload_cookies']['user_portrait']===$cookie,'Admin target upload replaced the administrator browser portrait');

// Historical free-form paths never become a new file disclosure or a remote-image activation.
$original=Db::name('User')->where('user_id',1)->value('user_portrait');
foreach (['https://fixture.invalid/a.jpg','//fixture.invalid/a.jpg','../source.png',[], 'upload/user/2/2-'.str_repeat('a',32).'.jpg'] as $bad) {
    if (is_array($bad)) {check(!UserPortrait::isManagedPath(1,$bad),'Array pointer accepted');continue;}
    Db::name('User')->where('user_id',1)->update(['user_portrait'=>$bad]); UserPortrait::forget(1);
    check(UserPortrait::url(1)==='/'.$legacy,'Historical unsafe/cross-owner portrait activated');
}
Db::name('User')->where('user_id',1)->update(['user_portrait'=>$original]); UserPortrait::forget(1);
foreach ([[],new stdClass(),-1,'1e0','4294967296'] as $bad) check(UserPortrait::url($bad)==='/static_new/images/touxiang.png','Malformed ID escaped reader boundary');
$outside=audit_temp_dir('avatar-outside'); copy('source.png',$outside.'/image.jpg');
$link='upload/user/1/1-'.str_repeat('b',32).'.jpg';symlink($outside.'/image.jpg',$link);
Db::name('User')->where('user_id',1)->update(['user_portrait'=>$link]);UserPortrait::forget(1);
check(UserPortrait::url(1)==='/'.$legacy,'Symlink avatar escaped the owned local tree');
unlink($link);audit_remove_temp($outside);Db::name('User')->where('user_id',1)->update(['user_portrait'=>$original]);UserPortrait::forget(1);
UserPortrait::prefetch([1,2,4294967295,1]);
// Once prefetched, even loss of the DB connection/table cannot add per-row queries or break cached reads.
Db::execute('ALTER TABLE upload_audit_user RENAME TO upload_audit_user_reader_fixture');
try {check(UserPortrait::url(1)==='/'.$original && str_contains(UserPortrait::url(4294967295),'4294967295-'),'Prefetched portraits queried the removed table');}
finally {Db::execute('ALTER TABLE upload_audit_user_reader_fixture RENAME TO upload_audit_user');}

require __DIR__.'/fixtures/security_audit_avatar_reads.php';

// Workers use the same actual database and upload tree, never the application entry/bootstrap.
$processConfig=$configuration;
if (!$mysql) {
    $database=ROOT_PATH.'avatar-process.sqlite';
    Db::execute('VACUUM INTO ?',[$database]);
    $processConfig['connections']['upload']['database']=$database;
}
file_put_contents(ROOT_PATH.'avatar-process.json',json_encode($processConfig,JSON_THROW_ON_ERROR));
$processDb=$mysql ? Db::connect() : Db::connect($processConfig['connections']['upload']);
function avatarWorker(string $case): array {
    $prefix=ROOT_PATH.'worker-'.bin2hex(random_bytes(6));
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/security_audit_avatar_worker.php',ROOT_PATH,$case,$prefix],
        [0=>['pipe','r'],1=>['file',$prefix.'.out','w'],2=>['file',$prefix.'.err','w']],$pipes);
    if (!is_resource($process))throw new RuntimeException('Cannot start avatar worker');
    fclose($pipes[0]); return [$process,$prefix];
}
function avatarWait(array $worker): array {
    [$process,$prefix]=$worker;$deadline=microtime(true)+10;
    while (!is_file($prefix.'.ready') && microtime(true)<$deadline && proc_get_status($process)['running']) {usleep(10000);clearstatcache();}
    check(is_file($prefix.'.ready'),'Worker never reached controlled fault: '.file_get_contents($prefix.'.err').' '.file_get_contents($prefix.'.out'));
    return json_decode(file_get_contents($prefix.'.ready'),true,512,JSON_THROW_ON_ERROR);
}
foreach (['published','before-commit','after-commit'] as $case) {
    $before=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    $count=count($processDb->name('Annex')->select()->toArray());$worker=avatarWorker($case);$event=avatarWait($worker);
    $visible=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    check($case==='after-commit' ? $visible===$event['path'] : $visible===$before,'Concurrent reader observed an uncommitted avatar pointer');
    check(is_file($visible) && getimagesize($visible)[2]===IMAGETYPE_JPEG,'Concurrent reader lost its complete JPEG');
    proc_terminate($worker[0],9);proc_close($worker[0]);
    $after=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    check($after===$visible && count($processDb->name('Annex')->select()->toArray())===$count+($case==='after-commit'?1:0),'Killed process split User and Annex commit');
    check(is_file($event['stage'].'/manifest.json') && is_file($before),'Killed process lost recovery evidence or an old cached avatar');
    audit_remove_temp($event['stage']);
}
foreach (['throw-before','throw-after','permissions'] as $case) {
    $before=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    $count=count($processDb->name('Annex')->select()->toArray());$worker=avatarWorker($case);
    check(proc_close($worker[0])===0,'Failure worker escaped a controlled error');
    $payload=json_decode(file_get_contents($worker[1].'.out'),true,512,JSON_THROW_ON_ERROR);
    check($payload['code']===0,'Uncertain commit/permission failure returned success');
    $after=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
    check(count($processDb->name('Annex')->select()->toArray())===$count+($case==='throw-after'?1:0)
        && ($case==='throw-after' ? $after===$payload['event']['path'] : $after===$before), 'Commit failure split User/Annex state');
    check(is_file($before) && is_file($after),'Commit failure deleted the old or possibly committed avatar');
    if ($case!=='permissions') {
        $event=$payload['event'];$manifest=json_decode(file_get_contents($event['stage'].'/manifest.json'),true,512,JSON_THROW_ON_ERROR);
        check($manifest['state']==='commit_outcome_unknown' && $manifest['avatar_owner']===1 && is_file($event['path']), 'Ambiguous commit lost its owner evidence or possibly referenced file');
        audit_remove_temp($event['stage']);
    }
}

// Two writers for the same owner: an in-flight transaction cannot overwrite another writer's file.
$before=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
$count=count($processDb->name('Annex')->select()->toArray());$first=avatarWorker('before-commit');$event=avatarWait($first);$second=avatarWorker('normal');
file_put_contents($first[1].'.release','continue');
check(proc_close($first[0])===0,'First concurrent upload failed');$secondCode=proc_close($second[0]);
$one=json_decode(file_get_contents($first[1].'.out'),true,512,JSON_THROW_ON_ERROR);
$two=json_decode(file_get_contents($second[1].'.out'),true,512,JSON_THROW_ON_ERROR);
check(($one['code']??0)===1 && in_array($two['code']??null,[0,1],true) && $secondCode===0,'Concurrent worker escaped a controlled result');
check(!$mysql || $two['code']===1,'MySQL row lock did not serialize both normal uploads');
$selected=$processDb->name('User')->where('user_id',1)->select()->toArray()[0]['user_portrait'];
check($selected===($two['code']===1?$two['file']:$one['file']) && is_file($selected),'Concurrent final pointer does not select the last committed complete file');
check(count($processDb->name('Annex')->select()->toArray())===$count+1+($two['code']===1?1:0) && is_file($before) && is_file($one['file']),'Concurrent operation deleted an old or committed avatar');
$process=proc_open([PHP_BINARY,__DIR__.'/fixtures/security_audit_avatar_subdirectory.php'],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
check(proc_close($process)===0 && str_contains($output,'Avatar subdirectory: 18 checks passed'),'Subdirectory cookie/permission regression failed: '.$output.' '.$errors);
printf("Avatar consistency: %d checks passed on PHP %s (%s)\n",$checks,PHP_VERSION,$mysql?'MySQL':'SQLite');
