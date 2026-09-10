<?php
/** New opt-in storage contract; existing callers are separately verified by the legacy adapter suite. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_storage_providers.php';
require __DIR__.'/fixtures/security_audit_storage_intent_db.php';
use app\common\util\StoragePublicUrl;
use app\common\util\StorageIntent;
use app\common\util\StorageTransfer;
use think\facade\Db;

foreach (['s3','upyun','qiniu','ftp'] as $provider) {
    foreach (['success','false','null','throw',...($provider==='upyun'?['array','202']:[]),...($provider==='s3'?['202']:[]),
        ...($provider==='qiniu'?['wrong-key','wrong-size','missing-hash']:[])] as $case) {
        $GLOBALS['storage_provider_mode']=$case;
        // The real FTP wrapper caches failures per connection; isolate each test's configured destination.
        $GLOBALS['config']['upload']['api']['ftp']['host']=$case;
        $policy=StoragePublicUrl::current($provider);$path=storageFile($provider);
        $intent=StorageIntent::prepare($path,$policy);$source=StorageIntent::source($path);
        $calls=$GLOBALS['storage_provider_calls'];$result=StorageTransfer::attempt($intent['intent_id']);
        check($GLOBALS['storage_provider_calls']===$calls+1,'New transfer did not invoke exactly one provider');
        check(is_file($path) && StorageIntent::source($path)===$source,'Strict transfer eagerly deleted or changed its local source');
        $record=StorageIntent::inspect($intent['intent_id']);
        check($record['reference_state']==='pending' && $record['annex_id']==0,'Provider acknowledgement falsely committed a business reference');
        if ($case==='success') {
            check($result['outcome']==='remote' && $result['file']===$policy->expected($path) && $record['transfer_state']==='remote_confirmed','Valid SDK upload did not produce a trusted remote result');
        } else {
            check($result['outcome']==='local_fallback' && $result['file']===$path && !$result['remote_confirmed'] && $record['transfer_state']==='outcome_unknown','Invalid/failed SDK reply did not retain a local fallback');
        }
        check(!str_contains(json_encode($record),'fixture-secret') && !str_contains(json_encode($record),'secret-bearing'),'Intent stored credentials/provider exception text');
        storageRejected(fn()=>StorageTransfer::attempt($intent['intent_id']),'Already attempted operation replay');
    }
}
$GLOBALS['storage_provider_mode']='success';
$policy=StoragePublicUrl::current('upyun');
foreach (['https://other.invalid/a','https://objects.fixture.invalid.evil/files/a','https://user:pass@objects.fixture.invalid/files/a',
    'javascript:alert(1)','https://objects.fixture.invalid/files/../elsewhere','https://objects.fixture.invalid/files/%2e%2e/elsewhere',
    "https://objects.fixture.invalid/files/a\r\nX:1",'https://objects.fixture.invalid/files/a?signature=secret',
    'https://objects.fixture.invalid/files/a#fragment','https://objects.fixture.invalid/files/%2fother',
    'https://objects.fixture.invalid/files/"onload=alert(1)',"https://objects.fixture.invalid/files/'x",'https://objects.fixture.invalid/files/<x>'] as $url) {
    check(!StoragePublicUrl::validUrl($url) || !$policy->accepts($url,'upload/vod/a.txt'),'Untrusted public URL passed destination policy');
}
$link='upload/vod/symlink.txt';symlink(storageFile(),$link);
storageRejected(fn()=>StorageIntent::prepare($link,$policy),'Symbolic source');unlink($link);
foreach (['upload/vod/../secret','upload/vod/.hidden','upload/vod/a/../../x','/upload/vod/a','php://filter','upload//a'] as $bad) {
    storageRejected(fn()=>StorageIntent::prepare($bad,$policy),'Invalid source path');
}
$settings=$GLOBALS['config']['upload']['api']['alibaba'];unset($settings['public_url_prefix']);
storageRejected(fn()=>StoragePublicUrl::configured('alibaba',$settings),'Unconfigured image service prefix');
$imagePolicy=StoragePublicUrl::current('alibaba');
check($imagePolicy->accepts('https://images.fixture.invalid/objects/server-random.jpg','upload/vod/a.jpg')
    && !$imagePolicy->accepts('https://images.fixture.invalid/objectsevil/a.jpg','upload/vod/a.jpg'),'Image service prefix matched the wrong URL scope');

// ORM and raw PDO outer transactions cannot hold a not-yet-durable intent across an external write.
foreach (['orm','pdo'] as $kind) {
    $path=storageFile();$row=StorageIntent::prepare($path,$policy);$another=storageFile();
    if ($kind==='orm')Db::startTrans();else Db::connect()->getPdo()->beginTransaction();
    try {
        storageRejected(fn()=>StorageIntent::prepare($another,$policy),'Outer '.$kind.' create');
        storageRejected(fn()=>StorageTransfer::attempt($row['intent_id']),'Outer '.$kind.' claim');
    } finally {if($kind==='orm')Db::rollback();else Db::connect()->getPdo()->rollBack();}
    check(StorageIntent::inspect($row['intent_id'])['transfer_state']==='prepared','Rejected outer transaction changed a durable intent');
}
$path=storageFile();$row=StorageIntent::prepare($path,$policy);
file_put_contents($path,'changed');storageRejected(fn()=>StorageTransfer::attempt($row['intent_id']),'Changed staged source');
$path=storageFile();$row=StorageIntent::prepare($path,$policy);
$GLOBALS['config']['upload']['api']['upyun']['url']='https://changed.fixture.invalid';
storageRejected(fn()=>StorageTransfer::attempt($row['intent_id']),'Changed configured destination');
$GLOBALS['config']['upload']['api']['upyun']['url']='https://objects.fixture.invalid/files';
$path=storageFile();$row=StorageIntent::prepare($path,$policy);
$GLOBALS['storage_provider_callback']=static function () use($path):void {file_put_contents($path,'different bytes');};
try {$result=StorageTransfer::attempt($row['intent_id']);}finally{unset($GLOBALS['storage_provider_callback']);}
check($result['outcome']==='unavailable' && $result['file']===null && !$result['remote_confirmed'],'Changed source was returned as verified remote content');
check(StorageIntent::inspect($row['intent_id'])['result_code']==='source_changed','Changed source lost the transfer outcome evidence');

// Real DB failures after the provider call leave the independently committed pre-call attempt.
$path=storageFile();$row=StorageIntent::prepare($path,$policy);
$GLOBALS['storage_provider_callback']=static function ():void {
    Db::execute($GLOBALS['mysql']
        ? "CREATE TRIGGER storage_result_fault BEFORE UPDATE ON storage_audit_storage_intent FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='controlled receipt failure'"
        : "CREATE TRIGGER storage_result_fault BEFORE UPDATE ON storage_audit_storage_intent BEGIN SELECT RAISE(ABORT,'controlled receipt failure'); END");
};
try {$result=StorageTransfer::attempt($row['intent_id']);}finally{unset($GLOBALS['storage_provider_callback']);Db::execute('DROP TRIGGER storage_result_fault');}
check($result['outcome']==='unrecorded' && $result['file']===$path && is_file($path),'Lost result persistence discarded the local fallback');
check(StorageIntent::inspect($row['intent_id'])['transfer_state']==='attempting','Business DB failure lost its initial durable intent');

// Reference status shares the business transaction and requires an exact actual Annex reference.
$path=storageFile();$row=StorageIntent::prepare($path,$policy);$remote=StorageTransfer::attempt($row['intent_id']);
storageRejected(fn()=>StorageIntent::recordReferences([$row['intent_id']=>1]),'Reference recording without business transaction');
Db::startTrans();
try {
    $id=Db::name('Annex')->insertGetId(['annex_file'=>$remote['file'],'annex_type'=>'file','annex_size'=>filesize($path),'annex_time'=>time()]);
    StorageIntent::recordReferences([$row['intent_id']=>$id]);
    check(StorageIntent::inspect($row['intent_id'])['reference_state']==='committed','Valid reference not recorded in caller transaction');
} finally {Db::rollback();}
check(StorageIntent::inspect($row['intent_id'])['reference_state']==='pending' && Db::name('Annex')->count()===0,'Business rollback lost intent or retained a false reference');
Db::startTrans();
try {
    $id=Db::name('Annex')->insertGetId(['annex_file'=>$remote['file'],'annex_type'=>'file','annex_size'=>filesize($path),'annex_time'=>time()]);
    StorageIntent::recordReferences([$row['intent_id']=>$id]);Db::commit();
} catch(Throwable $error){Db::rollback();throw $error;}
check(StorageIntent::inspect($row['intent_id'])['reference_state']==='committed' && is_file($path),'Reference confirmation unexpectedly deleted the source');

// Invalid references cannot promote a transfer; valid local fallback remains supported.
foreach (['wrong-file','wrong-size','wrong-type','not-attempted'] as $fault) {
    $path=storageFile();$row=StorageIntent::prepare($path,$policy);
    if($fault!=='not-attempted')StorageTransfer::attempt($row['intent_id']);
    Db::startTrans();
    try {
        $id=Db::name('Annex')->insertGetId(['annex_file'=>$fault==='wrong-file'?'upload/vod/other.txt':$path,
            'annex_size'=>filesize($path)+($fault==='wrong-size'?1:0),'annex_type'=>$fault==='wrong-type'?'bad':'file','annex_time'=>time()]);
        storageRejected(fn()=>StorageIntent::recordReferences([$row['intent_id']=>$id]),'Invalid reference '.$fault);
    } finally {Db::rollback();}
}
$path=storageFile();$row=StorageIntent::prepare($path,$policy);$GLOBALS['storage_provider_mode']='throw';
try {$fallback=StorageTransfer::attempt($row['intent_id']);}finally{$GLOBALS['storage_provider_mode']='success';}
Db::startTrans();
try {
    $id=Db::name('Annex')->insertGetId(['annex_file'=>$path,'annex_size'=>filesize($path),'annex_type'=>'file','annex_time'=>time()]);
    StorageIntent::recordReferences([$row['intent_id']=>$id]);Db::commit();
} catch(Throwable $error){Db::rollback();throw $error;}
check($fallback['outcome']==='local_fallback' && StorageIntent::inspect($row['intent_id'])['reference_state']==='committed','Real local fallback could not commit its actual attachment');
$path='upload/user/1/1-'.bin2hex(random_bytes(16)).'.jpg';file_put_contents($path,'prepared avatar fixture');
$avatar=StorageIntent::prepare($path,$policy,'avatar',1);StorageTransfer::attempt($avatar['intent_id']);
Db::startTrans();
try {
    $id=Db::name('Annex')->insertGetId(['annex_file'=>$path,'annex_size'=>filesize($path),'annex_type'=>'image','annex_time'=>time()]);
    storageRejected(fn()=>StorageIntent::recordReferences([$avatar['intent_id']=>$id]),'Avatar pointer does not select this object');
    Db::name('User')->where('user_id',1)->update(['user_portrait'=>$path]);
    StorageIntent::recordReferences([$avatar['intent_id']=>$id]);Db::commit();
} catch(Throwable $error){Db::rollback();throw $error;}
check(StorageIntent::inspect($avatar['intent_id'])['reference_state']==='committed','Actual User and Annex pointer could not commit together');
storageRejected(fn()=>StorageIntent::prepare(storageFile(),$policy,'avatar',1),'Avatar source is not owned by its declared user');

// Production DDL must reject clipping and nontransactional intent storage under permissive MySQL.
if ($mysql) {
    foreach (['Annex','User'] as $table) {
        Db::execute('ALTER TABLE storage_audit_'.strtolower($table).' ENGINE=MyISAM');
        $path='upload/user/1/1-'.bin2hex(random_bytes(16)).'.jpg';file_put_contents($path,'prepared avatar fixture');
        $guard=StorageIntent::prepare($path,$policy,'avatar',1);StorageTransfer::attempt($guard['intent_id']);
        // Create references before opening the transaction; the guard must reject any nontransactional participant.
        $id=Db::name('Annex')->insertGetId(['annex_file'=>$path,'annex_size'=>filesize($path),'annex_type'=>'image','annex_time'=>time()]);
        Db::name('User')->where('user_id',1)->update(['user_portrait'=>$path]);
        Db::startTrans();
        try {storageRejected(fn()=>StorageIntent::recordReferences([$guard['intent_id']=>$id]),'MyISAM reference '.$table);}
        finally {Db::rollback();Db::execute('ALTER TABLE storage_audit_'.strtolower($table).' ENGINE=InnoDB');}
    }
    Db::execute('ALTER TABLE storage_audit_storage_intent MODIFY result_code VARCHAR(2) NOT NULL DEFAULT ""');
    $path=storageFile();$row=StorageIntent::prepare($path,$policy);$result=StorageTransfer::attempt($row['intent_id']);
    check($result['outcome']==='unrecorded' && StorageIntent::inspect($row['intent_id'])['transfer_state']==='attempting','Non-strict clipped receipt was treated as durable');
    check($migration->preflight()['blockers']!==[],'Incompatible receipt column passed migration preflight');
    storageRejected(fn()=>$migration->apply(),'Incompatible migration apply');
    Db::execute('ALTER TABLE storage_audit_storage_intent MODIFY result_code VARCHAR(32) NOT NULL DEFAULT ""');
    Db::execute('ALTER TABLE storage_audit_storage_intent ENGINE=MyISAM');
    storageRejected(fn()=>StorageIntent::prepare(storageFile(),$policy),'MyISAM intent table');
    Db::execute('ALTER TABLE storage_audit_storage_intent ENGINE=InnoDB');
    Db::startTrans();try{storageRejected(fn()=>$migration->apply(),'Migration implicit outer commit');}finally{Db::rollback();}
    check($migration->apply()['changes']===[],'Idempotent migration changed existing receipts');
    require __DIR__.'/fixtures/security_audit_storage_migration.php';
}
foreach (['before-create','after-create','before-claim','after-claim','before-result','after-result'] as $case) {
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/security_audit_storage_commit.php',$case],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    $code=proc_close($process);$payload=json_decode($output,true);
    check($code===0 && ($payload['checks']??0)===4 && ($payload['case']??null)===$case,'COMMIT worker failed: '.$case.' '.$output.' '.$errors);
}
require __DIR__.'/fixtures/security_audit_storage_concurrency.php';
printf("Storage intent foundation: %d checks passed on PHP %s (%s)\n",$checks,PHP_VERSION,$mysql?'MySQL':'SQLite');
