<?php
/** Downloaded asset catalog: ordinary images, real processing/ORM, isolated source/provider transports. */
declare(strict_types=1);
require __DIR__.'/fixtures/download_asset_io.php';
require __DIR__.'/fixtures/security_audit_remote_upload_db.php';
use app\common\model\Image;
use app\common\util\StorageObjectUrl;
use think\facade\Db;
$fixtureRoot=dirname(__DIR__);uploadIdentityRequest([], 'GET', false);
$GLOBALS['download_asset_calls']=0;$GLOBALS['download_asset_bytes']=[];
$downloadUrl='https://1.1.1.1/ordinary-picture.jpg';
$baseConfig=['mode'=>'local','keep_local'=>0,'thumb'=>1,'thumb_size'=>'10x10,20x20','thumb_type'=>1,'watermark'=>0];
function downloadAsset(array $changes=[],string $flag='vod') {
    return (new Image())->down_load($GLOBALS['downloadUrl'],array_replace($GLOBALS['baseConfig'],$changes),$flag);
}
function downloadAnnex(): array { return Db::name('Annex')->order('annex_id')->select()->toArray(); }
function downloadNew(array $old): array { return array_values(array_filter(downloadAnnex(),static fn($row)=>!in_array($row['annex_id'],array_column($old,'annex_id'),true))); }
function downloadManifests(): array {
    $found=[];foreach(glob(sys_get_temp_dir().'/maccms-attachment-*') as $stage) {
        $data=@json_decode((string)@file_get_contents($stage.'/manifest.json'),true);
        if(is_array($data)&&($data['root']??null)===realpath(ROOT_PATH))$found[$stage]=$data;
    }return $found;
}
function downloadFailed(array $config=[],string $reason=''): void {
    $before=uploadIdentitySnapshot();$manifests=downloadManifests();$calls=$GLOBALS['storage_provider_calls'];
    check(downloadAsset($config)===$GLOBALS['downloadUrl'].'#err','Failed asset returned success: '.$reason);
    check(uploadIdentitySnapshot()===$before,'Failed local preparation/metadata changed files or DB: '.$reason);
    check(downloadManifests()===$manifests&&$GLOBALS['storage_provider_calls']===$calls,'Failed pre-transfer operation leaked evidence or called provider: '.$reason);
}
$canvas=imagecreatetruecolor(90,70);
for($x=0;$x<90;$x++)for($y=0;$y<70;$y++)imagesetpixel($canvas,$x,$y,imagecolorallocate($canvas,($x*7+$y)%256,($y*11+$x)%256,($x+$y*13)%256));
imagepng($canvas,'ordinary.png');imagejpeg($canvas,'ordinary.jpg');
$samples=['png'=>file_get_contents('ordinary.png'),'jpg'=>file_get_contents('ordinary.jpg'),
    'gif'=>file_get_contents($fixtureRoot.'/tests/fixtures/image-processing/animation.gif'),
    'webp'=>file_get_contents($fixtureRoot.'/tests/fixtures/image-processing/static.webp')];
$types=['png'=>IMAGETYPE_PNG,'jpg'=>IMAGETYPE_JPEG,'gif'=>IMAGETYPE_GIF,'webp'=>IMAGETYPE_WEBP];
$oldUser=Db::name('User')->order('user_id')->select()->toArray();$oldImage=file_get_contents('upload/user/1/1.jpg');
foreach($samples as $extension=>$bytes)foreach(['local','remote','s3'] as $mode) {
    $GLOBALS['download_asset_bytes'][$downloadUrl]=$bytes;$GLOBALS['storage_provider_mode']='success';
    $before=downloadAnnex();$calls=$GLOBALS['storage_provider_calls'];$result=downloadAsset(['mode'=>$mode]);$rows=downloadNew($before);
    check(is_string($result)&&!str_ends_with($result,'#err')&&count($rows)===3,'Normal format did not publish every derivative: '.$extension.'/'.$mode);
    check($GLOBALS['storage_provider_calls']===$calls+($mode==='s3'?3:0),'Local sentinel/provider call contract changed');
    foreach($rows as $index=>$row) {
        $path=$row['annex_file'];$intent=Db::name('StorageIntent')->where('local_path',$path)->find();
        $actual=$mode==='s3'?'remote-fixture/'.$intent['intent_id']:$path;
        check(pathinfo($path,PATHINFO_EXTENSION)===$extension&&getimagesize($actual)[2]===$types[$extension],'Filename inferred from URL instead of decoded image');
        check((int)$row['annex_size']===filesize($actual)&&$row['annex_type']==='image','Final derivative byte metadata differs');
        if($index===0)check($result===($mode==='s3'?$intent['remote_url']:$path),'Returned string does not select the actual stored asset');
        if($mode==='s3') {
            check($intent['scope']==='download'&&(int)$intent['owner_id']===0&&$intent['reference_state']==='committed'&&(int)$intent['annex_id']===(int)$row['annex_id'],'Asset reference did not commit with download intent');
            check(!is_file($path)&&(int)$intent['source_bytes']===(int)$row['annex_size'],'Confirmed remote cleanup or final bytes differ');
        } else { check($intent===null&&is_file($path),'Local mode created remote attempts or lost local data'); }
        if($extension==='gif') {
            $expected=new Imagick();$expected->readImageBlob($bytes);$actualGif=new Imagick($actual);
            check($actualGif->getNumberImages()===$expected->getNumberImages()&&$actualGif->getImageIterations()===$expected->getImageIterations(),'GIF frames or loop were lost');
            $delays=[];foreach($actualGif as $frame)$delays[]=$frame->getImageDelay();$expectedDelays=[];foreach($expected as $frame)$expectedDelays[]=$frame->getImageDelay();
            check($delays===$expectedDelays,'GIF delay changed during download/thumbnail preparation');$expected->clear();$actualGif->clear();
        }
    }
    check(downloadManifests()===[],'Committed download retained private stage files');
}
check(Db::name('User')->order('user_id')->select()->toArray()===$oldUser&&file_get_contents('upload/user/1/1.jpg')===$oldImage,'Content download changed user metadata or old avatar');
$GLOBALS['download_asset_bytes'][$downloadUrl]=$samples['png'];
$watermark=['watermark'=>1,'watermark_content'=>'Sample','watermark_font'=>$fixtureRoot.'/static/font/test.ttf','watermark_size'=>12,'watermark_color'=>'#00000000','watermark_location'=>5];
foreach(['local','s3'] as $mode) {
    $before=downloadAnnex();$result=downloadAsset($watermark+['mode'=>$mode]);$rows=downloadNew($before);
    check(!str_ends_with($result,'#err')&&count($rows)===3,'Watermarked derivative set failed');
    foreach($rows as $row) {
        $intent=Db::name('StorageIntent')->where('local_path',$row['annex_file'])->find();$file=$mode==='s3'?'remote-fixture/'.$intent['intent_id']:$row['annex_file'];
        check(filesize($file)===(int)$row['annex_size'],'Watermark bytes were recorded before processing');
    }
    $main=$mode==='s3'?'remote-fixture/'.Db::name('StorageIntent')->where('local_path',$rows[0]['annex_file'])->value('intent_id'):$result;
    check(hash_file('sha256',$main)!==hash('sha256',$samples['png']),'Watermark was silently omitted');
}
foreach(['false','throw','mixed'] as $mode) {
    $calls=$GLOBALS['storage_provider_calls'];$before=downloadAnnex();
    $GLOBALS['remote_provider_hook']=static function()use($mode,$calls):void{$GLOBALS['storage_provider_mode']=$mode==='mixed'?($GLOBALS['storage_provider_calls']===$calls+2?'false':'success'):$mode;};
    try{$result=downloadAsset(['mode'=>'s3']);}finally{unset($GLOBALS['remote_provider_hook']);$GLOBALS['storage_provider_mode']='success';}
    $rows=downloadNew($before);check(!str_ends_with($result,'#err')&&count($rows)===3,'Provider failure lost local fallback');
    foreach($rows as $index=>$row) {
        $intent=Db::name('StorageIntent')->where('local_path',$row['annex_file'])->find();$remote=$intent['transfer_state']==='remote_confirmed';
        check($intent['reference_state']==='committed'&&is_file($row['annex_file'])===!$remote,'Mixed outcome removed an unconfirmed local replica');
        if($index===0)check($result===($remote?$intent['remote_url']:$row['annex_file']),'Primary fallback string was wrong');
    }
}
$before=downloadAnnex();$result=downloadAsset(['mode'=>'s3','keep_local'=>1]);
check(!str_ends_with($result,'#err')&&count(downloadNew($before))===3,'keep_local=1 changed the remote success contract');
foreach(downloadNew($before) as $row)check(is_file($row['annex_file']),'keep_local=1 lost a processed replica');
$before=downloadAnnex();$calls=$GLOBALS['storage_provider_calls'];$result=downloadAsset(['mode'=>'unconfigured']);
check(is_file($result)&&count(downloadNew($before))===3&&$GLOBALS['storage_provider_calls']===$calls,'Non-applicable target did not preserve local behavior');
// Also check the whole set when only a derivative would exceed the resource field.
$domain=$GLOBALS['config']['upload']['api']['s3']['domain'];
$logical='upload/vod/'.date('Ymd').'-1/'.str_repeat('a',32).'.png';
$length=strlen(app\common\util\StoragePublicUrl::current('s3')->expected($logical));
$GLOBALS['config']['upload']['api']['s3']['domain']=$domain.'/'.str_repeat('t',1019-$length-1);
check(strlen(app\common\util\StoragePublicUrl::current('s3')->expected($logical))===1019,'Derivative-length fixture setup changed');
$before=downloadAnnex();$calls=$GLOBALS['storage_provider_calls'];$result=downloadAsset(['mode'=>'s3']);
check(is_file($result)&&count(downloadNew($before))===3&&$GLOBALS['storage_provider_calls']===$calls,'A fitting primary URL started SDK calls before checking its oversized derivative');
$GLOBALS['config']['upload']['api']['s3']['domain']=$domain;
// Precomputed destinations too large for resource fields never reach any provider.
$domain=$GLOBALS['config']['upload']['api']['s3']['domain'];$GLOBALS['config']['upload']['api']['s3']['domain']='https://objects.fixture.invalid/'.str_repeat('a',1000);
$before=downloadAnnex();$calls=$GLOBALS['storage_provider_calls'];$result=downloadAsset(['mode'=>'s3']);
check(is_file($result)&&count(downloadNew($before))===3&&$GLOBALS['storage_provider_calls']===$calls,'Predicted oversized resource URL reached provider or lost local fallback');
foreach(downloadNew($before) as $row)check(Db::name('StorageIntent')->where('local_path',$row['annex_file'])->count()===0,'Oversized destination partially prepared remote attempts');
$GLOBALS['config']['upload']['api']['s3']['domain']=$domain;
// A random image-service receipt can be valid for Annex yet too long for resource columns.
$GLOBALS['download_asset_image_url']='https://images.fixture.invalid/objects/'.str_repeat('b',1100).'.png';
$before=downloadAnnex();$result=downloadAsset(['mode'=>'uomg']);$rows=downloadNew($before);
check(is_file($result)&&count($rows)===3,'Long attested random URL was returned to a limited resource field');
$listed=(new app\common\model\Annex())->listData([['annex_id','in',array_column($rows,'annex_id')]],'annex_id asc')['list'];
foreach($rows as $index=>$row) {
    $intent=Db::name('StorageIntent')->where('local_path',$row['annex_file'])->find();
    check($intent['remote_url']===$GLOBALS['download_asset_image_url']&&$intent['reference_state']==='committed'&&is_file($row['annex_file']),'Long remote receipt was discarded or its needed source deleted');
    check($listed[$index]['annex_url']===$intent['remote_url'],'Annex cannot display the attested long URL');
}
unset($GLOBALS['download_asset_image_url']);
// Only this new set is affected when remote intent storage is unavailable or preparation stops partway.
Db::execute('ALTER TABLE upload_audit_storage_intent RENAME TO upload_audit_storage_saved');
try{$before=downloadAnnex();$calls=$GLOBALS['storage_provider_calls'];$result=downloadAsset(['mode'=>'s3']);check(is_file($result)&&count(downloadNew($before))===3&&$GLOBALS['storage_provider_calls']===$calls,'Missing intent table did not fall back before any SDK');}
finally{Db::execute('ALTER TABLE upload_audit_storage_saved RENAME TO upload_audit_storage_intent');}
$trigger=$mysql?"CREATE TRIGGER download_prepare BEFORE INSERT ON upload_audit_storage_intent FOR EACH ROW BEGIN IF NEW.local_path LIKE '%_10x10.png' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture unavailable'; END IF; END"
    :"CREATE TRIGGER download_prepare BEFORE INSERT ON upload_audit_storage_intent WHEN NEW.local_path LIKE '%_10x10.png' BEGIN SELECT RAISE(ABORT,'fixture unavailable'); END";
Db::execute($trigger);
try{$before=downloadAnnex();$calls=$GLOBALS['storage_provider_calls'];$result=downloadAsset(['mode'=>'s3']);check(is_file($result)&&count(downloadNew($before))===3&&$GLOBALS['storage_provider_calls']===$calls,'Partial preparation started an external batch');}
finally{Db::execute('DROP TRIGGER download_prepare');}
foreach(['ordinary incomplete image','',false] as $bytes) {$GLOBALS['download_asset_bytes'][$downloadUrl]=$bytes;downloadFailed(['mode'=>'s3'],'unavailable/incomplete image');}
$GLOBALS['download_asset_bytes'][$downloadUrl]=$samples['png'];
downloadFailed(['thumb_size'=>'10x10,missing'],'unfinished thumbnail set');
downloadFailed(array_replace($watermark,['watermark_font'=>'/missing-fixture-font.ttf']),'missing watermark font');
foreach(['short-write','second-publish','corrupt-write'] as $fault) {$GLOBALS['attachment_io_fault']=$fault;$GLOBALS['attachment_publish_count']=0;try{downloadFailed(['mode'=>'s3'],'publication');}finally{unset($GLOBALS['attachment_io_fault']);}}
foreach(['orm','raw'] as $outer) {
    if($outer==='orm')Db::startTrans();else Db::connect()->getPdo()->beginTransaction();
    try{downloadFailed(['mode'=>'s3'],'existing '.$outer.' transaction');check(Db::connect()->getPdo()->inTransaction(),'Download rolled back the caller transaction');}
    finally{if($outer==='orm')Db::rollback();else Db::connect()->getPdo()->rollBack();}
}
$calls=$GLOBALS['download_asset_calls'];foreach(['user','covers/set'] as $flag)check(downloadAsset([],$flag)===$downloadUrl.'#err','Reserved/non-resource flag was accepted');
check($GLOBALS['download_asset_calls']===$calls,'Rejected flag downloaded bytes');
check((new Image())->down_load('upload/vod/existing.png',$baseConfig)==='upload/vod/existing.png','Existing local string was downloaded again');
$originalUrl=$downloadUrl;$downloadUrl='http://1.1.1.1/ordinary-image';$GLOBALS['download_asset_bytes'][$downloadUrl]=$samples['jpg'];
$before=downloadAnnex();$result=downloadAsset(['thumb'=>0]);
check(is_file($result)&&pathinfo($result,PATHINFO_EXTENSION)==='jpg'&&count(downloadNew($before))===1,'HTTP image without suffix or disabled thumbnails changed its contract');
$downloadUrl=$originalUrl;
require __DIR__.'/fixtures/download_asset_failures.php';
// Ordinary existing entrypoints still use the same service without the internal download scope.
foreach(['local','s3'] as $mode)foreach([true,false] as $admin) {
    if($admin)uploadIdentityAdmin();else uploadIdentityMember();remoteUploadConfig(['mode'=>$mode]);
    $before=downloadAnnex();$result=remoteUploadAttempt([],$admin);$rows=downloadNew($before);
    check(($result['code']??null)===1&&count($rows)===($admin?3:1),'Ordinary manual/avatar regression failed');
    foreach($rows as $row) {
        $intent=Db::name('StorageIntent')->where('local_path',$row['annex_file'])->find();
        check($mode==='local'?$intent===null:$intent['scope']===($admin?'attachment':'avatar'),'New download scope changed a manual/avatar intent');
    }
}
foreach(['permissions','commit-before','commit-after','remote-commit-before','remote-commit-after'] as $case) {
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/download_asset_worker.php',$case],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    check(proc_close($process)===0,'Ordinary download worker failed: '.$case.' '.$errors.' '.$output);
    $reported=json_decode($output,true,512,JSON_THROW_ON_ERROR);check(($reported['result']??null)==='passed'&&($reported['case']??null)===$case,'Worker did not confirm its fixture outcome');
}
echo 'Downloaded asset catalog: '.$checks.' checks passed on PHP '.PHP_VERSION.' ('.($mysql?'MySQL':'SQLite').")\n";
