<?php
/** Local staging/publication + real Annex transactions and adverse SQLite/MySQL storage. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_upload_identity_db.php';
require __DIR__.'/fixtures/security_audit_local_attachment_io.php';
use app\common\model\Upload;
use think\facade\Db;
use think\facade\Config;

function attachmentConfig(array $changes = []): void {
    Config::set(['site'=>['install_dir'=>'/'], 'upload'=>array_merge(['mode'=>'local','thumb'=>1,
        'thumb_size'=>'10x10,20x20','thumb_type'=>1,'watermark'=>0],$changes)],'maccms');
}
function attachmentDenied(callable $call, string $message): void {
    $before=uploadIdentitySnapshot();
    $stages=glob(sys_get_temp_dir().'/maccms-attachment-*');sort($stages);
    $result=$call();
    check($result['code']===0, $message.' returned success');
    check(uploadIdentitySnapshot()===$before, $message.' changed existing metadata/files or left a partial upload');
    $after=glob(sys_get_temp_dir().'/maccms-attachment-*');sort($after);
    check($after===$stages, $message.' leaked a staging directory');
}
function attachmentAttempt(array $parameters=[]): array {
    uploadIdentityRequest(array_merge(['flag'=>'vod','thumb'=>'1'],$parameters));
    return (new Upload())->upload([],true);
}
function attachmentTrigger(string $kind): void {
    if ($GLOBALS['mysql']) {
        $sql=match($kind) {
            'reject'=>"CREATE TRIGGER attachment_fault BEFORE INSERT ON upload_audit_annex FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture failure'",
            'second'=>"CREATE TRIGGER attachment_fault BEFORE INSERT ON upload_audit_annex FOR EACH ROW BEGIN IF NEW.annex_file LIKE '%_10x10.png' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture derivative failure'; END IF; END",
            'mutate'=>"CREATE TRIGGER attachment_fault BEFORE INSERT ON upload_audit_annex FOR EACH ROW SET NEW.annex_size = NEW.annex_size + 1",
        };
    } else {
        $sql=match($kind) {
            'reject'=>"CREATE TRIGGER attachment_fault BEFORE INSERT ON upload_audit_annex BEGIN SELECT RAISE(ABORT, 'fixture failure'); END",
            'second'=>"CREATE TRIGGER attachment_fault BEFORE INSERT ON upload_audit_annex WHEN NEW.annex_file LIKE '%_10x10.png' BEGIN SELECT RAISE(ABORT, 'fixture derivative failure'); END",
            'mutate'=>"CREATE TRIGGER attachment_fault AFTER INSERT ON upload_audit_annex BEGIN UPDATE upload_audit_annex SET annex_size=annex_size+1 WHERE annex_id=NEW.annex_id; END",
            'ignore'=>"CREATE TRIGGER attachment_fault BEFORE INSERT ON upload_audit_annex BEGIN SELECT RAISE(IGNORE); END",
        };
    }
    Db::execute($sql);
}
uploadIdentityAdmin();attachmentConfig();
$existing=uploadIdentitySnapshot();
$before=Db::name('Annex')->count();
$result=attachmentAttempt();
check($result['code']===1,'Normal local upload failed');
$path=uploadIdentityPath($result);
$paths=[$path,$path.'_10x10.png',$path.'_20x20.png'];
check(Db::name('Annex')->count()===$before+3,'Did not register every thumbnail');
foreach($paths as $file) {
    $row=Db::name('Annex')->where('annex_file',$file)->find();
    check($row && (int)$row['annex_size']===filesize($file) && $row['annex_type']==='image','Attachment bytes/type do not match exact stored file');
    check(getimagesize($file)[2]===IMAGETYPE_PNG,'Published file is not a valid image');
}
check(uploadIdentitySnapshot()[0]===$existing[0],'Local content upload touched avatar ownership');
check(glob(sys_get_temp_dir().'/maccms-attachment-*')===[],'Success left private staging files');

// Non-image attachments retain their allowed extension contract, including an empty text file.
foreach(['report.pdf'=>"%PDF-1.4\nfixture",'clip.mp4'=>"fixture media bytes",'empty.txt'=>''] as $name=>$bytes) {
    uploadIdentityRequest(['flag'=>'vod','thumb'=>'0']);file_put_contents('incoming.png',$bytes);
    request()->withFiles(['file'=>['tmp_name'=>ROOT_PATH.'incoming.png','name'=>$name,'type'=>'application/octet-stream','error'=>UPLOAD_ERR_OK,'size'=>strlen($bytes)]]);
    $result=(new Upload())->upload([],true);$file=uploadIdentityPath($result);
    check($result['code']===1 && file_get_contents($file)===$bytes,'Normal non-image attachment changed its payload');
    $row=Db::name('Annex')->where('annex_file',$file)->find();
    check((int)$row['annex_size']===strlen($bytes),'Non-image attachment size was not stored in bytes');
}
uploadIdentityRequest(['flag'=>'vod','thumb'=>'0']);
$large=fopen('incoming.png','c');ftruncate($large,4294967296);fclose($large);
attachmentDenied(fn()=>(new Upload())->upload([],true),'Attachment exceeds actual UINT32 size column');
$outside=audit_temp_dir('attachment-outside');file_put_contents($outside.'/sentinel','unrelated');symlink($outside,'upload/linked');
try {attachmentDenied(fn()=>attachmentAttempt(['flag'=>'linked']),'Symbolic-link publication directory');
    check(file_get_contents($outside.'/sentinel')==='unrelated' && count(scandir($outside))===3,'Upload touched a directory outside its publication tree');}
finally {unlink('upload/linked');audit_remove_temp($outside);}

foreach([[],"invalid\xff"] as $prefix) {
    Config::set(['site'=>['install_dir'=>$prefix],'upload'=>['mode'=>'local','thumb'=>0,'watermark'=>0]],'maccms');
    attachmentDenied(fn()=>attachmentAttempt(),'Invalid response path configuration');
}
attachmentConfig();

// Invalid source/processing configuration must never become a public attachment.
foreach(['10x10,0x20','10x10,broken','10x10,10x10','',str_repeat('1x1,',16).'2x2'] as $sizes) {
    attachmentConfig(['thumb_size'=>$sizes]);
    attachmentDenied(fn()=>attachmentAttempt(),'Invalid/partial thumbnail set');
}
attachmentConfig(['watermark'=>1,'watermark_content'=>'required','watermark_font'=>'/missing-font.ttf']);
attachmentDenied(fn()=>attachmentAttempt(),'Required watermark failed');
attachmentConfig();
foreach(['scanner','not-image','wrong-extension','truncated-gif'] as $case) {
    uploadIdentityRequest(['flag'=>'vod','thumb'=>'0']);
    if($case==='scanner')file_put_contents('incoming.png','<script>alert(1)</script>',FILE_APPEND);
    if($case==='not-image')file_put_contents('incoming.png','not an image');
    if($case==='wrong-extension') {
        $gd=imagecreatetruecolor(10,10);imagejpeg($gd,'incoming.png');
    }
    if($case==='truncated-gif')file_put_contents('incoming.png','GIF89a'.str_repeat("\0",20));
    attachmentDenied(fn()=>(new Upload())->upload([],true),'Rejected source '.$case);
}
foreach(['reject','second','mutate'] as $kind) {
    attachmentTrigger($kind);
    try {attachmentDenied(fn()=>attachmentAttempt(),'Metadata '.$kind);}
    finally {Db::execute('DROP TRIGGER attachment_fault');}
}
if(!$mysql) {
    attachmentTrigger('ignore');
    try {attachmentDenied(fn()=>attachmentAttempt(),'Ignored insert with non-exception save response');}
    finally {Db::execute('DROP TRIGGER attachment_fault');}
} else {
    // Non-strict MySQL silently truncates the narrower column. Readback must reject it and roll back.
    Db::execute('ALTER TABLE upload_audit_annex MODIFY annex_size TINYINT UNSIGNED NOT NULL DEFAULT 0');
    $savedSource=file_get_contents('source.png');
    $noise=imagecreatetruecolor(80,60);
    for($x=0;$x<80;$x++)for($y=0;$y<60;$y++)imagesetpixel($noise,$x,$y,imagecolorallocate($noise,($x*17+$y)%256,($y*19+$x)%256,($x+$y*13)%256));
    imagepng($noise,'source.png');
    try {attachmentDenied(fn()=>attachmentAttempt(),'Non-strict clipped metadata');}
    finally {file_put_contents('source.png',$savedSource);Db::execute('ALTER TABLE upload_audit_annex MODIFY annex_size INT UNSIGNED NOT NULL DEFAULT 0');}
    Db::execute('ALTER TABLE upload_audit_annex ENGINE=MyISAM');
    try {attachmentDenied(fn()=>attachmentAttempt(),'Non-transactional metadata engine');}
    finally {Db::execute('ALTER TABLE upload_audit_annex ENGINE=InnoDB');}
}
foreach(['short-write','second-publish','corrupt-write'] as $fault) {
    $GLOBALS['attachment_io_fault']=$fault;$GLOBALS['attachment_publish_count']=0;
    try {attachmentDenied(fn()=>attachmentAttempt(),'Filesystem '.$fault);}
    finally {unset($GLOBALS['attachment_io_fault']);}
}
// A random-name collision must not overwrite/delete the existing object or its unrelated row.
$fixed=str_repeat('61',16);$collision='upload/vod/'.date('Ymd').'-1/'.$fixed.'.png';
file_put_contents($collision,'existing unrelated object');
$GLOBALS['attachment_random_fixture']='a';
try {attachmentDenied(fn()=>attachmentAttempt(),'Exclusive publication collision');}
finally {unset($GLOBALS['attachment_random_fixture']);}
check(file_get_contents($collision)==='existing unrelated object','Collision overwrote an existing file');

// The "remote access" sentinel currently stores locally; vendor and avatar policies are separate groups.
attachmentConfig(['mode'=>'remote']);
$before=Db::name('Annex')->count();$result=attachmentAttempt();
check($result['code']===1 && Db::name('Annex')->count()===$before+3,'Remote-access local mode changed its storage contract');
attachmentConfig();
uploadIdentityRequest(['flag'=>'vod','thumb'=>'1','imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))],'POST',false);
check((new Upload())->upload([],true)['code']===1,'Valid base64 local attachment failed');
uploadIdentityAdmin(',user/info,');
attachmentDenied(fn()=>attachmentAttempt(),'Missing upload permission');
uploadIdentityAdmin();uploadIdentityRequest(['flag'=>'vod','thumb'=>'1'],'POST',true,['X-CSRF-Token'=>'wrong']);
attachmentDenied(fn()=>(new Upload())->upload([],true),'Invalid CSRF');

// A surrounding transaction cannot be acknowledged before its actual owner commits.
Db::startTrans();
try {attachmentDenied(fn()=>attachmentAttempt(),'Nested transaction');}
finally {Db::rollback();}
$workers=['annex-error-before','annex-error-after','permissions','commit-before','commit-after'];
foreach(['ueditor','umeditor','ckeditor','kindeditor','tinymce'] as $editor) {
    $workers[]='editor-success-'.$editor;$workers[]='editor-failure-'.$editor;
}
foreach($workers as $worker) {
    $process=proc_open([PHP_BINARY,__DIR__.'/fixtures/security_audit_local_attachment_worker.php',$worker],
        [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);
    check(proc_close($process)===0 && str_contains($errors,'attachment worker passed: '.$worker), 'Failure/exit worker failed: '.$worker.' '.$errors.' '.$output);
    $payload=json_decode($output,true,512,JSON_THROW_ON_ERROR);
    $ok=($payload['code']??null)===1 || ($payload['state']??null)==='SUCCESS' || ($payload['uploaded']??null)===1
        || ($payload['error']??null)===0 || isset($payload['location']);
    check($ok===str_starts_with($worker,'editor-success-'),'Editor/fault protocol falsely acknowledged success: '.$worker);
}
printf("Local attachment consistency: %d checks passed on PHP %s (%s)\n",$checks,PHP_VERSION,$mysql?'MySQL':'SQLite');
