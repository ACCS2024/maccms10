<?php
/** Included by the remote upload suite: real failed SQL statements leave complete external/local evidence. */
use think\facade\Db;
use app\common\util\UserPortrait;
uploadIdentityAdmin();remoteUploadConfig();$GLOBALS['storage_provider_mode']='success';
foreach(['annex-reject','annex-mutate','reference-reject','receipt-reject','source-changed','owner-reject','owner-disabled'] as $fault) {
    $avatar=str_starts_with($fault,'owner-');
    if($avatar)uploadIdentityMember();else uploadIdentityAdmin();
    $before=Db::name('Annex')->order('annex_id')->select()->toArray();$user=Db::name('User')->find(1);$cookie=$GLOBALS['upload_cookies']['user_portrait']??null;
    $oldIds=array_column(Db::name('StorageIntent')->select()->toArray(),'intent_id');$calls=$GLOBALS['storage_provider_calls'];
    $GLOBALS['remote_provider_hook']=static function(array $intent)use($fault,$calls):void {
        if($GLOBALS['storage_provider_calls']!==$calls+1)return;
        if($fault==='source-changed'){file_put_contents($intent['local_path'],'altered source after external acceptance');return;}
        if($fault==='owner-disabled'){Db::name('User')->where('user_id',1)->update(['user_status'=>0]);return;}
        $table=match($fault){'owner-reject'=>'user','reference-reject','receipt-reject'=>'storage_intent',default=>'annex'};
        $event=$table==='annex'?'INSERT':'UPDATE';
        $condition=$fault==='reference-reject'?"NEW.reference_state='committed'":'1=1';
        if($GLOBALS['mysql']) {
            $effect=$fault==='annex-mutate'?'SET NEW.annex_size=NEW.annex_size+1':"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='remote fixture failure'";
            $sql="CREATE TRIGGER remote_fault BEFORE $event ON upload_audit_$table FOR EACH ROW BEGIN IF $condition THEN $effect; END IF; END";
        } else {
            $sql=$fault==='annex-mutate'
                ? "CREATE TRIGGER remote_fault AFTER INSERT ON upload_audit_annex BEGIN UPDATE upload_audit_annex SET annex_size=annex_size+1 WHERE annex_id=NEW.annex_id; END"
                : "CREATE TRIGGER remote_fault BEFORE $event ON upload_audit_$table WHEN $condition BEGIN SELECT RAISE(ABORT,'remote fixture failure'); END";
        }
        Db::execute($sql);
    };
    try {$result=remoteUploadAttempt([],!$avatar);}
    finally {
        unset($GLOBALS['remote_provider_hook']);
        if(!in_array($fault,['source-changed','owner-disabled'],true))Db::execute('DROP TRIGGER remote_fault');
        if($fault==='owner-disabled')Db::name('User')->where('user_id',1)->update(['user_status'=>1]);
    }
    $new=array_values(array_filter(Db::name('StorageIntent')->select()->toArray(),fn($row)=>!in_array($row['intent_id'],$oldIds,true)));
    check($result['code']===0 && Db::name('Annex')->order('annex_id')->select()->toArray()===$before,'Failed '.$fault.' acknowledged success or partially committed Annex');
    check(Db::name('User')->find(1)['user_portrait']===$user['user_portrait'] && ($GLOBALS['upload_cookies']['user_portrait']??null)===$cookie,'Failed '.$fault.' changed the visible avatar/cookie');
    check(count($new)===($avatar?1:3),'Failed '.$fault.' lost its prepared set evidence');
    foreach($new as $intent) {
        check($intent['reference_state']==='pending' && is_file($intent['local_path']),'Failed '.$fault.' discarded source evidence or invented a committed reference');
        if($intent['transfer_state']==='remote_confirmed')check(is_file('remote-fixture/'.$intent['intent_id']),'Failure attempted a fake remote rollback');
    }
    if($fault==='receipt-reject')check($GLOBALS['storage_provider_calls']===$calls+1 && count(array_filter($new,fn($row)=>$row['transfer_state']==='attempting'))===1,'Receipt failure continued the external batch or erased the durable attempt');
    $found=false;
    foreach(glob(sys_get_temp_dir().'/maccms-attachment-*') as $stage) {
        $manifest=json_decode(file_get_contents($stage.'/manifest.json'),true);
        if(($manifest['root']??null)===realpath(ROOT_PATH) && in_array($new[0]['intent_id'],$manifest['remote']['intents']??[],true)) {
            $found=$manifest['state']==='remote_reference_failed';break;
        }
    }
    check($found,'Failed '.$fault.' lost its private reconciliation manifest');
}

// A real non-strict MySQL schema clips new bytes; preserve other fixture rows by temporarily using an empty Annex table.
if($mysql) {
    Db::execute('ALTER TABLE upload_audit_annex RENAME TO upload_audit_annex_saved');
    Db::execute('CREATE TABLE upload_audit_annex LIKE upload_audit_annex_saved');
    Db::execute('ALTER TABLE upload_audit_annex MODIFY annex_size TINYINT UNSIGNED NOT NULL DEFAULT 0');
    $source=file_get_contents('source.png');$canvas=imagecreatetruecolor(80,60);
    for($x=0;$x<80;$x++)for($y=0;$y<60;$y++)imagesetpixel($canvas,$x,$y,imagecolorallocate($canvas,($x*17+$y)%256,($y*19+$x)%256,($x+$y*13)%256));
    imagepng($canvas,'source.png');uploadIdentityAdmin();
    try {
        $calls=$GLOBALS['storage_provider_calls'];$result=remoteUploadAttempt();
        check($result['code']===0 && Db::name('Annex')->count()===0 && $GLOBALS['storage_provider_calls']===$calls+3,'Non-strict Annex clipping was accepted after successful remote writes');
    } finally {
        file_put_contents('source.png',$source);Db::execute('DROP TABLE upload_audit_annex');Db::execute('ALTER TABLE upload_audit_annex_saved RENAME TO upload_audit_annex');
    }
}

// No remote writes on authorization, CSRF, validation, filesystem publication or outer-transaction failure.
uploadIdentityAdmin();remoteUploadConfig();
foreach(['csrf','image','publication','outer','permission'] as $fault) {
    $calls=$GLOBALS['storage_provider_calls'];$before=uploadIdentitySnapshot();
    uploadIdentityRequest(['flag'=>'vod','thumb'=>'1'],'POST',true,$fault==='csrf'?['X-CSRF-Token'=>'wrong']:[]);
    if($fault==='image')file_put_contents('incoming.png','invalid PNG');
    if($fault==='publication'){$GLOBALS['attachment_io_fault']='second-publish';$GLOBALS['attachment_publish_count']=0;}
    if($fault==='outer')Db::startTrans();
    if($fault==='permission')uploadIdentityAdmin(',user/info,');
    try {$result=(new app\common\model\Upload())->upload([],true);}
    finally {if($fault==='outer')Db::rollback();unset($GLOBALS['attachment_io_fault']);}
    if($fault==='permission')uploadIdentityAdmin();
    check($result['code']===0 && $GLOBALS['storage_provider_calls']===$calls && uploadIdentitySnapshot()===$before,'Pre-transfer '.$fault.' changed files/metadata or reached SDK');
}
