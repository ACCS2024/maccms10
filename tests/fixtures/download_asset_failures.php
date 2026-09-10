<?php
/** Ordinary storage failures in the real asset/intent tables. */
use think\facade\Db;
function downloadTrigger(string $fault): void {
    $table=in_array($fault,['reference','receipt'],true)?'storage_intent':'annex';
    $event=$table==='annex'?'INSERT':'UPDATE';
    $condition=match($fault){'second'=>"NEW.annex_file LIKE '%_10x10.png'",'reference'=>"NEW.reference_state='committed'",'receipt'=>"NEW.transfer_state IN ('remote_confirmed','outcome_unknown')",default=>'1=1'};
    if($GLOBALS['mysql']) {
        $effect=$fault==='mutate'?'SET NEW.annex_size=NEW.annex_size+1':"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='ordinary fixture unavailable'";
        $sql="CREATE TRIGGER download_fault BEFORE $event ON upload_audit_$table FOR EACH ROW BEGIN IF $condition THEN $effect; END IF; END";
    } else {
        $sql=$fault==='mutate'?"CREATE TRIGGER download_fault AFTER INSERT ON upload_audit_annex BEGIN UPDATE upload_audit_annex SET annex_size=annex_size+1 WHERE annex_id=NEW.annex_id; END"
            :"CREATE TRIGGER download_fault BEFORE $event ON upload_audit_$table WHEN $condition BEGIN SELECT RAISE(".($fault==='ignore'?'IGNORE':"ABORT,'ordinary fixture unavailable'")."); END";
    }
    Db::execute($sql);
}
foreach(['local','s3','uomg'] as $mode)foreach($mysql?['reject','second','mutate']:['reject','second','mutate','ignore'] as $fault) {
    if($mode==='uomg')$GLOBALS['download_asset_image_url']='https://images.fixture.invalid/objects/'.str_repeat('r',1100).'.png';
    downloadTrigger($fault);
    try {
        if($mode==='local'){downloadFailed(['mode'=>$mode],'Annex '.$fault);continue;}
        $before=downloadAnnex();$ids=Db::name('StorageIntent')->column('intent_id');$stages=downloadManifests();$calls=$GLOBALS['storage_provider_calls'];
        check(downloadAsset(['mode'=>$mode])===$downloadUrl.'#err','Rejected Annex returned success');
        check(downloadAnnex()===$before&&$GLOBALS['storage_provider_calls']===$calls+3,'Annex failure partially committed or did not exercise all provider receipts');
        $intents=Db::name('StorageIntent')->whereNotIn('intent_id',$ids)->order('local_path')->select()->toArray();
        check(count($intents)===3,'Annex failure lost prepared identities');
        foreach($intents as $intent)check($intent['scope']==='download'&&$intent['reference_state']==='pending'&&is_file($intent['local_path'])&&is_file('remote-fixture/'.$intent['intent_id']),'Annex failure discarded its source/provider evidence');
        $new=array_diff_key(downloadManifests(),$stages);check(count($new)===1,'Annex failure did not retain exactly its own manifest');$manifest=reset($new);
        check($manifest['state']==='remote_reference_failed'&&$manifest['scope']==='download'&&$manifest['resource_url_limit']===1024,'Retained manifest has no asset scope/state');
        foreach($intents as $intent) {
            $selected=$manifest['remote']['selected_urls'][$intent['local_path']]??null;
            check($selected===($mode==='uomg'?$intent['local_path']:$intent['remote_url']),'Manifest confused provider receipt with selected resource URL');
        }
    } finally {Db::execute('DROP TRIGGER download_fault');unset($GLOBALS['download_asset_image_url']);}
}
foreach(['reference','receipt'] as $fault) {
    downloadTrigger($fault);$calls=$GLOBALS['storage_provider_calls'];$before=downloadAnnex();$ids=Db::name('StorageIntent')->column('intent_id');$stages=downloadManifests();
    try {check(downloadAsset(['mode'=>'s3'])===$downloadUrl.'#err','Unrecorded receipt/reference returned success');}
    finally{Db::execute('DROP TRIGGER download_fault');}
    check(downloadAnnex()===$before&&$GLOBALS['storage_provider_calls']===$calls+($fault==='receipt'?1:3),'Incomplete durable receipt continued the provider batch or committed Annex');
    $new=Db::name('StorageIntent')->whereNotIn('intent_id',$ids)->select()->toArray();check(count($new)===3,'Receipt failure discarded pre-created identities');
    foreach($new as $intent)check($intent['reference_state']==='pending'&&is_file($intent['local_path']),'Failed reference removed a source');
    check(count(array_diff_key(downloadManifests(),$stages))===1,'Receipt failure lost private journal');
}
if($mysql) {
    Db::execute('ALTER TABLE upload_audit_annex RENAME TO upload_audit_annex_saved');
    Db::execute('CREATE TABLE upload_audit_annex LIKE upload_audit_annex_saved');
    Db::execute('ALTER TABLE upload_audit_annex MODIFY annex_size TINYINT UNSIGNED NOT NULL DEFAULT 0');
    try {
        downloadFailed(['mode'=>'local'],'non-strict byte clipping');
        $stages=downloadManifests();$calls=$GLOBALS['storage_provider_calls'];
        check(downloadAsset(['mode'=>'s3'])===$downloadUrl.'#err'&&Db::name('Annex')->count()===0,'Non-strict remote metadata clipping returned success');
        check($GLOBALS['storage_provider_calls']===$calls+3&&count(array_diff_key(downloadManifests(),$stages))===1,'Non-strict failure discarded external evidence');
    } finally{Db::execute('DROP TABLE upload_audit_annex');Db::execute('ALTER TABLE upload_audit_annex_saved RENAME TO upload_audit_annex');}
    Db::execute('ALTER TABLE upload_audit_annex ENGINE=MyISAM');
    try {downloadFailed(['mode'=>'s3'],'non-transactional metadata table');}
    finally{Db::execute('ALTER TABLE upload_audit_annex ENGINE=InnoDB');}
}
