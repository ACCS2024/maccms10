<?php
/** Real editor exits and member response/cookie contracts under a subdirectory installation. */
declare(strict_types=1);
$case=$argv[1]??'';$member=str_starts_with($case,'member-');
define('UPLOAD_AUDIT_MAC_PATH','/site/');putenv('REMOTE_UPLOAD_AUDIT_MYSQL=0');
putenv('UPLOAD_AUDIT_ENTRANCE='.($member?'index':'admin'));
require __DIR__.'/security_audit_remote_upload_db.php';
use think\facade\Db;
use app\common\util\UserPortrait;
remoteUploadConfig();
if($member) {
    uploadIdentityMember();
    if($case==='member-fallback')$GLOBALS['storage_provider_mode']='false';
    $result=remoteUploadAttempt([],false);$path=Db::name('User')->find(1)['user_portrait'];
    $selected=UserPortrait::url(1);
    check($result['code']===1 && UserPortrait::isManagedPath(1,$path),'Subdirectory member remote upload failed');
    check(str_starts_with($result['file'],$selected.'?') && $GLOBALS['upload_cookies']['user_portrait']===$selected,'Member response/cookie differs from actual committed reader');
    check($case==='member-fallback'?($selected===MAC_PATH.$path&&is_file($path)):(str_starts_with($selected,'https://')&&!str_contains($selected,'/site/')&&!is_file($path)),
        'Subdirectory was prefixed onto a remote URL or omitted from local fallback');
    require __DIR__.'/security_audit_remote_projection.php';
    foreach(['tinymce','ueditor','umeditor','kindeditor','ckeditor'] as $editor) {
        $cookie=$GLOBALS['upload_cookies']['user_portrait'];$calls=$GLOBALS['storage_provider_calls'];uploadIdentityRequest(['from'=>$editor]);
        uploadIdentityDenied(fn()=>(new app\common\model\Upload())->upload(),'Member remote editor capability');
        check($GLOBALS['upload_cookies']['user_portrait']===$cookie&&$GLOBALS['storage_provider_calls']===$calls,'Denied editor changed cookie or invoked SDK');
    }
    echo json_encode($result,JSON_THROW_ON_ERROR);fwrite(STDERR,'remote client passed: '.$case."\n");exit;
}
$parts=explode('-',$case);$editor=$parts[2]??'';$success=($parts[1]??'')==='success';
if(!in_array($editor,['tinymce','ueditor','umeditor','kindeditor','ckeditor'],true))throw new RuntimeException('Unknown remote editor fixture');
uploadIdentityAdmin();uploadIdentityRequest(['flag'=>'vod','thumb'=>'1','from'=>$editor]);
if(!$success)Db::execute("CREATE TRIGGER remote_editor_fault BEFORE INSERT ON upload_audit_annex BEGIN SELECT RAISE(ABORT,'remote editor fixture'); END");
$cleanup=$GLOBALS['upload_identity_before_cleanup'];
$GLOBALS['upload_identity_before_cleanup']=static function()use($success,$case,$cleanup):void {
    try {
        $rows=Db::name('StorageIntent')->select()->toArray();
        check(count($rows)===3 && Db::name('Annex')->count()===($success?3:0),'Editor exited before the full metadata set was resolved');
        foreach($rows as $intent)check($intent['reference_state']===($success?'committed':'pending')&&is_file($intent['local_path'])===!$success,
            'Editor emitted success/failure before reference commit and safe cleanup completed');
        fwrite(STDERR,'remote client passed: '.$case."\n");
    } finally {$cleanup();}
};
uploadIdentityController('admin');
throw new RuntimeException('Editor adapter did not complete its response');
