<?php
/** Real member cookies, request and models with a non-root deployment prefix. */
declare(strict_types=1);
define('UPLOAD_AUDIT_MAC_PATH','/site/');
require __DIR__.'/security_audit_upload_identity_db.php';
use app\common\model\Upload;
use app\common\util\UserPortrait;
use think\facade\Config;
use think\facade\Db;
Config::set(['site'=>['install_dir'=>'/site/'],'upload'=>['mode'=>'local','thumb'=>0,'watermark'=>0]],'maccms');
uploadIdentityMember();uploadIdentityRequest(['from'=>'']);
$result=(new Upload())->upload();$path=uploadIdentityPath($result);
check($result['code']===1 && UserPortrait::isManagedPath(1,$path),'Legal subdirectory member upload failed');
check(str_starts_with($result['file'],MAC_PATH.$path.'?') && Db::name('User')->find(1)['user_portrait']===$path,'Subdirectory leaked into the stored avatar identity');
check($GLOBALS['upload_cookies']['user_portrait']===MAC_PATH.$path,'Subdirectory member upload lost its exact portrait cookie prefix');
foreach (['tinymce','ueditor','umeditor','kindeditor','ckeditor'] as $editor) {
    $cookie=$GLOBALS['upload_cookies']['user_portrait'];uploadIdentityRequest(['from'=>$editor]);
    uploadIdentityDenied(fn()=>(new Upload())->upload(),'Member editor capability under subdirectory: '.$editor);
    check($GLOBALS['upload_cookies']['user_portrait']===$cookie,'Rejected member editor request changed the portrait cookie');
}
printf("Avatar subdirectory: %d checks passed (%s, %s)\n",$checks,PHP_VERSION,$mysql?'MySQL':'SQLite');
