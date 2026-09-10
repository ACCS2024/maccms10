<?php
/** Editor adapters deliberately exit; run them in a fresh SQLite process and always clean temporary files. */
declare(strict_types=1);
putenv('UPLOAD_AUDIT_MYSQL=0');
putenv('UPLOAD_AUDIT_ENTRANCE=admin');
require __DIR__.'/security_audit_upload_identity_db.php';
use think\facade\Db;

$case = $argv[1] ?? '';
$isUpload = str_starts_with($case, 'upload-');
$from = $isUpload ? substr($case, 7) : 'ueditor';
if (!in_array($case, ['config-ok', 'config-guest', 'config-member', 'config-revoked', 'upload-get',
    'upload-ueditor', 'upload-umeditor', 'upload-kindeditor', 'upload-ckeditor', 'upload-tinymce'], true)) {
    throw new RuntimeException('Unknown editor fixture');
}
mkdir('static/ueditor', 0777, true);
copy(dirname(__DIR__,2).'/static/ueditor/config.json', 'static/ueditor/config.json');
if ($case === 'config-member') { uploadIdentityMember(); }
elseif ($case !== 'config-guest') { uploadIdentityAdmin(); }
if ($case === 'config-revoked') { Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>'']); }
$method = $isUpload && $case !== 'upload-get' ? 'POST' : 'GET';
if ($case === 'upload-get') { $from = 'ueditor'; }
uploadIdentityRequest(['from'=>$from, 'flag'=>'vod_editor', 'action'=>$isUpload ? 'uploadimage' : 'config'], $method, $isUpload);
$before = uploadIdentitySnapshot();
$GLOBALS['upload_identity_before_cleanup'] = static function () use ($before, $isUpload, $case): void {
    if ($isUpload && $case !== 'upload-get') {
        $annex = Db::name('Annex')->order('annex_id')->find();
        check($annex && is_file($annex['annex_file']) && getimagesize($annex['annex_file'])[2] === IMAGETYPE_PNG,
            'Editor success did not persist a valid uploaded image');
        check(Db::name('User')->order('user_id')->select()->toArray() === $before[0], 'Editor upload changed an avatar owner');
    } else {
        check(uploadIdentitySnapshot() === $before, 'Configuration GET or denied editor request wrote files or metadata');
    }
};
echo json_encode(uploadIdentityController('admin'), JSON_THROW_ON_ERROR);
