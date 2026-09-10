<?php
/** Real Cookie/JWT/admin identity checks, ORM metadata, Request files and isolated image writes. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_upload_identity_db.php';
use app\common\model\Upload;
use think\facade\Db;

// A global display snapshot and arbitrary target/from/flag parameters never authenticate a write.
foreach ([['flag'=>'user', 'user_id'=>2], ['flag'=>'vod'], ['flag'=>'user', 'from'=>'ueditor', 'action'=>'config']] as $params) {
    uploadIdentityRequest($params);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Anonymous model upload accepted forged display identity');
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Anonymous admin action reached a file write');
}
uploadIdentityRequest(['user_id'=>2]);
uploadIdentityDenied(fn() => uploadIdentityController('member'), 'Public portrait action accepted an unauthenticated caller');

uploadIdentityMember();
foreach ([['flag'=>'user', 'user_id'=>2], ['flag'=>'vod'], ['flag'=>'site'], ['flag'=>'user_editor'],
    ['flag'=>'user', 'from'=>'ueditor'], ['flag'=>'user', 'from'=>'kindeditor'],
    ['flag'=>'user', 'from'=>'tinymce'], ['flag'=>'user', 'user_id'=>'1e0']] as $params) {
    uploadIdentityRequest($params);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Member selected an unrelated target or admin upload capability');
}
foreach (['admin', 'adminContext', 'admin_context', 'is_admin'] as $key) {
    uploadIdentityRequest(['flag'=>'vod', $key=>1]);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Request parameter granted admin context: '.$key);
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Member cookies impersonated an administrator');
}
foreach (['from', 'input', 'flag', 'thumb', 'thumb_class', 'user_id', 'action', 'ueditor_theme', 'imgdata'] as $key) {
    foreach ([[], ['nested'=>'unexpected']] as $bad) {
        uploadIdentityRequest([$key=>$bad]);
        uploadIdentityDenied(fn() => (new Upload())->upload(), 'Malformed '.$key.' escaped as PHP error or file write');
    }
}
foreach ([null, 'input', 1, new stdClass()] as $overrides) {
    uploadIdentityRequest();
    uploadIdentityDenied(fn() => (new Upload())->upload($overrides), 'Malformed internal override container escaped as PHP error');
}
foreach (['../user', 'user/2', 'user\\2', 'a'.str_repeat('b',64)] as $flag) {
    uploadIdentityRequest(['flag'=>$flag]);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Malformed path flag was silently repaired');
}
foreach (['GET', 'PUT', 'DELETE'] as $method) {
    uploadIdentityRequest(['flag'=>'user', 'imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))], $method);
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Non-POST member upload wrote a file');
}
$GLOBALS['config']['user']['portrait_status'] = '0';
uploadIdentityRequest();
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Closed portrait feature still allowed direct member upload');
uploadIdentityDenied(fn() => uploadIdentityController('member'), 'Closed portrait feature still allowed its public action');
$GLOBALS['config']['user']['portrait_status'] = '1';

// The normal public action overrides client target/flag and persists the same authenticated owner it writes.
uploadIdentityRequest(['user_id'=>2, 'flag'=>'vod']);
$victim = hash_file('sha256', 'upload/user/2/2.jpg');
$result = uploadIdentityController('member');
check($result['code'] === 1 && app\common\util\UserPortrait::isManagedPath(1, uploadIdentityPath($result)), 'Normal portrait controller lost the server-owned target');
check(hash_file('sha256', 'upload/user/2/2.jpg') === $victim && getimagesize(uploadIdentityPath($result))[2] === IMAGETYPE_JPEG,
    'Member avatar overwrote another user or returned mislabeled content');
check(Db::name('User')->where('user_id',1)->value('user_portrait') === uploadIdentityPath($result)
    && Db::name('Annex')->where('annex_file',uploadIdentityPath($result))->count() === 1, 'Avatar metadata does not match its authenticated target');
$GLOBALS['user'] = ['user_id'=>2];
uploadIdentityRequest();
uploadIdentityDenied(fn() => uploadIdentityController('member'), 'A stale/forged global identity overrode authenticated cookies');
$GLOBALS['user'] = ['user_id'=>1];
uploadIdentityRequest(['imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))], 'POST', false);
check((new Upload())->upload()['code'] === 1, 'Authenticated normal base64 avatar stopped working');
uploadIdentityRequest(['from'=>'ueditor', 'action'=>'config'], 'GET', false);
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Member read admin editor configuration');

// Live account status and current credentials, not GLOBALS or a cached cookie ID, govern the write.
foreach ([['user_status'=>0], ['user_random'=>'revoked'], ['user_name'=>'renamed']] as $change) {
    $saved = Db::name('User')->find(1);
    Db::name('User')->where('user_id',1)->update($change);
    uploadIdentityRequest();
    uploadIdentityDenied(fn() => (new Upload())->upload(), 'Revoked member identity retained upload access');
    Db::name('User')->where('user_id',1)->update($saved);
}
$saved = Db::name('User')->find(1);
Db::name('User')->where('user_id',1)->delete();
uploadIdentityRequest();
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Deleted member retained access through a global/cookie snapshot');
Db::name('User')->insert($saved);
$token = app\common\util\JwtService::encode(1, 'upload-random-1');
$GLOBALS['upload_cookies'] = [];
uploadIdentityRequest([], 'POST', true, ['authorization'=>'Bearer '.$token]);
check((new Upload())->upload()['code'] === 1, 'Valid bearer identity failed a normal model upload');
uploadIdentityMember();
uploadIdentityRequest([], 'POST', true, ['authorization'=>'Bearer '.$token.'x']);
uploadIdentityDenied(fn() => (new Upload())->upload(), 'Invalid enabled bearer fell back to a valid cookie');

// Upload permission does not grant arbitrary account avatar editing.
uploadIdentityAdmin();
uploadIdentityRequest(['flag'=>'user', 'user_id'=>2]);
uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Upload-only administrator overwrote a member avatar');
uploadIdentityAdmin(',user/info,');
uploadIdentityRequest(['flag'=>'user', 'user_id'=>2]);
uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Member edit permission bypassed upload permission');
foreach ([',otherupload/upload,user/info,', ',upload/upload,user/info_extra,', ',upload/upload,newuser/info,',
    ',upload/upload,user/in_fo,'] as $grants) {
    uploadIdentityAdmin($grants);
    uploadIdentityRequest(['flag'=>'user', 'user_id'=>2]);
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Substring permission match granted avatar access');
}
uploadIdentityAdmin(', Upload/Upload , USER/INFO?view=edit,');
foreach ([0, '', null, [], -1, '2e0', '4294967296', 999] as $target) {
    uploadIdentityRequest(['flag'=>'user', 'user_id'=>$target]);
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Admin accepted invalid or missing avatar target');
}
unset($GLOBALS['user']);
foreach ([2, 4294967295] as $target) {
    Db::name('User')->where('user_id',$target)->update(['user_portrait'=>'old-'.$target]);
    uploadIdentityRequest(['flag'=>'user', 'user_id'=>(string)$target]);
    $before = Db::name('User')->find(1);
    $result = uploadIdentityController('admin');
    $expected = uploadIdentityPath($result);
    check(app\common\util\UserPortrait::isManagedPath($target, $expected), 'Administrator avatar path belongs to another owner');
    check($result['code'] === 1 && uploadIdentityPath($result) === $expected, 'Authorized admin avatar chose the wrong path');
    check(Db::name('User')->where('user_id',$target)->value('user_portrait') === $expected && Db::name('User')->find(1) === $before,
        'Authorized admin avatar wrote unrelated/global user metadata');
    check(is_file($expected) && Db::name('Annex')->where('annex_file',$expected)->count() === 1,
        'Authorized admin avatar did not persist matching file and annex');
}
uploadIdentityAdmin();
foreach (['vod', 'art_editor', 'vod_screenshot', 'site', 'manga', 'addon'] as $flag) {
    uploadIdentityRequest(['flag'=>$flag]);
    $result = uploadIdentityController('admin');
    $path = uploadIdentityPath($result);
    check($result['code'] === 1 && str_starts_with($path, 'upload/'.$flag.'/') && is_file($path)
        && Db::name('Annex')->where('annex_file',$path)->count() === 1, 'Normal admin upload lost its supported directory or metadata');
}
foreach (['GET','PUT','DELETE'] as $method) {
    uploadIdentityRequest(['flag'=>'vod', 'imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))], $method);
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Non-POST admin upload wrote a file');
}
foreach ([['admin_status'=>0], ['admin_pwd'=>'changed'], ['admin_auth'=>',vod/info,']] as $change) {
    uploadIdentityAdmin();
    $saved = Db::name('Admin')->find(2);
    Db::name('Admin')->where('admin_id',2)->update($change);
    uploadIdentityRequest(['flag'=>'vod']);
    uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'A revoked admin session retained upload access');
    Db::name('Admin')->where('admin_id',2)->update($saved);
}
uploadIdentityAdmin();
$saved = Db::name('Admin')->find(2);
Db::name('Admin')->where('admin_id',2)->delete();
uploadIdentityRequest(['flag'=>'vod']);
uploadIdentityDenied(fn() => uploadIdentityController('admin'), 'Deleted administrator retained access through its session');
Db::name('Admin')->insert($saved);
uploadIdentityAdmin('', 1);
uploadIdentityRequest(['flag'=>'user', 'user_id'=>2]);
check(uploadIdentityController('admin')['code'] === 1, 'Super-admin no longer has explicit avatar management rights');
check(glob('upload/user/*/.portrait-*') === [], 'Upload identity paths left avatar staging files');

// The real editor front/back methods exit after emitting JSON, so isolate each adapter in a child process.
foreach (['config-ok', 'config-guest', 'config-member', 'config-revoked', 'upload-get',
    'upload-ueditor', 'upload-umeditor', 'upload-kindeditor', 'upload-ckeditor', 'upload-tinymce'] as $case) {
    $process = proc_open([PHP_BINARY, __DIR__.'/fixtures/security_audit_upload_editor_worker.php', $case],
        [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']], $pipes, dirname(__DIR__));
    if (!is_resource($process)) { throw new RuntimeException('Editor worker unavailable'); }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $errors = stream_get_contents($pipes[2]); fclose($pipes[2]);
    check(proc_close($process) === 0 && $errors === '', 'Editor worker failed: '.$case.' '.$errors);
    $response = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
    $ok = match ($case) {
        'config-ok' => ($response['imageActionName'] ?? null) === 'uploadimage',
        'upload-ueditor', 'upload-umeditor' => ($response['state'] ?? null) === 'SUCCESS',
        'upload-kindeditor' => ($response['error'] ?? null) === 0,
        'upload-ckeditor' => ($response['uploaded'] ?? null) === 1,
        'upload-tinymce' => str_starts_with($response['location'] ?? '', '/upload/vod_editor/'),
        default => ($response['code'] ?? null) === 0,
    };
    check($ok, 'Authenticated editor configuration/upload response changed: '.$case);
}

echo 'Upload identity: '.$checks.' checks passed on PHP '.PHP_VERSION.' ('.($mysql ? 'MySQL' : 'SQLite').', '.ENTRANCE.")\n";
