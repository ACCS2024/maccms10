<?php
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_image_helpers.php';
use app\common\model\Upload;
use think\file\UploadedFile;

$root = dirname(__DIR__);
$temp = audit_temp_dir('image-upload');
$cwd = getcwd();
define('ROOT_PATH', $temp . '/');
define('MAC_PATH','/');
define('ENTRANCE','index');
$GLOBALS['user'] = ['user_id'=>1];
$GLOBALS['image_upload_member'] = ['user_id'=>1];
$GLOBALS['image_upload_admin'] = ['admin_id'=>2, 'admin_auth'=>',upload/upload,'];
$GLOBALS['config']['user']['portrait_status'] = '1';
$GLOBALS['config']['user']['portrait_size'] = '30x20';
$GLOBALS['image_config'] = ['maccms.site'=>['install_dir'=>'/'], 'maccms.upload'=>[
    'mode'=>'local','watermark'=>0,'thumb'=>1,'thumb_size'=>'30x30,90x90','thumb_type'=>1,
]];
$GLOBALS['image_user_updates'] = [];
try {
    chdir($temp);
    mkdir('upload/user/1',0777,true);
    $gd = imagecreatetruecolor(120,60);
    imagefill($gd,0,0,imagecolorallocate($gd,255,0,0));
    imagepng($gd,'source.png');
    imagejpeg($gd,'source.jpg');
    foreach (['png','jpg','gif'] as $extension) {
        $source = $extension === 'gif' ? $root . '/tests/fixtures/image-processing/animation.gif' : 'source.' . $extension;
        imageAuditRequest(['flag'=>'user','user_id'=>1,'imgdata'=>'data:image/' . $extension . ';base64,' . base64_encode(file_get_contents($source))]);
        $result = (new Upload())->upload();
        $portrait = ltrim(explode('?', $result['file'])[0], '/');
        check($result['code'] === 1 && app\common\util\UserPortrait::isManagedPath(1, $portrait), 'Base64 avatar returned a staging path or failure');
        $info = getimagesize($portrait);
        check([$info[0],$info[1],$info[2]] === [30,20,IMAGETYPE_JPEG], 'Avatar extension did not match real JPEG content');
        check(glob('upload/user/1/.portrait-*') === [], 'Successful avatar left its incoming temporary file');
    }
    $original = file_get_contents($portrait);
    foreach (['bad-data', 'bad-size', 'truncated-gif', 'missing-file'] as $failure) {
        $params = ['flag'=>'user','user_id'=>1];
        $GLOBALS['config']['user']['portrait_size'] = $failure === 'bad-size' ? '0x20' : '30x20';
        if ($failure !== 'missing-file') {
            $source = match ($failure) {
                'bad-data'=>'not an image',
                'truncated-gif'=>substr(file_get_contents($root . '/tests/fixtures/image-processing/animation.gif'),0,-10),
                default=>file_get_contents('source.png'),
            };
            $params['imgdata'] = 'data:image/gif;base64,' . base64_encode($source);
        }
        imageAuditRequest($params);
        $updates = think\facade\Db::name('User')->find(1);
        $result = (new Upload())->upload();
        check($result['code'] !== 1 && $result['file'] === '', 'Invalid avatar did not return a controlled failure');
        check(file_get_contents($portrait) === $original && think\facade\Db::name('User')->find(1) === $updates,
            'Failed avatar replaced the old file or its metadata');
        check(glob('upload/user/1/.portrait-*') === [], 'Failed avatar leaked its incoming data');
    }

    $GLOBALS['config']['user']['portrait_size'] = '30x20';
    copy('source.png','uploaded.png');
    $file = new UploadedFile($temp . '/uploaded.png','client.PNG','image/png',UPLOAD_ERR_OK,true);
    imageAuditRequest(['flag'=>'user','user_id'=>1],['file'=>$file]);
    $result = (new Upload())->upload();
    $portrait = ltrim(explode('?', $result['file'])[0], '/');
    check($result['code'] === 1 && getimagesize($portrait)[2] === IMAGETYPE_JPEG,
        'Real TP8 UploadedFile avatar still called a removed file API');

    foreach (['png','jpg','gif'] as $extension) {
        $source = $extension === 'gif' ? $root . '/tests/fixtures/image-processing/animation.gif' : 'source.' . $extension;
        copy($source,'incoming.' . $extension);
        imageAuditRequest(['flag'=>'vod','thumb'=>1],['file'=>new UploadedFile($temp . '/incoming.' . $extension,
            'client.' . strtoupper($extension),null,UPLOAD_ERR_OK,true)]);
        $result = (new Upload())->upload([], true);
        $path = ltrim(explode('?',$result['file'])[0],'/');
        check($result['code'] === 1 && is_file($path) && pathinfo($path,PATHINFO_EXTENSION) === $extension,
            'TP8 upload lost the selected date directory, suffix, or successful return path');
        check(is_file($path . '_30x30.' . $extension) && is_file($path . '_90x90.' . $extension),
            'Real file upload did not create both thumbnails');
        if ($extension === 'gif') {
            $gif = imageAuditGif($path . '_90x90.gif');
            check(count($gif['frames']) === 3 && array_column($gif['frames'],'delay') === [7,13,25],
                'Upload pipeline lost GIF animation');
            check($gif['width'] === 80, 'Second GIF thumbnail was derived from the first smaller thumbnail');
        }
    }
    imageAuditRequest(['flag'=>'vod','thumb'=>1,'imgdata'=>'data:image/png;base64,' . base64_encode(file_get_contents('source.png'))]);
    $result = (new Upload())->upload([], true);
    $path = ltrim(explode('?',$result['file'])[0],'/');
    check($result['code'] === 1 && pathinfo($path,PATHINFO_EXTENSION) === 'png' && is_file($path . '_90x90.png'),
        'Base64 image uploads lacked an extension, date directory, or image thumbnail handling');

    $GLOBALS['image_config']['maccms.upload'] += ['watermark_content'=>'X','watermark_font'=>$root . '/static/font/test.ttf',
        'watermark_size'=>12,'watermark_color'=>'#00000000','watermark_location'=>5];
    $GLOBALS['image_config']['maccms.upload']['watermark'] = 1;
    $GLOBALS['image_config']['maccms.upload']['thumb_size'] = '120x60';
    imageAuditRequest(['flag'=>'vod','thumb'=>1,'imgdata'=>'data:image/png;base64,' . base64_encode(file_get_contents('source.png'))]);
    $result = (new Upload())->upload([], true);
    $path = ltrim(explode('?',$result['file'])[0],'/');
    app\common\util\ImageProcessor::open($path)->thumb(120,60)->save('expected-upload.png');
    check($result['code'] === 1 && hash_file('sha256',$path . '_120x60.png') === hash_file('sha256','expected-upload.png'),
        'Upload chain applied the watermark again while making a thumbnail');
    $GLOBALS['image_download_fixture'] = file_get_contents($root . '/tests/fixtures/image-processing/animation.gif');
    $download = (new app\common\model\Image())->down_exec('https://image.fixture/animation.gif',$GLOBALS['image_config']['maccms.upload']);
    check(is_file($download) && is_file($download . '_120x60.gif'), 'Downloader did not reach the real watermark/thumbnail pipeline');
    $gif = imageAuditGif($download . '_120x60.gif');
    check(count($gif['frames']) === 3 && array_column($gif['frames'],'delay') === [7,13,25] && $gif['loops'] === 4,
        'Download chain damaged GIF animation metadata');

    file_put_contents('bad.php','<?php echo 1;');
    imageAuditRequest(['flag'=>'vod'],['file'=>new UploadedFile($temp . '/bad.php','bad.php',null,UPLOAD_ERR_OK,true)]);
    check((new Upload())->upload([], true)['code'] !== 1, 'Disallowed upload extension was accepted during file API migration');
    imageAuditRequest(['flag'=>'vod'],['file'=>new UploadedFile($temp . '/source.png','bad.png',null,UPLOAD_ERR_PARTIAL,true)]);
    check((new Upload())->upload([], true)['code'] !== 1, 'An incomplete uploaded file was accepted');
    $request = (new think\Request())->withServer(['REQUEST_METHOD'=>'POST','REQUEST_TIME'=>123456])
        ->withHeader(['X-CSRF-Token'=>'image-upload-csrf'])
        ->withPost(['flag'=>'user','user_id'=>1])->withFiles(['file'=>[
            'name'=>'failed.png','type'=>'image/png','tmp_name'=>$temp . '/source.png','error'=>UPLOAD_ERR_PARTIAL,'size'=>10,
        ]]);
    think\Container::getInstance()->instance('request',$request);
    $GLOBALS['image_request'] = $request;
    check((new Upload())->upload()['code'] !== 1, 'Real Request upload error escaped as a PHP exception');
    imageAuditRequest(['flag'=>'user','user_id'=>1,'imgdata'=>['unexpected']]);
    check((new Upload())->upload()['code'] !== 1, 'Non-string base64 input escaped as a PHP error');
    echo "image upload audit: $checks checks passed on PHP " . PHP_VERSION . "\n";
} finally {
    chdir($cwd);
    audit_remove_temp($temp);
}
