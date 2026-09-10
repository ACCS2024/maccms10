<?php
/** Direct protocol cases and isolated real HTTP uploads; no application entry/configuration. */
declare(strict_types=1);
$case = PHP_SAPI === 'cli-server' ? ($_GET['case'] ?? '') : ($argv[1] ?? '');
$integration = str_starts_with($case, 'upload-');
if ($integration) {
    putenv('UPLOAD_AUDIT_MYSQL=0');
    putenv('UPLOAD_AUDIT_ENTRANCE=admin');
    require __DIR__.'/security_audit_upload_identity_db.php';
    uploadIdentityAdmin();
    $GLOBALS['upload_session']['__csrf_token__'] = 'tinymce-protocol-csrf';
    $request=(new \think\Request())->withServer($_SERVER)->withHeader(getallheaders())
        ->withGet($_GET)->withPost($_POST)->withFiles($_FILES);
    \think\Container::getInstance()->instance('request',$request);
    ob_start();
    $before=uploadIdentitySnapshot();
    $GLOBALS['upload_identity_before_cleanup']=static function () use($before,$case): void {
        $after=uploadIdentitySnapshot();
        header('X-Audit-Unchanged: '.($after === $before ? 'yes' : 'no'));
        header('X-Audit-Annex-Count: '.\think\facade\Db::name('Annex')->count());
        if ($case === 'upload-success') {
            $annex=\think\facade\Db::name('Annex')->order('annex_id')->find();
            check($annex && getimagesize($annex['annex_file'])[2] === IMAGETYPE_PNG, 'TinyMCE success lost its real image');
            check($before[0] === $after[0], 'Editor upload changed member avatars');
        } else { check($before === $after, 'TinyMCE upload rejection wrote files or metadata'); }
    };
    echo json_encode(uploadIdentityController('admin'),JSON_THROW_ON_ERROR);
    exit;
}
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/security_audit_test_helpers.php';
$cases = [
    'success'=>['ok',1,['file'=>'/upload/image.png']],
    'success-string'=>['ok','1',['file'=>'https://cdn.example.invalid/中文.png?signature=a%2Fb']],
    'success-relative'=>['ok',1,['file'=>'upload/image.png']],
    'failure'=>['Rejected',0,[]],
    'failure-with-file'=>['Rejected',0,['file'=>'/must-not-return.png']],
    'failure-string'=>['Rejected','0',['file'=>'/must-not-return.png']],
    'failure-false'=>['Rejected',false,[]],
    'failure-no-info'=>[null,0,[]],
    'failure-array-info'=>[['secret'=>'value'],0,[]],
    'failure-object-info'=>[new \stdClass(),0,[]],
    'failure-long-info'=>[str_repeat('a',4097),0,[]],
    'failure-binary-info'=>["invalid\xff",0,[]],
    'missing-file'=>['Invalid success',1,[]],
    'empty-file'=>['Invalid success',1,['file'=>'']],
    'whitespace-file'=>['Invalid success',1,['file'=>" \t"]],
    'array-file'=>['Invalid success',1,['file'=>[]]],
    'object-file'=>['Invalid success',1,['file'=>new \stdClass()]],
    'number-file'=>['Invalid success',1,['file'=>42]],
    'null-data'=>['Invalid success',1,null],
    'string-data'=>['Invalid success',1,'bad'],
    'object-data'=>['Invalid success',1,new \stdClass()],
    'binary-file'=>['Invalid success',1,['file'=>"/bad\xff.png"]],
    'control-file'=>['Invalid success',1,['file'=>"/bad\n.png"]],
    'long-file'=>['Invalid success',1,['file'=>'/'.str_repeat('x',8192)]],
    'bad-status-array'=>['Invalid status',[],['file'=>'/image.png']],
    'bad-status-number'=>['Invalid status',2,['file'=>'/image.png']],
    'bad-status-true'=>['Invalid status',true,['file'=>'/image.png']],
];
if (!isset($cases[$case])) { http_response_code(404); exit('Unknown case'); }
if (PHP_SAPI === 'cli') {
    // The adapter deliberately exits. Capture its actual status/body at shutdown for the parent process.
    ob_start();
    register_shutdown_function(static function (): void {
        $body=ob_get_clean();
        echo json_encode(['status'=>http_response_code(), 'body'=>$body],JSON_THROW_ON_ERROR);
    });
}
(new \app\common\extend\editor\Tinymce())->back(...$cases[$case]);
