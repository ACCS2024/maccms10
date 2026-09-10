<?php
/** Isolated CLI-server router. Never loads an application entry or reads its live configuration. */
declare(strict_types=1);
if (PHP_SAPI !== 'cli-server') { throw new RuntimeException('Use the isolated PHP CLI server'); }
$source = dirname(__DIR__,2);
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$remoteBrowser = getenv('REMOTE_UPLOAD_AUDIT_BROWSER') === '1';
$cloudDirectory = getenv('REMOTE_UPLOAD_AUDIT_OBJECT_DIR');
if ($remoteBrowser) {
    if (!is_string($cloudDirectory) || !str_starts_with($cloudDirectory,sys_get_temp_dir().'/maccms-upload-http-')
        || basename($cloudDirectory)!=='cloud' || str_contains($cloudDirectory,'..')) { throw new RuntimeException('Remote browser requires its isolated object directory'); }
    if (!is_dir($cloudDirectory) && !mkdir($cloudDirectory,0700,true) && !is_dir($cloudDirectory)) { throw new RuntimeException('Cannot create fixture object storage'); }
    if (str_starts_with($path,'/fixture-cloud/')) {
        $object=$cloudDirectory.'/'.hash('sha256','http://'.$_SERVER['HTTP_HOST'].$path);
        if (!is_file($object)) {http_response_code(404);exit;}
        header('Content-Type: '.image_type_to_mime_type(getimagesize($object)[2]));readfile($object);exit;
    }
}
if (preg_match('~^/(?:static/|static_new/|template/default/asset/|template/demo/(?:js|vendor)/)~', $path)) {
    $file = realpath($source.$path);
    if (!$file || !str_starts_with($file, $source.'/') || !is_file($file)
        || !in_array(strtolower(pathinfo($file,PATHINFO_EXTENSION)), ['js','css','png','jpg','gif','svg','woff','woff2','ttf','html'],true)) {
        http_response_code(404); exit;
    }
    $mime = ['js'=>'text/javascript','css'=>'text/css','html'=>'text/html','svg'=>'image/svg+xml'];
    header('Content-Type: '.($mime[pathinfo($file,PATHINFO_EXTENSION)] ?? 'application/octet-stream'));
    readfile($file); exit;
}
if ($path === '/health') { echo 'ready'; exit; }
putenv('UPLOAD_AUDIT_MYSQL=0');
putenv('UPLOAD_AUDIT_ENTRANCE='. (str_contains($path,'/admin.php/') || in_array($_GET['client'] ?? '', ['native','layui','ueditor'],true) ? 'admin' : 'index'));
ob_start();
if ($remoteBrowser) {
    putenv('REMOTE_UPLOAD_AUDIT_MYSQL=0');
    require __DIR__.'/security_audit_remote_upload_db.php';
    remoteUploadConfig(['thumb'=>0]);
    $GLOBALS['config']['upload']['api']['s3']['domain']='http://'.$_SERVER['HTTP_HOST'].'/fixture-cloud';
    $transport=$GLOBALS['storage_provider_callback'];
    $GLOBALS['storage_provider_callback']=static function(string $path) use($transport,$cloudDirectory):void {
        $transport($path);
        $url=app\common\util\StoragePublicUrl::current('s3')->expected($path);
        if (!copy(ROOT_PATH.$path,$cloudDirectory.'/'.hash('sha256',$url))) {throw new RuntimeException('Fixture object write failed');}
    };
} else { require __DIR__.'/security_audit_upload_identity_db.php'; }
function mac_csrf_token() { return 'upload-browser-csrf'; }
function url($route) { return '/admin.php/'.$route; }
function response($data, $code = 200) { return new \think\response\Html(new \think\Cookie(request()), $data, $code); }
function renderUploadSource(string $html, array $vars=[]): void {
    $template = new \think\Template(['cache_path'=>ROOT_PATH.'templates/', 'tpl_replace_string'=>[
        '__STATIC__'=>'/static_new', '__ROOT__'=>'', '__ASSETV__'=>'audit']]);
    $template->display($html, $vars);
}
function renderUploadTemplate(string $file, array $vars=[]): void { renderUploadSource(file_get_contents($file), $vars); }

if ($path === '/page') {
    header('Content-Type: text/html; charset=UTF-8');
    // Fixture login cookies select seeded identities; real production checkLogin still verifies their digest/DB status.
    uploadIdentityMember();
    foreach ($GLOBALS['upload_cookies'] as $name=>$value) { setcookie($name,$value,['path'=>'/','httponly'=>true,'samesite'=>'Lax']); }
    setcookie('audit_admin','yes',['path'=>'/','httponly'=>true,'samesite'=>'Lax']);
    $client=$_GET['client'] ?? 'legacy';
    if ($client === 'native') {
        renderUploadTemplate($source.'/application/admin/view/upload/index.html', ['path'=>'', 'id'=>'']); exit;
    }
    if (in_array($client,['layui','ueditor'],true)) {
        renderUploadTemplate($source.'/application/admin/view/public/head.html');
    } else {
        echo '<!doctype html><meta charset="utf-8">';
        $include=match($client) {
            'default','deferred'=>'template/default/html/user/include.html',
            'demo'=>'template/demo/html/user/include.html',
            default=>'template/m1938pc3_v2/html9/user/include.html',
        };
        // Render the exact upload dependency fragment from the shipped theme, including its real jQuery/SRI.
        if (!preg_match('~<script[^>]*src="[^"\n]*jquery[^"\n]*\.js"[^>]*></script>\s*<meta name="mac-upload-csrf"[^>]*>\s*<script[^>]*upload_csrf[^>]*></script>~',file_get_contents($source.'/'.$include),$fragment)) {
            throw new RuntimeException('Theme lost its upload CSRF dependency fragment');
        }
        renderUploadSource($fragment[0],['maccms'=>['path'=>'/','path_tpl'=>'/template/demo/']]);
    }
    if ($client === 'layui') {
        echo '<button id="pick">upload</button><script>layui.use(["upload"],function(){layui.upload.render({elem:"#pick",url:"/admin.php/upload/upload?flag=vod",done:function(data){window.uploadResult=data;}});window.clientReady=true;});</script>';
    } elseif ($client === 'ueditor') {
        renderUploadTemplate($source.'/application/admin/view/extend/editor/ueditor.html', ['cl'=>'vod','editor'=>'ueditor']);
        echo '<script id="editor" type="text/plain"></script><script>window.auditEditor=editor_getEditor("editor");auditEditor.ready(function(){window.clientReady=true;});</script>';
    } elseif ($client === 'deferred') {
        echo '<input type="file" id="macUserPortraitFile"><script>function checkcookie(){};var maccms={base_url:""};var MAC={alert:function(){}};</script><script src="/template/default/asset/js/head-defer-public.js"></script><script>$(function(){window.clientReady=true;});</script>';
    } else {
        $plugin=match($client) {
            'demo'=>'/template/demo/js/jquery.imageupload.safe.js',
            'default'=>'/template/default/asset/js/jquery.imageupload.js',
            'static_new'=>'/static_new/js/jquery.imageupload.js',
            default=>'/static/js/jquery.imageupload.js',
        };
        echo '<script src="'.$plugin.'"></script><img id="portrait" src="/sample.png"><script>$("#portrait").imageUpload({formAction:"/index.php/user/portrait",inputFileName:"file",automaticUpload:true,hover:false});window.clientReady=true;</script>';
    }
    exit;
}
if ($path === '/sample.png' || str_starts_with($path,'/upload/')) {
    header('Content-Type: image/png'); readfile('source.png'); exit;
}
if (!preg_match('~^/(admin|index)\.php/(upload/upload|user/portrait)(?:\.html)?$~', $path)) { http_response_code(404); exit; }
$GLOBALS['upload_cookies'] = $_COOKIE;
if (($_COOKIE['audit_admin'] ?? '') === 'yes') { uploadIdentityAdmin(); }
$GLOBALS['upload_session']['__csrf_token__'] = 'upload-browser-csrf';
$request=(new \think\Request())->withServer($_SERVER)->withHeader(getallheaders())->withGet($_GET)->withPost($_POST)->withFiles($_FILES);
$request->setPathinfo(ENTRANCE === 'admin' ? 'upload/upload' : 'user/portrait');
\think\Container::getInstance()->instance('request',$request);
$GLOBALS['config']['app']['security_csrf_admin'] = '0';
$GLOBALS['config']['app']['security_csrf_admin_exempt'] = 'upload/*';
foreach (['static','static_new'] as $folder) { mkdir($folder.'/ueditor',0777,true); copy($source.'/'.$folder.'/ueditor/config.json',$folder.'/ueditor/config.json'); }
$before=uploadIdentitySnapshot();
$GLOBALS['upload_identity_before_cleanup']=static function () use ($before,$remoteBrowser): void {
    $after=uploadIdentitySnapshot();
    header('X-Audit-Unchanged: '.($before === $after ? 'yes' : 'no'));
    header('X-Audit-Annex-Count: '.\think\facade\Db::name('Annex')->count());
    if ($remoteBrowser) {header('X-Audit-Remote-Count: '.\think\facade\Db::name('StorageIntent')->where('reference_state','committed')->count());}
};
header('Content-Type: application/json');
try {
    (new \app\middleware\CsrfGuard())->handle($request, static function () {
        echo json_encode(uploadIdentityController(ENTRANCE === 'admin' ? 'admin' : 'member'),JSON_THROW_ON_ERROR);
    });
} catch (\think\exception\HttpResponseException $error) {
    http_response_code($error->getResponse()->getCode());
    echo $error->getResponse()->getContent();
}
