<?php
/** Managed file read/write/delete boundary regressions in temporary roots. */
require __DIR__ . "/fixtures/security_audit_controller_stubs.php";
require dirname(__DIR__) . '/application/admin/controller/Base.php';
require dirname(__DIR__) . '/application/admin/controller/Template.php';
require dirname(__DIR__) . '/application/admin/controller/Images.php';
require dirname(__DIR__) . '/application/admin/controller/Annex.php';
$temp = audit_temp_dir('paths');
define('ROOT_PATH', $temp . '/');
try {
foreach (['template', 'template_backup', 'upload', 'upload_backup', 'outside'] as $dir) {
    mkdir($temp . '/' . $dir);
    file_put_contents($temp . '/' . $dir . '/sentinel.html', 'untouched');
}
symlink($temp . '/outside', $temp . '/template/escape');
symlink($temp . '/outside', $temp . '/upload/escape');
symlink($temp . '/template/sentinel.html', $temp . '/template/file-link.html');
$resolve = new \ReflectionMethod(\app\admin\controller\Base::class, 'resolveManagedPath');
foreach ([['./template_backup/sentinel.html', 'template'], ['./upload_backup/sentinel.html', 'upload'],
    ['./template/escape/sentinel.html', 'template'], ['./upload/escape/sentinel.html', 'upload'],
    ['./template/../outside/sentinel.html', 'template'], [[], 'template'], ["./template/a\0.html", 'template'],
    ['./template/file-link.html', 'template'],
    ['./template/escape/new.html', 'template']] as [$path, $root]) {
    check($resolve->invoke(null, $path, $root, true) === null, 'Managed path escaped its root');
}
check($resolve->invoke(null, './template/sentinel.html', 'template') === $temp . '/template/sentinel.html', 'Valid file rejected');
check($resolve->invoke(null, './template/new.html', 'template', true) === $temp . '/template/new.html', 'Valid new file rejected');

$template = (new \ReflectionClass(\app\admin\controller\Template::class))->newInstanceWithoutConstructor();
$images = (new \ReflectionClass(\app\admin\controller\Images::class))->newInstanceWithoutConstructor();
$GLOBALS['audit_request'] = new AuditRequest();
foreach (['./template_backup', './template/escape'] as $path) {
    \think\facade\Request::$input = ['fpath' => $path, 'fname' => 'sentinel.html'];
    check($template->info()['ok'] === false, 'Out of root file read allowed');
    \think\facade\Request::$input = ['fname' => $path . '/sentinel.html'];
    check($template->del()['ok'] === false, 'Out of root template deletion allowed');
}
foreach (['./upload_backup/sentinel.html', './upload/escape/sentinel.html'] as $path) {
    \think\facade\Request::$input = ['ids' => [$path]];
    check($images->del()['ok'] === false, 'Out of root image deletion allowed');
}
check(file_get_contents($temp . '/outside/sentinel.html') === 'untouched', 'Outside file changed');
check(file_get_contents($temp . '/template_backup/sentinel.html') === 'untouched', 'Sibling file changed');
\think\facade\Request::$input = ['ids' => './upload/sentinel.html'];
check($images->del()['ok'] === true && !file_exists($temp . '/upload/sentinel.html'), 'Valid image deletion failed');

$annex = (new \ReflectionClass(\app\admin\controller\Annex::class))->newInstanceWithoutConstructor();
foreach (['@upload_backup', '@upload@escape'] as $path) {
    \think\facade\Request::$input = ['path' => $path];
    check($annex->file()['ok'] === false, 'Attachment browser escaped its managed root');
}
echo 'Managed path regressions: ' . $checks . " assertions passed\n";
} finally { audit_remove_temp($temp); }
