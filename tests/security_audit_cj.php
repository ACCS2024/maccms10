<?php
/** Collection content deletion must remove every associated history fingerprint. */
require __DIR__ . '/fixtures/security_audit_runtime_stubs.php';
require dirname(__DIR__) . '/application/admin/controller/Cj.php';
use think\facade\Db;
Db::execute('CREATE TABLE audit_cj_content (id INTEGER PRIMARY KEY, url TEXT)');
Db::execute('CREATE TABLE audit_cj_history (md5 TEXT PRIMARY KEY)');
foreach ([1, 2, 3] as $id) {
    $url = 'https://fixture.example/' . $id;
    Db::name('cj_content')->insert(['id' => $id, 'url' => $url]);
    Db::name('cj_history')->insert(['md5' => md5($url)]);
}
$controller = (new ReflectionClass(app\admin\controller\Cj::class))->newInstanceWithoutConstructor();
think\facade\Request::$input = ['ids' => [1, 2]];
check($controller->content_del()['ok'] === true, 'Collection deletion failed');
check(Db::name('cj_content')->column('id') === [3], 'Collection deletion changed the wrong content');
check(Db::name('cj_history')->column('md5') === [md5('https://fixture.example/3')], 'Only the last selected history fingerprint was removed');
think\facade\Request::$input = ['ids' => [99]];
check($controller->content_del()['ok'] === true, 'Empty selection caused an undefined fingerprint');
check(Db::name('cj_history')->count() === 1, 'Empty selection deleted unrelated history');
think\facade\Request::$input = [];
check($controller->content_del()['ok'] === true, 'Missing optional selection raised a diagnostic');
echo 'Collection deletion regressions: ' . $checks . " assertions passed\n";
