<?php
/** Admin account, grant and Update route authorization regressions. */
require __DIR__ . "/fixtures/security_audit_controller_stubs.php";
require dirname(__DIR__) . '/application/admin/controller/Base.php';
require dirname(__DIR__) . '/application/admin/controller/Admin.php';
$admin = (new \ReflectionClass(\app\admin\controller\Admin::class))->newInstanceWithoutConstructor();
$admin->_admin = ['admin_id' => 2, 'admin_auth' => ',admin/info,vod/info,'];
$GLOBALS['audit_request'] = new AuditRequest('', true);
foreach ([['admin_id' => 1, 'admin_pwd' => 'changed'], ['admin_id' => 2, 'admin_auth' => ['system/config']],
    ['admin_id' => [], 'admin_auth' => []], ['admin_auth' => 'system/config']] as $input) {
    \think\facade\Request::$input = $input;
    check($admin->info()['ok'] === false, 'Admin account or grant boundary bypass');
}
foreach ([1, '1,2', ['1'], [['1']]] as $ids) {
    \think\facade\Request::$input = ['ids' => $ids, 'col' => 'admin_status', 'val' => '0'];
    check($admin->del()['ok'] === false, 'Superadmin deletion allowed');
    check($admin->field()['ok'] === false, 'Superadmin deactivation allowed');
}
check(!$admin->check_auth('Update', 'step2'), 'Ungrantable upgrade permission allowed');
check($admin->check_auth('Vod', 'info'), 'Valid delegated permission rejected');
$admin->_admin = ['admin_id' => 1, 'admin_auth' => ''];
\think\facade\Request::$input = ['admin_id' => 1, 'admin_status' => 0];
check($admin->info()['ok'] === false, 'Superadmin disabled itself through account form');
define('ENTRANCE', 'admin');
$GLOBALS['config'] = ['app' => ['pagesize' => 20, 'makesize' => 20]];
try {
    new \app\admin\controller\Base();
    check(false, 'Update route bypassed the constructor authorization gate');
} catch (\think\exception\HttpResponseException $e) {
    check($e->response['ok'] === false, 'Unexpected authorization response');
}

echo 'Admin authorization regressions: ' . $checks . " assertions passed\n";
