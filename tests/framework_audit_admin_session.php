<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\Admin;

$frameworkAuditTables = ['admin'];
require __DIR__ . '/fixtures/framework_audit_db.php';

// Administrator sessions must follow live account status and permissions.
Db::name('Admin')->insert([
    'admin_id'=>2,'admin_name'=>'editor','admin_pwd'=>password_hash('audit-secret', PASSWORD_BCRYPT, ['cost'=>4]),
    'admin_status'=>1,'admin_auth'=>',vod/data,vod/del,','admin_random'=>'initial',
]);
$admin = new Admin();
expect($admin->login(['admin_name'=>'editor','admin_pwd'=>'audit-secret'])['code'] === 1, 'Valid admin login');
expect($admin->checkLogin()['code'] === 1, 'Password rehash during login must not invalidate the new session');
expect(!isset($admin->checkLogin()['info']['admin_pwd']), 'Authorization result must omit password hash');
Db::name('Admin')->where('admin_id', 2)->update(['admin_auth'=>',vod/data,']);
expect($admin->checkLogin()['info']['admin_auth'] === ',vod/data,', 'Permission revocation must affect existing sessions');
foreach ([['admin_status'=>0], ['admin_name'=>'renamed'], ['admin_pwd'=>password_hash('new-password', PASSWORD_DEFAULT)]] as $change) {
    $saved = Db::name('Admin')->where('admin_id', 2)->find();
    session('admin_auth', '1'); session('admin_info', $saved);
    Db::name('Admin')->where('admin_id', 2)->update($change);
    expect($admin->checkLogin()['code'] !== 1 && session('admin_auth') === null, 'Account security changes must revoke old sessions');
    Db::name('Admin')->where('admin_id', 2)->update($saved);
}
$saved = Db::name('Admin')->where('admin_id', 2)->find();
session('admin_auth', '1'); session('admin_info', $saved);
Db::name('Admin')->where('admin_id', 2)->delete();
expect($admin->checkLogin()['code'] !== 1 && session('admin_info') === null, 'Deleted administrator must lose access');
session('admin_auth', '1'); session('admin_info', ['admin_id'=>2]);
expect($admin->checkLogin()['code'] !== 1, 'Incomplete admin session must fail closed');


finishFrameworkAudit('framework_audit_admin_session');
