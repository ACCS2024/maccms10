<?php
/** Real User/JWT/ORM; isolated credentials and user table, no App bootstrap. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\User;
use app\common\util\JwtService;
$frameworkAuditTables = ['user'];
require __DIR__.'/fixtures/framework_audit_db.php';
function cookie($key, $value = null, $options = []) {
    if (func_num_args() === 1) { return $GLOBALS['member_session_cookies'][$key] ?? null; }
    $GLOBALS['member_session_cookies'][$key] = $value;
}
function request() { return $GLOBALS['member_session_request']; }
$GLOBALS['member_session_request'] = new think\Request();
Db::execute('ALTER TABLE audit_user ADD COLUMN user_random VARCHAR(64)');
Db::name('User')->insert(['user_id'=>1,'user_name'=>'member','user_random'=>md5('fixture-session')]);
$valid = ['user_id'=>'1','user_name'=>'member','user_check'=>md5(md5('fixture-session').'-member-1-')];
$model = new User();
$GLOBALS['member_session_cookies'] = [];
expect($model->checkLogin()['code'] === 1001, 'Absent cookies must return not logged in without diagnostics');
foreach (array_keys($valid) as $field) {
    foreach ([null, [], ['nested'=>'x'], true, false, 1.5, new stdClass(), ''] as $bad) {
        $GLOBALS['member_session_cookies'] = array_replace($valid, [$field=>$bad]);
        expect($model->checkLogin()['code'] !== 1, 'Malformed credential accepted: '.$field);
    }
}
foreach (['0','-1','1x','1e0','%31','4294967296',str_repeat('1',129)] as $bad) {
    $GLOBALS['member_session_cookies'] = array_replace($valid,['user_id'=>$bad]);
    expect($model->checkLogin()['code'] !== 1,'Malformed owner cookie accepted');
}
foreach ([['user_check'=>str_repeat('0',32)],['user_check'=>str_repeat('a',257)],['user_name'=>str_repeat('a',1025)] ] as $bad) {
    $GLOBALS['member_session_cookies'] = array_replace($valid,$bad);
    expect($model->checkLogin()['code'] !== 1,'Invalid/oversized cookie accepted');
}
foreach (['1',1] as $id) {
    $GLOBALS['member_session_cookies'] = array_replace($valid,['user_id'=>$id]);
    expect($model->checkLogin()['code'] === 1,'Valid original parsed cookie stopped working');
}
foreach ([['user_status'=>0],['user_random'=>'rotated'],['user_name'=>'renamed']] as $change) {
    $GLOBALS['member_session_cookies'] = $valid;
    $before=Db::name('User')->find(1);Db::name('User')->where('user_id',1)->update($change);
    expect($model->checkLogin()['code'] !== 1,'Account change did not invalidate cookie credentials');
    Db::name('User')->where('user_id',1)->update($before);
}
$GLOBALS['config']['app'] += ['api_jwt_enabled'=>'1','api_jwt_secret'=>str_repeat('fixture-',8),'api_jwt_iss'=>'member-session-audit'];
$token=JwtService::encode(1,md5('fixture-session'));
$GLOBALS['member_session_cookies'] = ['user_id'=>[]];
$GLOBALS['member_session_request'] = (new think\Request())->withHeader(['authorization'=>'Bearer '.$token]);
expect($model->checkLogin()['code'] === 1,'Valid bearer credentials must not depend on cookies');
$GLOBALS['member_session_cookies'] = $valid;
$GLOBALS['member_session_request'] = (new think\Request())->withHeader(['authorization'=>'Bearer '.$token.'x']);
expect($model->checkLogin()['code'] !== 1,'Invalid enabled bearer token must not fall back to valid cookies');
$GLOBALS['member_session_request'] = new think\Request();
Db::name('User')->where('user_id',1)->delete();
expect($model->checkLogin()['code'] !== 1,'Deleted user retained cookie access');
finishFrameworkAudit('framework_audit_member_session');
