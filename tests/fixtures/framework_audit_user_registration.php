<?php
/** Dedicated registration schema; never reads application runtime credentials or calls delivery providers. */
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/security_audit_test_helpers.php';
function lang($key, $vars = []) { return $key; }
function request() { return \think\Container::getInstance()->make('request'); }
function config($key, $default = null) { return \think\facade\Config::get($key, $default); }
function mac_validate($name) { $class = 'app\\common\\validate\\'.$name; return new $class(); }
function mac_fe_write_throttle(...$args) { return $GLOBALS['registration_fixture_throttle']; }
function mac_get_ip_long() { return $GLOBALS['registration_fixture_ip']; }
function mac_password_hash($password) {
    if ($GLOBALS['registration_fixture_hash_failure']) { throw new RuntimeException('Isolated hash fixture failure'); }
    return password_hash($password, PASSWORD_BCRYPT, ['cost'=>4]);
}
function mac_password_verify($password, $hash) {
    return strlen($hash) === 32 && ctype_xdigit($hash) ? hash_equals(strtolower($hash),md5($password)) : password_verify($password,$hash);
}
function mac_password_need_rehash($hash) { return password_needs_rehash($hash,PASSWORD_BCRYPT,['cost'=>4]); }
function mac_send_mail($target, ...$args) { return registrationFixtureDelivery('email', $target); }
function mac_send_sms($target, ...$args) { return registrationFixtureDelivery('phone', $target); }
function registrationFixtureDelivery(string $channel, string $target): array {
    if (empty($GLOBALS['registration_fixture_allow_delivery']) || !in_array($target, ['fixture@example.invalid','13000000000'], true)) {
        throw new RuntimeException('Unexpected registration delivery fixture');
    }
    $GLOBALS['registration_fixture_deliveries'][] = [$channel, $target];
    return ['code'=>1];
}
$temp = audit_temp_dir('user-registration');
if (!defined('ROOT_PATH')) { define('ROOT_PATH', $temp.'/'); }
if (!defined('MAC_PATH')) { define('MAC_PATH', '/fixture/'); }
register_shutdown_function(static function() use ($temp): void { audit_remove_temp($temp); });
$app = new \think\App($temp);
$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_user_registration' : ':memory:',
    'prefix'=>'audit_', 'trigger_sql'=>false, 'fields_cache'=>false, 'charset'=>'utf8mb4',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
    'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '',
]]];
$app->config->set($configuration,'database');
$manager = new \think\DbManager(); $manager->setConfig($configuration); $app->instance('think\\DbManager',$manager);
$app->instance('log', new class { public function record(...$args) {} public function error(...$args) {} });
if ($mysql) { \think\facade\Db::execute("SET SESSION sql_mode=''"); }
if (!defined('REGISTRATION_FIXTURE_EXISTING_DB')) {
$ddl = file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
foreach (['user','msg','plog','group'] as $table) {
    if (!preg_match('/CREATE TABLE `mac_'.$table.'` \(([\s\S]*?)\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Required install DDL missing'); }
    if ($mysql) {
        \think\facade\Db::execute('DROP TABLE IF EXISTS audit_'.$table);
        \think\facade\Db::execute(str_replace('`mac_'.$table.'`','`audit_'.$table.'`',$match[0]));
    } else {
        $columns = [];
        foreach (explode("\n",$match[1]) as $line) {
            if (!preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/',$line,$field)) { continue; }
            [$unused,$name,$type,$options] = $field;
            if (str_contains($options,'AUTO_INCREMENT')) { $columns[] = $name.' INTEGER PRIMARY KEY AUTOINCREMENT'; continue; }
            $integer = str_contains($type,'int');
            $column = $name.($integer ? ' INTEGER' : ' TEXT');
            if (str_contains($options,'NOT NULL')) { $column .= ' NOT NULL'; }
            if (preg_match("/DEFAULT ('[^']*'|[0-9]+)/",$options,$default)) { $column .= ' DEFAULT '.$default[1]; }
            if (str_contains($options,'unsigned')) { $column .= ' CHECK('.$name.' BETWEEN 0 AND 4294967295)'; }
            if (preg_match('/varchar\(([0-9]+)\)/',$type,$length)) { $column .= ' CHECK(length('.$name.') <= '.$length[1].')'; }
            $columns[] = $column;
        }
        \think\facade\Db::execute('CREATE TABLE audit_'.$table.' ('.implode(',',$columns).')');
    }
}
}
function registrationFixtureConfig(array $overrides = []): void {
    global $app;
    $base = ['user'=>[
        'status'=>1,'reg_open'=>1,'reg_verify'=>0,'reg_status'=>1,'reg_phone_sms'=>0,'reg_email_sms'=>0,
        'reg_points'=>'10','reg_num'=>0,'invite_reg_points'=>0,'filter_words'=>'admin,blocked',
        'invite_reward_status'=>0,'login_verify'=>0,
    ],'app'=>['cache_flag'=>'fixture-registration','api_jwt_enabled'=>1,'api_jwt_secret'=>str_repeat('fixture-secret-',4)],
        'email'=>['time'=>5]];
    $base['user'] = array_replace($base['user'],$overrides);
    $GLOBALS['config'] = $base;
    $app->config->set($base,'maccms');
}
function registrationFixtureSeed(array $configuration = []): void {
    global $app;
    foreach (['msg','plog','user','group'] as $table) { \think\facade\Db::execute('DELETE FROM audit_'.$table); }
    foreach ([1,2,3,4,5] as $group) { \think\facade\Db::name('Group')->insert(['group_id'=>$group,'group_name'=>'Fixture '.$group,'group_status'=>1,'group_type'=>'','group_popedom'=>'']); }
    registrationFixtureConfig($configuration);
    $GLOBALS['user'] = ['user_id'=>0,'user_name'=>''];
    $GLOBALS['registration_fixture_ip'] = '2130706433';
    $GLOBALS['registration_fixture_throttle'] = true;
    $GLOBALS['registration_fixture_hash_failure'] = false;
    $GLOBALS['registration_fixture_allow_delivery'] = false;
    $GLOBALS['registration_fixture_deliveries'] = [];
    $GLOBALS['registration_fixture_captchas'] = [];
    $app->instance('request',(new \think\Request())->withHeader([]));
}
function registrationFixtureParam(array $overrides = []): array {
    return $overrides + ['user_name'=>'FixtureUser','user_pwd'=>'fixture+raw%42&password',
        'user_pwd2'=>'fixture+raw%42&password','verify'=>'fixture-captcha'];
}
function registrationFixtureState(): array {
    return [\think\facade\Db::name('User')->order('user_id')->select()->toArray(),
        \think\facade\Db::name('Msg')->order('msg_id')->select()->toArray(),
        \think\facade\Db::name('Plog')->order('plog_id')->select()->toArray()];
}
