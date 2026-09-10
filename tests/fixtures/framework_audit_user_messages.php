<?php
/** Isolated real User/Msg ORM. No production configuration, accounts, or delivery services are loaded. */
declare(strict_types=1);
require dirname(__DIR__, 2) . '/vendor/autoload.php';
require __DIR__ . '/security_audit_test_helpers.php';

function lang($key, $vars = []) { return $key; }
function request() { return \think\Container::getInstance()->make('request'); }
function config($key, $default = null) { return \think\facade\Config::get($key, $default); }
function mac_fe_write_throttle(...$args) { return $GLOBALS['message_fixture_throttle']; }
function mac_get_rndstr(...$args) { return '123456'; }
function mac_password_hash($password) {
    if ($GLOBALS['message_fixture_password_write_failure']) { return 'fixture-reject-write'; }
    return password_hash($password, PASSWORD_BCRYPT);
}
function mac_validate($name) { $class = 'app\\common\\validate\\'.$name; return new $class(); }
function mac_send_mail($to, $title, $body) { return messageFixtureDelivery('email', $to); }
function mac_send_sms($to, ...$args) { return messageFixtureDelivery('phone', $to); }
function messageFixtureDelivery(string $channel, string $target) {
    if (!in_array($target, ['fixture@example.invalid', 'fixture+tag@example.invalid', '13000000000'], true)) {
        throw new RuntimeException('Unexpected fixture recipient');
    }
    $GLOBALS['message_fixture_deliveries'][] = [$channel, $target];
    if ($GLOBALS['message_fixture_delivery'] instanceof Throwable) { throw $GLOBALS['message_fixture_delivery']; }
    return $GLOBALS['message_fixture_delivery'];
}
$temp = audit_temp_dir('user-messages');
register_shutdown_function(static function () use ($temp): void { audit_remove_temp($temp); });
$app = new \think\App($temp);
$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_user_messages' : ':memory:',
    'prefix'=>'audit_', 'trigger_sql'=>false, 'fields_cache'=>false, 'charset'=>'utf8mb4',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
    'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '',
]]];
$app->config->set($configuration, 'database');
$manager = new \think\DbManager();
$manager->setConfig($configuration);
$app->instance('think\\DbManager', $manager);
$app->instance('view', new class {
    public function assign($data) { return $this; }
    public function display($text) { return $text; }
});
$app->instance('log', new class {
    public function record($message, $type = 'info') { $GLOBALS['message_fixture_logs'][] = $type; }
    public function error($message) { $GLOBALS['message_fixture_logs'][] = 'error'; }
});
if ($mysql) {
    \think\facade\Db::execute("SET SESSION sql_mode=''");
    $ddl = file_get_contents(dirname(__DIR__, 2).'/application/install/sql/install.sql');
    foreach (['user', 'msg'] as $table) {
        if (!preg_match('/CREATE TABLE `mac_'.$table.'` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
            throw new RuntimeException('Required installation schema missing');
        }
        \think\facade\Db::execute('DROP TABLE IF EXISTS audit_'.$table);
        \think\facade\Db::execute(str_replace('`mac_'.$table.'`', '`audit_'.$table.'`', $match[0]));
    }
    \think\facade\Db::execute('ALTER TABLE audit_user ADD CONSTRAINT fixture_password_write CHECK(user_pwd != "fixture-reject-write")');
} else {
    \think\facade\Db::execute('CREATE TABLE audit_user (user_id INTEGER PRIMARY KEY, user_name TEXT, user_email TEXT,
        user_phone TEXT, user_question TEXT, user_answer TEXT, user_status INTEGER DEFAULT 1, user_pwd TEXT CHECK(user_pwd != "fixture-reject-write"),
        user_random TEXT DEFAULT "fixture-session")');
    \think\facade\Db::execute('CREATE TABLE audit_msg (msg_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER DEFAULT 0,
        msg_type INTEGER DEFAULT 0, msg_status INTEGER DEFAULT 0, msg_to TEXT, msg_code TEXT, msg_content TEXT, msg_time INTEGER)');
}

function messageFixtureTrigger(string $name, string $table, string $operation): void {
    global $mysql;
    if (!in_array($name, ['audit_message_insert_failure', 'audit_message_consume_failure'], true)
        || $table !== 'audit_msg' || !in_array($operation, ['INSERT', 'UPDATE'], true)) {
        throw new RuntimeException('Unexpected fault fixture');
    }
    $body = $mysql
        ? "FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Fixture database write failure'"
        : "BEGIN SELECT RAISE(ABORT, 'Fixture database write failure'); END";
    \think\facade\Db::execute('CREATE TRIGGER '.$name.' BEFORE '.$operation.' ON '.$table.' '.$body);
}

function messageFixtureSeed(): void {
    \think\facade\Db::execute('DELETE FROM audit_msg');
    \think\facade\Db::execute('DELETE FROM audit_user');
    \think\facade\Db::name('User')->insert(['user_id'=>1, 'user_name'=>'fixture-user', 'user_email'=>'fixture@example.invalid',
        'user_phone'=>'13000000000', 'user_question'=>'Fixture question', 'user_answer'=>'Fixture answer', 'user_status'=>1,
        'user_pwd'=>'fixture-original-password', 'user_random'=>'0123456789abcdef0123456789abcdef']);
    $GLOBALS['config'] = ['app'=>['cache_flag'=>'fixture'], 'user'=>[],
        'email'=>['time'=>'5', 'tpl'=>[
            'user_bind_title'=>'Fixture binding', 'user_bind_body'=>'Fixture code',
            'user_reg_title'=>'Fixture registration', 'user_reg_body'=>'Fixture code',
            'user_findpass_title'=>'Fixture reset', 'user_findpass_body'=>'Fixture code',
        ]], 'sms'=>['content'=>'Fixture [类型] [验证码]'],
    ];
    $GLOBALS['user'] = ['user_id'=>0, 'user_name'=>''];
    $GLOBALS['message_fixture_throttle'] = true;
    $GLOBALS['message_fixture_password_write_failure'] = false;
    $GLOBALS['message_fixture_delivery'] = ['code'=>1, 'msg'=>'Fixture accepted'];
    $GLOBALS['message_fixture_deliveries'] = $GLOBALS['message_fixture_logs'] = [];
}
function messageFixtureRow(array $overrides = []): array {
    return $overrides + ['user_id'=>0, 'msg_type'=>2, 'msg_status'=>0, 'msg_to'=>'fixture@example.invalid',
        'msg_code'=>'123456', 'msg_content'=>'Fixture code', 'msg_time'=>time()];
}
function messageFixtureParam(array $overrides = []): array {
    return $overrides + ['ac'=>'email', 'to'=>'fixture@example.invalid', 'code'=>'123456', 'type'=>2];
}
function messageFixtureState(): array {
    return [\think\facade\Db::name('User')->order('user_id')->select()->toArray(),
        \think\facade\Db::name('Msg')->order('msg_id')->select()->toArray()];
}
