<?php
/** Actual auth, Comment model and isolated installed tables; no application initialization. */
declare(strict_types=1);
require dirname(__DIR__, 2) . '/vendor/autoload.php';
require __DIR__ . '/security_audit_test_helpers.php';
use think\facade\Db;
function lang($key, $vars = []) { return $key; }
function config($key, $default = null) { return think\facade\Config::get($key, $default); }
function cookie($key, $value = '', $options = []) {
    if ($value === '') { return $GLOBALS['comment_cookies'][$key] ?? ''; }
    $GLOBALS['comment_cookies'][$key] = $value;
}
function request() { return think\Container::getInstance()->make('request'); }
function json($data) { return $data; }
function mac_validate($name) { $class = 'app\\common\\validate\\' . $name; return new $class(); }
function mac_filter_xss($value) { return $value; }
function mac_filter_words($value) { return $value; }
function mac_get_ip_long() { return '2130706433'; }
function mac_fe_write_throttle($scope, $window, $count) { return !$GLOBALS['comment_throttled']; }
class CommentAuditCaptcha {
    public function check($value) { return $value === 'fixture-valid-captcha'; }
}
class CommentAuditCache {
    public function get($key, $default = null) {
        return [1=>['group_id'=>1,'group_name'=>'guest'],2=>['group_id'=>2,'group_name'=>'registered']];
    }
}
class CommentAuditRequest extends think\Request {
    public function isCli(): bool { return false; }
}
$mysql = getenv('MEMBERSHIP_AUDIT_MYSQL') === '1';
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_membership' : ':memory:',
    'prefix'=>'audit_', 'hostname'=>getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
    'password'=>getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '', 'charset'=>'utf8mb4', 'trigger_sql'=>false, 'fields_cache'=>false,
]]];
$manager = new think\DbManager();
$manager->setConfig($configuration);
$fixtureConfig = new think\Config();
$fixtureConfig->set($configuration, 'database');
think\Container::getInstance()->instance('think\\DbManager', $manager);
think\Container::getInstance()->instance('config', $fixtureConfig);
think\Container::getInstance()->instance('cache', new CommentAuditCache());
think\Container::getInstance()->instance('think\\captcha\\Captcha', new CommentAuditCaptcha());
$targets = ['vod','art','topic','actor','role','website','manga'];
if ($mysql) {
    $ddl = file_get_contents(dirname(__DIR__, 2) . '/application/install/sql/install.sql');
    foreach (array_merge(['user','comment'], $targets) as $table) {
        if (!preg_match('/CREATE TABLE `mac_' . $table . '` \\([\\s\\S]*?\\) ENGINE[^;]*;/', $ddl, $match)) {
            throw new RuntimeException('Installation comment schema missing');
        }
        Db::execute('DROP TABLE IF EXISTS audit_' . $table);
        Db::execute(str_replace('`mac_' . $table . '`', '`audit_' . $table . '`', $match[0]));
    }
    Db::execute("SET SESSION sql_mode=''");
} else {
    Db::execute('CREATE TABLE audit_user (user_id INTEGER PRIMARY KEY, user_name TEXT, user_nick_name TEXT,
        user_random TEXT, user_status INTEGER DEFAULT 1, group_id TEXT DEFAULT "2", user_end_time INTEGER DEFAULT 0)');
    Db::execute('CREATE TABLE audit_comment (comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        comment_mid INTEGER DEFAULT 1, comment_rid INTEGER DEFAULT 0, comment_pid INTEGER DEFAULT 0,
        user_id INTEGER DEFAULT 0, comment_status INTEGER DEFAULT 1, comment_name TEXT, comment_ip INTEGER,
        comment_time INTEGER, comment_content TEXT, comment_up INTEGER DEFAULT 0, comment_down INTEGER DEFAULT 0,
        comment_reply INTEGER DEFAULT 0, comment_report INTEGER DEFAULT 0)');
    foreach ($targets as $target) {
        Db::execute('CREATE TABLE audit_' . $target . ' (' . $target . '_id INTEGER PRIMARY KEY, ' . $target . '_status INTEGER DEFAULT 1)');
        if (in_array($target, ['vod','art','manga'], true)) {
            Db::execute('ALTER TABLE audit_' . $target . ' ADD COLUMN ' . $target . '_recycle_time INTEGER DEFAULT 0');
        }
    }
}
function commentSeed(): void {
    $GLOBALS['comment_cookies'] = [];
    $GLOBALS['comment_throttled'] = false;
    $GLOBALS['config'] = ['app'=>['cache_flag'=>'comment_audit','api_jwt_enabled'=>'0'],
        'comment'=>['status'=>'1','login'=>'0','verify'=>'0','audit'=>'0','timespan'=>'30']];
    think\facade\Config::set(['black_keyword_list'=>[], 'black_ip_list'=>[]], 'blacks');
    Db::name('Comment')->delete(true);
    Db::name('User')->delete(true);
    foreach ([1=>'alice',2=>'bob'] as $uid=>$name) {
        Db::name('User')->insert(['user_id'=>$uid, 'user_name'=>$name, 'user_nick_name'=>$name . '-nickname',
            'user_random'=>'fixture-nonce-' . $uid, 'user_status'=>1,'group_id'=>'2']);
    }
    foreach (['vod','art','topic','actor','role','website','manga'] as $target) {
        Db::name($target)->delete(true);
        Db::name($target)->insert([$target . '_id'=>1, $target . '_status'=>1]);
        Db::name($target)->insert([$target . '_id'=>2, $target . '_status'=>0]);
    }
    Db::name('Comment')->insert(['comment_id'=>1,'comment_mid'=>1,'comment_rid'=>1,'user_id'=>2,
        'comment_name'=>'original','comment_content'=>'unchanged','comment_time'=>1,'comment_ip'=>0]);
}
function commentLogin(int $uid = 1): void {
    $row = Db::name('User')->find($uid);
    $GLOBALS['comment_cookies'] = ['user_id'=>(string)$uid,'user_name'=>$row['user_name'],
        'user_check'=>md5($row['user_random'] . '-' . $row['user_name'] . '-' . $uid . '-')];
}
function commentRequest(array $body, string $method = 'POST', array $query = [], string $bearer = ''): think\Request {
    $request = (new CommentAuditRequest())->withServer(['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.test']);
    $request->withGet($query)->withPost($body)->withHeader(['Authorization'=>$bearer]);
    think\Container::getInstance()->instance('request', $request);
    return $request;
}
function publicComment(string $entry, array $body, string $method = 'POST', array $query = [], string $bearer = ''): array {
    $request = commentRequest($body, $method, $query, $bearer);
    $class = $entry === 'index' ? app\index\controller\Comment::class : app\api\controller\Comment::class;
    $controller = (new ReflectionClass($class))->newInstanceWithoutConstructor();
    return $entry === 'index' ? $controller->saveData() : $controller->submit($request);
}
function commentRows(): array { return Db::name('Comment')->order('comment_id')->select()->toArray(); }
