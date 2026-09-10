<?php
/**
 * PHP 8.3/8.4 model regressions using real Think ORM + an isolated database.
 * No App::initialize(), middleware, site configuration, application DB or network is used.
 * Shared fixture for the independently runnable framework audit regression groups.
 * Optional MySQL: FRAMEWORK_AUDIT_MYSQL=1, FRAMEWORK_AUDIT_HOST / FRAMEWORK_AUDIT_PASSWORD.
 * MySQL always uses the dedicated maccms_audit_models database and replaces its audit_* tables.
 */
declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use think\Container;
use think\facade\Db;

$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
if (!extension_loaded($mysql ? 'pdo_mysql' : 'pdo_sqlite')) {
    fwrite(STDERR, "The selected PDO driver is required\n");
    exit(2);
}
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    throw new ErrorException($message, 0, $level, $file, $line);
});

function lang($key, $vars = []) { return $key; }
function config($key, $default = null) { return think\facade\Config::get($key, $default); }
function mac_get_vip_exclusive_type_ids() { return []; }
function mac_param_url() { return $GLOBALS['audit_url_params'] ?? []; }
function mac_search_len_check($params) { return $params; }
function mac_url($url, $params) { return $url; }
function mac_safe_order($prefix, $by, $order) { return $prefix . $by . ' ' . $order; }

function session($key, $value = null) {
    if (func_num_args() === 1) { return $GLOBALS['audit_session'][$key] ?? null; }
    if ($value === null) { unset($GLOBALS['audit_session'][$key]); } else { $GLOBALS['audit_session'][$key] = $value; }
}
function mac_password_verify($password, $hash) { return password_verify($password, $hash); }
function mac_password_hash($password) { return password_hash($password, PASSWORD_DEFAULT); }
function mac_password_need_rehash($hash) { return password_needs_rehash($hash, PASSWORD_DEFAULT); }
function mac_get_ip_long() { return 0; }
class FrameworkAuditSession {
    public function regenerate($destroy = false) {}
}
function mac_validate($name) {
    if ($name === 'Plog' && !empty($GLOBALS['audit_plog_error'])) {
        throw new TypeError('injected log failure');
    }
    $class = 'app\\common\\validate\\' . $name;
    return new $class();
}
class FrameworkAuditDb extends think\DbManager {
    public $beforeStart;
    public function startTrans(): void {
        // Reproduce a second callback committing after the first read but before its transaction.
        $hook = $this->beforeStart;
        $this->beforeStart = null;
        if ($hook) { $hook(); }
        $this->connect()->startTrans();
    }
}
class FrameworkAuditCache {
    public function get($key, $default = null) { return [1 => ['group_id' => 1, 'group_name' => 'test']]; }
}
$configuration = [
    'default' => 'audit', 'auto_timestamp' => false,
    'connections' => ['audit' => [
        'type' => $mysql ? 'mysql' : 'sqlite',
        'database' => $mysql ? 'maccms_audit_models' : ':memory:', 'prefix' => 'audit_',
        'hostname' => getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1',
        'username' => 'root', 'password' => getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '',
        'charset' => 'utf8mb4',
        'trigger_sql' => false, 'fields_cache' => false,
    ]],
];
$manager = new FrameworkAuditDb();
$manager->setConfig($configuration);
$config = new think\Config();
$config->set($configuration, 'database');
Container::getInstance()->instance('think\\DbManager', $manager);
Container::getInstance()->instance('config', $config);
Container::getInstance()->instance('cache', new FrameworkAuditCache());
Container::getInstance()->instance('session', new FrameworkAuditSession());
$GLOBALS['config'] = [
    'app' => ['cache_flag' => 'audit', 'count_cache_sec' => 0, 'admin_login_verify' => '0', 'cache_core' => 0, 'cache_time' => 60],
    'user' => ['cash_status' => '1', 'cash_min' => 1, 'cash_ratio' => 1],
];

$allAuditSchemas = [
    'rows' => 'row_id INTEGER PRIMARY KEY, label TEXT',
    'query_vod' => 'vod_id INTEGER PRIMARY KEY, vod_status INTEGER, vod_name TEXT, vod_actor TEXT, vod_director TEXT, vod_tag TEXT',
    'type' => 'type_id INTEGER PRIMARY KEY, type_pid INTEGER',
    'annex' => 'annex_id INTEGER PRIMARY KEY',
    'comment' => 'comment_id INTEGER PRIMARY KEY',
    'manga' => 'manga_id INTEGER PRIMARY KEY, manga_recycle_time INTEGER DEFAULT 0',
    'msg' => 'msg_id INTEGER PRIMARY KEY',
    'visit' => 'visit_id INTEGER PRIMARY KEY',
    'actor' => 'actor_id INTEGER PRIMARY KEY, actor_status INTEGER, type_id INTEGER, type_id_1 INTEGER',
    'website' => 'website_id INTEGER PRIMARY KEY, website_status INTEGER, type_id INTEGER, type_id_1 INTEGER',
    'group' => 'group_id INTEGER PRIMARY KEY, group_name TEXT',
    'cj_node' => 'nodeid INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, lastdate INTEGER, urlpage TEXT, page_base TEXT, sourcecharset TEXT, customize_config TEXT, program_config TEXT',
    'admin' => 'admin_id INTEGER PRIMARY KEY, admin_name TEXT, admin_pwd TEXT, admin_status INTEGER, admin_auth TEXT, admin_random TEXT, admin_login_ip INTEGER DEFAULT 0, admin_login_time INTEGER DEFAULT 0, admin_login_num INTEGER DEFAULT 0, admin_last_login_time INTEGER DEFAULT 0, admin_last_login_ip INTEGER DEFAULT 0',
    'user' => 'user_id INTEGER PRIMARY KEY, user_name TEXT, group_id TEXT DEFAULT "1", user_points INTEGER DEFAULT 0, user_points_froze INTEGER DEFAULT 0',
    'order' => 'order_id INTEGER PRIMARY KEY, order_code TEXT, order_status INTEGER DEFAULT 0, order_price REAL, order_points INTEGER, user_id INTEGER, order_pay_time INTEGER, order_pay_type TEXT, order_remarks TEXT DEFAULT ""',
    'cash' => 'cash_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, cash_money REAL, cash_points INTEGER, cash_time INTEGER, cash_status INTEGER DEFAULT 0, cash_time_audit INTEGER, cash_bank_name TEXT, cash_bank_no TEXT, cash_payee_name TEXT',
    'plog' => 'plog_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plog_type INTEGER, plog_points INTEGER, plog_time INTEGER',
];
foreach (array_intersect_key($allAuditSchemas, array_flip($frameworkAuditTables)) as $table => $columns) {
    if ($mysql) {
        $columns = str_replace(['AUTOINCREMENT', 'group_id TEXT DEFAULT "1"', 'order_remarks TEXT DEFAULT ""'],
            ['AUTO_INCREMENT', 'group_id VARCHAR(16) DEFAULT "1"', 'order_remarks VARCHAR(255) DEFAULT ""'], $columns);
        Db::execute('DROP TABLE IF EXISTS audit_' . $table);
    }
    Db::execute('CREATE TABLE audit_' . $table . ' (' . $columns . ')' . ($mysql ? ' ENGINE=InnoDB' : ''));
}
$checks = 0;
function expect($condition, string $message): void {
    global $checks;
    ++$checks;
    if (!$condition) { throw new RuntimeException($message); }
}
function seed(): void {
    global $frameworkAuditTables;
    foreach (array_intersect(['cash', 'order', 'plog', 'user'], $frameworkAuditTables) as $table) { Db::execute('DELETE FROM audit_' . $table); }
    Db::name('User')->insert(['user_id'=>1,'user_name'=>'one','group_id'=>'1','user_points'=>100,'user_points_froze'=>0]);
    Db::name('User')->insert(['user_id'=>2,'user_name'=>'two','group_id'=>'1','user_points'=>100,'user_points_froze'=>0]);
    $GLOBALS['user'] = ['user_id'=>1,'user_points'=>100,'user_points_froze'=>0];
    $GLOBALS['audit_plog_error'] = false;
}
function orderSeed(): void {
    Db::name('Order')->insert(['order_id'=>1,'order_code'=>'once','order_price'=>10,'order_points'=>20,'user_id'=>1]);
}
function balance(int $id = 1): array {
    return Db::name('User')->where('user_id', $id)->find();
}
function finishFrameworkAudit(string $suite): void {
    global $checks, $mysql;
    echo $suite . ': ' . $checks . ' checks passed on PHP ' . PHP_VERSION
        . ' / ' . ($mysql ? 'MySQL' : 'SQLite') . PHP_EOL;
}
