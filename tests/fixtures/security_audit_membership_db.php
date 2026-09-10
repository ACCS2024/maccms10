<?php
/** Real ORM and isolated financial tables; MySQL uses the repository's installation DDL. */
declare(strict_types=1);
require dirname(__DIR__, 2) . '/vendor/autoload.php';
require __DIR__ . '/security_audit_test_helpers.php';
use think\facade\Db;

function lang($key, $vars = []) { return $key; }
function config($key, $default = null) { return think\facade\Config::get($key, $default); }
function cookie($key, $value = null, $options = []) { $GLOBALS['member_cookies'][$key] = $value; }
function mac_validate($name) {
    $class = 'app\\common\\validate\\' . $name;
    $validator = new $class();
    if ($name !== 'Plog') { return $validator; }
    return new class($validator) {
        public function __construct(private $validator) {}
        public function check($data): bool {
            $type = (int)$data['plog_type'];
            if (in_array($type, $GLOBALS['member_throw_log_types'] ?? [], true)) {
                throw new TypeError('fixture ledger exception');
            }
            if (in_array($type, $GLOBALS['member_fail_log_types'] ?? [], true)) { return false; }
            return $this->validator->check($data);
        }
        public function getError(): string { return 'fixture ledger rejected'; }
    };
}
class MembershipAuditDb extends think\DbManager {
    public $beforeStart;
    public function startTrans(): void {
        $hook = $this->beforeStart;
        $this->beforeStart = null;
        if ($hook) { $hook(); }
        $this->connect()->startTrans();
    }
}
class MembershipAuditCache {
    public function get($key, $default = null) { return $GLOBALS['member_groups']; }
}
$mysql = getenv('MEMBERSHIP_AUDIT_MYSQL') === '1';
if (!extension_loaded($mysql ? 'pdo_mysql' : 'pdo_sqlite')) { throw new RuntimeException('Required PDO driver unavailable'); }
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_membership' : ':memory:',
    'prefix'=>'audit_', 'hostname'=>getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1',
    'username'=>'root', 'password'=>getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '',
    'charset'=>'utf8mb4', 'trigger_sql'=>false, 'fields_cache'=>false,
]]];
$manager = new MembershipAuditDb();
$manager->setConfig($configuration);
$config = new think\Config();
$config->set($configuration, 'database');
think\Container::getInstance()->instance('think\\DbManager', $manager);
think\Container::getInstance()->instance('config', $config);
think\Container::getInstance()->instance('cache', new MembershipAuditCache());
$GLOBALS['config'] = ['app'=>['cache_flag'=>'audit'], 'user'=>[
    'reward_status'=>'1', 'reward_ratio'=>'10', 'reward_ratio_2'=>'5', 'reward_ratio_3'=>'5',
]];

if ($mysql) {
    $ddl = file_get_contents(dirname(__DIR__, 2) . '/application/install/sql/install.sql');
    foreach (['user', 'group', 'order', 'plog'] as $table) {
        if (!preg_match('/CREATE TABLE `mac_' . $table . '` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
            throw new RuntimeException('Installation financial schema missing');
        }
        Db::execute('DROP TABLE IF EXISTS audit_' . $table);
        Db::execute(str_replace('`mac_' . $table . '`', '`audit_' . $table . '`', $match[0]));
    }
} else {
    // Mirror the financial column bounds that SQLite's integer affinity otherwise omits.
    Db::execute('CREATE TABLE audit_user (user_id INTEGER PRIMARY KEY, user_name TEXT, group_id INTEGER DEFAULT 2,
        user_points INTEGER DEFAULT 0 CHECK(user_points BETWEEN 0 AND 4294967295), user_end_time INTEGER DEFAULT 0,
        user_pid INTEGER DEFAULT 0, user_pid_2 INTEGER DEFAULT 0, user_pid_3 INTEGER DEFAULT 0)');
    Db::execute('CREATE TABLE audit_order (order_id INTEGER PRIMARY KEY, order_code TEXT, order_status INTEGER DEFAULT 0,
        order_price NUMERIC, order_points INTEGER CHECK(order_points BETWEEN 0 AND 16777215), user_id INTEGER,
        order_pay_time INTEGER, order_pay_type TEXT, order_remarks TEXT DEFAULT "")');
    Db::execute('CREATE TABLE audit_plog (plog_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plog_type INTEGER,
        plog_points INTEGER CHECK(plog_points BETWEEN 0 AND 65535), plog_time INTEGER, plog_remarks TEXT)');
}

function membershipSeed(int $balance = 100): void {
    foreach (['plog', 'order', 'user'] as $table) { Db::execute('DELETE FROM audit_' . $table); }
    foreach ([1, 2, 3, 4] as $id) {
        Db::name('User')->insert(['user_id'=>$id, 'user_name'=>'fixture' . $id, 'user_points'=>$id === 1 ? $balance : 0,
            'group_id'=>2, 'user_end_time'=>0, 'user_pid'=>$id === 1 ? 2 : 0, 'user_pid_2'=>$id === 1 ? 3 : 0,
            'user_pid_3'=>$id === 1 ? 4 : 0]);
    }
    $GLOBALS['user'] = Db::name('User')->find(1);
    $GLOBALS['member_groups'] = [1=>['group_id'=>1, 'group_name'=>'guest'], 2=>['group_id'=>2, 'group_name'=>'registered'],
        3=>['group_id'=>3, 'group_name'=>'member', 'group_status'=>1,
        'group_points_day'=>20, 'group_points_week'=>100, 'group_points_month'=>200, 'group_points_year'=>2000]];
    $GLOBALS['member_fail_log_types'] = $GLOBALS['member_throw_log_types'] = $GLOBALS['member_cookies'] = [];
}
function membershipOrderSeed(int $points = 20): void {
    Db::name('Order')->insert(['order_id'=>1, 'user_id'=>1, 'order_code'=>'member-once', 'order_price'=>'10.00',
        'order_points'=>$points, 'order_remarks'=>json_encode(['biz'=>'member_upgrade', 'group_id'=>3,
            'long'=>'day', 'upgrade_points'=>20])]);
}
function membershipState(): array {
    return [Db::name('User')->order('user_id')->select()->toArray(), Db::name('Order')->order('order_id')->select()->toArray(),
        Db::name('Plog')->order('plog_id')->select()->toArray()];
}
function memberRow(int $id = 1): array { return Db::name('User')->find($id); }
