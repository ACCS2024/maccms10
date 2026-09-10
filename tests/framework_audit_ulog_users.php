<?php
/** Real Ulog/Topic models and SQL scope; MySQL uses only maccms_audit_http/audit_ulog_* tables. */
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});
function lang($key, $vars = []) { return $key; }
function mac_array_rekey($rows, $key) { return array_column($rows, null, $key); }
function mac_url_topic_detail($row) { return '/topic/' . $row['topic_id']; }
function mac_url_img($value) { return $value; }

$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$container = new think\Container();
think\Container::setInstance($container);
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_http' : ':memory:',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
    'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '', 'charset'=>'utf8mb4',
    'prefix'=>'audit_ulog_', 'trigger_sql'=>true, 'fields_cache'=>false,
]]];
$config = new think\Config();
$config->set($configuration, 'database');
$container->instance('config', $config);
$db = new think\DbManager();
$db->setConfig($configuration);
$container->instance('think\\DbManager', $db);
$GLOBALS['config'] = ['app'=>['cache_core'=>0, 'cache_flag'=>'audit_ulog']];
$sqlLog = [];
$db->listen(static function ($sql) use (&$sqlLog): void { $sqlLog[] = $sql; });
$schemas = [
    'user'=>"user_id INTEGER PRIMARY KEY, user_name VARCHAR(100), user_pwd VARCHAR(100) DEFAULT 'private-secret'",
    'ulog'=>'ulog_id INTEGER PRIMARY KEY, user_id INTEGER, ulog_mid INTEGER, ulog_type INTEGER, ulog_rid INTEGER, ulog_sid INTEGER DEFAULT 0, ulog_nid INTEGER DEFAULT 0, ulog_time INTEGER',
    'topic'=>'topic_id INTEGER PRIMARY KEY, topic_name VARCHAR(100), topic_pic VARCHAR(100)',
];
$checks = 0;
function ulogExpect($condition, string $message): void {
    global $checks;
    ++$checks;
    if (!$condition) { throw new RuntimeException($message); }
}
function ulogRead(array $where, int $page = 1, int $limit = 20): array {
    global $sqlLog;
    $sqlLog = [];
    $result = (new app\common\model\Ulog())->listData($where, 'ulog_id asc', $page, $limit);
    $queries = array_values(array_filter($sqlLog, static function ($sql) {
        return preg_match('/^SELECT\b.*\bFROM\s+[`"]?audit_ulog_user[`"]?(?:\s|$)/i', $sql) === 1;
    }));
    return [$result, $queries];
}
function ulogScope(array $queries, array $expectedIds): void {
    ulogExpect(count($queries) === 1, 'Username enrichment must issue one bounded user query, without a user count');
    $rows = think\facade\Db::query($queries[0]);
    $ids = array_map('intval', array_column($rows, 'user_id'));
    sort($ids);
    sort($expectedIds);
    ulogExpect($ids === $expectedIds, 'The actual user SQL must read only accounts referenced by this log page');
    foreach ($rows as $row) {
        $fields = array_keys($row);
        sort($fields);
        ulogExpect($fields === ['user_id', 'user_name'], 'Username enrichment must not retrieve password or unrelated user fields');
    }
}
try {
    foreach ($schemas as $table=>$fields) {
        think\facade\Db::execute('DROP TABLE IF EXISTS audit_ulog_' . $table);
        think\facade\Db::execute('CREATE TABLE audit_ulog_' . $table . ' (' . $fields . ')');
    }
    think\facade\Db::name('User')->insertAll([
        ['user_id'=>1, 'user_name'=>'Older owner'], ['user_id'=>2, 'user_name'=>'Other owner'],
    ]);
    // More than 999 unrelated, newer accounts reproduce the old unfiltered/truncated lookup.
    $unrelated = [];
    for ($id = 1000; $id < 2005; ++$id) { $unrelated[] = ['user_id'=>$id, 'user_name'=>'New user ' . $id]; }
    foreach (array_chunk($unrelated, 200) as $chunk) { think\facade\Db::name('User')->insertAll($chunk); }
    think\facade\Db::name('Topic')->insertAll([
        ['topic_id'=>1, 'topic_name'=>'Owner topic', 'topic_pic'=>'owner.jpg'],
        ['topic_id'=>2, 'topic_name'=>'Other topic', 'topic_pic'=>'other.jpg'],
    ]);
    $logs = [];
    foreach ([[1,1,1], [2,2,2], [3,1,2], [4,999,1], [5,0,2]] as [$id,$uid,$rid]) {
        $logs[] = ['ulog_id'=>$id, 'user_id'=>$uid, 'ulog_mid'=>3, 'ulog_type'=>2, 'ulog_rid'=>$rid, 'ulog_time'=>$id];
    }
    think\facade\Db::name('Ulog')->insertAll($logs);

    [$owned, $queries] = ulogRead(['user_id'=>1]);
    ulogExpect($owned['total'] === 2 && array_column($owned['list'], 'ulog_id') === [1,3], 'The owner filter must continue to select only that user’s logs');
    ulogExpect(array_column($owned['list'], 'user_name') === ['Older owner','Older owner'], 'An older account must still resolve with more than 999 newer accounts');
    ulogExpect(array_column(array_column($owned['list'], 'data'), 'name') === ['Owner topic','Other topic'], 'Real content rows must stay aligned with the selected logs');
    ulogExpect($owned['list'][1]['data']['link'] === '/topic/2' && $owned['list'][1]['data']['pic'] === 'other.jpg', 'Content enrichment must retain the referenced row’s image and link');
    ulogScope($queries, [1]);
    echo 'Scoped username SQL: ' . $queries[0] . PHP_EOL;

    [$mixed, $queries] = ulogRead(['ulog_id'=>[1,2,3]]);
    ulogExpect(array_column($mixed['list'], 'user_name') === ['Older owner','Other owner','Older owner'], 'A mixed-owner result must map each username by its log user_id');
    ulogExpect(array_column(array_column($mixed['list'], 'data'), 'name') === ['Owner topic','Other topic','Other topic'], 'Cross-user content and usernames must not overwrite neighboring rows');
    ulogScope($queries, [1,2]);

    [$page, $queries] = ulogRead(['ulog_id'=>[1,2,3]], 2, 1);
    ulogExpect($page['total'] === 3 && $page['pagecount'] == 3 && array_column($page['list'], 'ulog_id') === [2], 'Pagination must preserve total and fetch only the requested log');
    ulogScope($queries, [2]);

    [$missing, $queries] = ulogRead(['ulog_id'=>[4,5]]);
    ulogExpect(array_column($missing['list'], 'user_name') === ['',''], 'Deleted and guest accounts must have an empty username without a strict warning');
    ulogScope($queries, []);
    ulogExpect(str_contains($queries[0], '999') && !preg_match('/[,(]\s*0\s*[,)]/', $queries[0]), 'A mixed missing/guest page must only look up the positive account ID');

    [$guest, $queries] = ulogRead(['user_id'=>0]);
    ulogExpect(count($guest['list']) === 1 && $queries === [], 'Guest-only logs must not query users');
    [$empty, $queries] = ulogRead(['ulog_id'=>999999]);
    ulogExpect($empty['total'] === 0 && $empty['list'] === [] && $queries === [], 'An empty log result must not query users');
    [$pastEnd, $queries] = ulogRead(['user_id'=>1], 3, 1);
    ulogExpect($pastEnd['total'] === 2 && $pastEnd['list'] === [] && $queries === [], 'An empty page of an otherwise nonempty log set must not query users');

    // A valid large page must not retain the old unrelated 999-account truncation.
    $logs = [];
    for ($id = 1000; $id <= 2000; ++$id) {
        $logs[] = ['ulog_id'=>$id, 'user_id'=>$id, 'ulog_mid'=>0, 'ulog_type'=>5, 'ulog_rid'=>0, 'ulog_time'=>$id];
    }
    foreach (array_chunk($logs, 100) as $chunk) { think\facade\Db::name('Ulog')->insertAll($chunk); }
    [$large, $queries] = ulogRead(['ulog_type'=>5], 1, 1001);
    ulogExpect(count($large['list']) === 1001 && $large['list'][0]['user_name'] === 'New user 1000' && $large['list'][1000]['user_name'] === 'New user 2000', 'Every distinct account on a large current log page must resolve');
    ulogExpect(count($queries) === 1 && count(think\facade\Db::query($queries[0])) === 1001, 'Large-page username SQL must remain scoped to the page’s distinct IDs');
    echo 'framework_audit_ulog_users: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . ' / ' . ($mysql ? 'MySQL' : 'SQLite') . PHP_EOL;
} catch (Throwable $error) {
    fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
    $failed = true;
} finally {
    foreach (array_keys($schemas) as $table) { think\facade\Db::execute('DROP TABLE IF EXISTS audit_ulog_' . $table); }
}
exit(empty($failed) ? 0 : 1);
