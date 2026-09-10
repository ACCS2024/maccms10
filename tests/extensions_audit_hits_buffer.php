<?php
/** Real ThinkPHP 8 + MySQL + Redis; run through run_hits_buffer_audit.py. */
declare(strict_types=1);

use app\common\util\HitsBuffer;
use think\facade\Cache;
use think\facade\Db;

$database = getenv('HITS_AUDIT_DATABASE') ?: '';
$prefix = getenv('HITS_AUDIT_PREFIX') ?: '';
if (!preg_match('/^maccms_audit_hits_[a-f0-9]+$/D', $database)
    || !preg_match('/^audit_hits_[a-f0-9]+:$/D', $prefix)
    || getenv('HITS_AUDIT_MYSQL_SOCKET') !== '/audit/mysql.sock'
    || getenv('HITS_AUDIT_REDIS_SOCKET') !== '/audit/redis.sock') {
    throw new RuntimeException('Only the dedicated Unix-socket audit fixture is allowed');
}
require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message, 0, $level, $file, $line);
});
date_default_timezone_set('Asia/Shanghai');
$runtime = '/audit/runtime-' . getmypid() . '/';
$app = new think\App($runtime);
think\Container::setInstance($app);
$cacheConfig = ['default' => 'audit', 'stores' => [
    'audit' => ['type' => 'redis', 'host' => '/audit/redis.sock', 'port' => 0, 'select' => 15, 'prefix' => $prefix],
    'file' => ['type' => 'file', 'path' => $runtime],
    'unavailable' => ['type' => 'redis', 'host' => '/audit/absent.sock', 'port' => 0, 'timeout' => 1],
]];
$app->config->set($cacheConfig, 'cache');
$manager = new think\DbManager();
$manager->setConfig(['default' => 'audit', 'auto_timestamp' => false, 'connections' => ['audit' => [
    'type' => 'mysql', 'socket' => '/audit/mysql.sock', 'database' => $database,
    'username' => 'root', 'password' => getenv('HITS_AUDIT_PASSWORD'), 'prefix' => 'audit_',
    'charset' => 'utf8mb4', 'trigger_sql' => false, 'fields_cache' => false,
]]]);
$app->instance('think\DbManager', $manager);
class HitsAuditLog {
    public array $entries = [];
    public function warning($message, $context = []): void { $this->entries[] = [$message, $context]; }
}
$logger = new HitsAuditLog();
$app->instance('log', $logger);
$GLOBALS['config'] = ['app' => ['hits_buffer' => '1']];
$redis = Cache::store()->handler();
$key = static fn(string $kind): string => $prefix . 'mac_hits_buf:' . $kind;

if (($argv[1] ?? '') === 'worker') {
    $deadline = microtime(true) + 15;
    while (!is_file('/audit/start-' . $argv[2])) {
        if (microtime(true) > $deadline) { throw new RuntimeException('Worker barrier timed out'); }
        usleep(1000);
    }
    if ($argv[3] === 'flush') {
        for ($i = 0; $i < (int)$argv[4]; $i++) { HitsBuffer::flush(); usleep(1000); }
    } else {
        for ($i = 0; $i < (int)$argv[4]; $i++) {
            if (!HitsBuffer::bump($argv[3], (int)$argv[5])) { throw new RuntimeException('Worker unexpectedly fell back'); }
        }
    }
    exit(0);
}

$checks = 0;
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
};
$workers = [];
$barriers = [];
$startWorker = static function (string $barrier, string $mode, int $count, int $id = 1) use (&$workers): int {
    $pipes = [];
    $process = proc_open([PHP_BINARY, __FILE__, 'worker', $barrier, $mode, (string)$count, (string)$id],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    fclose($pipes[0]);
    $workers[] = [$process, $pipes];
    return array_key_last($workers);
};
$join = static function (int $index) use (&$workers): void {
    [$process, $pipes] = $workers[$index];
    $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $code = proc_close($process);
    unset($workers[$index]);
    if ($code !== 0 || $output !== '') { throw new RuntimeException('Worker failed: ' . $output); }
};
$release = static function (string $barrier) use (&$barriers): void {
    $path = '/audit/start-' . $barrier;
    file_put_contents($path, 'start');
    $barriers[] = $path;
};
$row = static fn(string $kind, int $id): array => Db::name($kind)->where($kind . '_id', $id)->find();
$pending = static fn(string $kind, int $id): int => (int)$redis->hGet($key($kind), (string)$id);
$trigger = static function (string $kind, int $id, bool $delay = false): void {
    Db::execute("CREATE TRIGGER audit_fail_{$kind} BEFORE UPDATE ON audit_{$kind} FOR EACH ROW BEGIN "
        . "IF NEW.{$kind}_id = {$id} THEN " . ($delay ? 'DO SLEEP(0.5); ' : '')
        . "SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit rejection'; END IF; END");
};
try {
    foreach (['vod', 'art'] as $kind) {
        Db::execute("CREATE TABLE audit_{$kind} ({$kind}_id INT PRIMARY KEY, {$kind}_hits BIGINT DEFAULT 0, "
            . "{$kind}_hits_day BIGINT DEFAULT 0, {$kind}_hits_week BIGINT DEFAULT 0, "
            . "{$kind}_hits_month BIGINT DEFAULT 0, {$kind}_time_hits BIGINT DEFAULT 0) ENGINE=InnoDB");
        for ($id = 1; $id <= 6; $id++) { Db::name($kind)->insert([$kind . '_id' => $id]); }
    }
    $redis->hSet('mac_hits_buf:vod', '1', 777);
    $check(HitsBuffer::enabled(), 'ThinkPHP 8 Redis store must activate the configured buffer');
    $GLOBALS['config']['app']['hits_buffer'] = '0';
    $cacheConfig['default'] = 'missing';
    $app->config->set($cacheConfig, 'cache');
    $check(!HitsBuffer::enabled() && !HitsBuffer::bump('vod', 1), 'Disabled buffer must not resolve a cache driver');
    $GLOBALS['config']['app']['hits_buffer'] = '1';
    foreach (['file', 'unavailable'] as $driver) {
        $cacheConfig['default'] = $driver;
        $app->config->set($cacheConfig, 'cache');
        $check(!HitsBuffer::enabled() && !HitsBuffer::bump('vod', 1), 'Non-Redis/unavailable store must use caller fallback');
    }
    $cacheConfig['default'] = 'audit';
    $app->config->set($cacheConfig, 'cache');
    $check(!HitsBuffer::bump('unknown', 1) && !HitsBuffer::bump('vod', 0) && HitsBuffer::flush('../vod') === 0,
        'Invalid content identifiers cannot select other counters');
    for ($i = 0; $i < 9; $i++) { $check(HitsBuffer::bump('vod', 1), 'Below-threshold hit accepted'); }
    $check($row('vod', 1)['vod_hits'] === 0 && $pending('vod', 1) === 9, 'Sub-threshold hits remain in Redis');
    $check(HitsBuffer::bump('vod', 1) && $row('vod', 1)['vod_hits'] === 10 && $pending('vod', 1) === 0,
        'Threshold moves exactly one batch to MySQL');
    for ($i = 0; $i < 3; $i++) { HitsBuffer::bump('vod', 1); }
    $check(HitsBuffer::flush('vod') === 1 && $row('vod', 1)['vod_hits'] === 13, 'Flush persists the remainder');
    $check($row('vod', 1)['vod_hits_day'] === 13 && $row('vod', 1)['vod_hits_week'] === 13
        && $row('vod', 1)['vod_hits_month'] === 13, 'Current-period counters increase together');
    $check($redis->hGet('mac_hits_buf:vod', '1') === '777', 'Cache prefix isolates unrelated legacy counters');
    $check(HitsBuffer::flush() === 0, 'Empty flush reports no writes');

    Db::name('art')->where('art_id', 1)->update(['art_hits' => 100, 'art_hits_day' => 40,
        'art_hits_week' => 50, 'art_hits_month' => 60, 'art_time_hits' => strtotime('-2 months')]);
    $redis->hSet($key('art'), '1', 3);
    $check(HitsBuffer::flush('art') === 1 && $row('art', 1)['art_hits'] === 103, 'Lifetime count survives period reset');
    $check($row('art', 1)['art_hits_day'] === 3 && $row('art', 1)['art_hits_week'] === 3
        && $row('art', 1)['art_hits_month'] === 3, 'Expired day/week/month reset to claimed delta');

    $trigger('vod', 2);
    $redis->hSet($key('vod'), '2', 9);
    $check(HitsBuffer::bump('vod', 2), 'Acknowledged Redis hit cannot request a duplicate caller increment on DB failure');
    $check($row('vod', 2)['vod_hits'] === 0 && $pending('vod', 2) === 10, 'Failed DB batch is restored');
    $check(in_array('HitsBuffer database', array_column($logger->entries, 0), true), 'Database failure is observable without raw SQL');
    Db::execute('DROP TRIGGER audit_fail_vod');
    $check(HitsBuffer::flush('vod') === 1 && $row('vod', 2)['vod_hits'] === 10, 'Restored batch retries once');

    $trigger('art', 2);
    $redis->hMSet($key('art'), ['2' => 4, '3' => 2]);
    $check(HitsBuffer::flush('art') === 1, 'Flush only counts successful database writes');
    $check($pending('art', 2) === 4 && $row('art', 2)['art_hits'] === 0 && $row('art', 3)['art_hits'] === 2,
        'One failing content row does not erase its batch or prevent other rows');
    Db::execute('DROP TRIGGER audit_fail_art');
    $check(HitsBuffer::flush('art') === 1 && $row('art', 2)['art_hits'] === 4, 'Failed flush batch remains retryable');

    $trigger('vod', 4, true);
    $redis->hSet($key('vod'), '4', 9);
    $barrier = bin2hex(random_bytes(5));
    $worker = $startWorker($barrier, 'vod', 1, 4);
    $release($barrier);
    $deadline = microtime(true) + 10;
    while ($redis->hExists($key('vod'), '4')) {
        if (microtime(true) > $deadline) { throw new RuntimeException('Delayed DB worker never claimed its batch'); }
        usleep(1000);
    }
    for ($i = 0; $i < 3; $i++) { HitsBuffer::bump('vod', 4); }
    $join($worker);
    $check($pending('vod', 4) === 13 && $row('vod', 4)['vod_hits'] === 0, 'DB failure restore preserves arrivals during the attempted write');
    Db::execute('DROP TRIGGER audit_fail_vod');
    $check(HitsBuffer::flush('vod') === 1 && $row('vod', 4)['vod_hits'] === 13, 'Merged restored/new counts persist once');

    // Deny only EVAL on the already-connected Redis client after enabling the store.
    $control = new Redis();
    $control->connect('/audit/redis.sock');
    $aclPassword = bin2hex(random_bytes(8));
    $control->rawCommand('ACL', 'SETUSER', 'audit_noeval', 'on', '>' . $aclPassword, '~' . $prefix . '*', '+@all', '-eval');
    $redis->auth(['audit_noeval', $aclPassword]);
    $redis->hSet($key('vod'), '3', 9);
    $check(HitsBuffer::bump('vod', 3) && $pending('vod', 3) === 10 && $row('vod', 3)['vod_hits'] === 0,
        'Failure to claim after acknowledged increment retains the hit and does not ask caller to add it again');
    $redis->close();
    Cache::forgetDriver('audit');
    $redis = Cache::store()->handler();
    $control->rawCommand('ACL', 'DELUSER', 'audit_noeval');
    $control->close();
    $pending = static fn(string $kind, int $id): int => (int)$redis->hGet($key($kind), (string)$id);
    $check(HitsBuffer::flush('vod') === 1 && $row('vod', 3)['vod_hits'] === 10, 'Unclaimed accepted hits retry after Redis permissions recover');

    $barrier = bin2hex(random_bytes(5));
    for ($i = 0; $i < 6; $i++) { $startWorker($barrier, $i % 2 ? 'vod' : 'art', 200, 5); }
    for ($i = 0; $i < 2; $i++) { $startWorker($barrier, 'flush', 120); }
    $release($barrier);
    foreach (array_keys($workers) as $worker) { $join($worker); }
    HitsBuffer::flush();
    $check($row('vod', 5)['vod_hits'] === 600 && $pending('vod', 5) === 0, 'Concurrent threshold writers and flushers preserve all 600 video hits');
    $check($row('art', 5)['art_hits'] === 600 && $pending('art', 5) === 0, 'Concurrent threshold writers and flushers preserve all 600 article hits');
    $rows = [];
    $counters = [];
    for ($id = 1000; $id < 1700; $id++) { $rows[] = ['vod_id' => $id]; $counters[(string)$id] = 1; }
    Db::name('vod')->insertAll($rows);
    $redis->hMSet($key('vod'), $counters);
    $cursor = null;
    $redis->hScan($key('vod'), $cursor, null, 100);
    $check($cursor !== 0, 'Large hash fixture requires more than one HSCAN batch');
    $check(HitsBuffer::flush('vod') === 700 && (int)Db::name('vod')->where('vod_id', '>=', 1000)->sum('vod_hits') === 700
        && $redis->hLen($key('vod')) === 0, 'Deleting claimed fields during paginated scan preserves all 700 remaining rows');
    $redis->hSet($key('vod'), '999', 3);
    $check(HitsBuffer::flush('vod') === 0 && $pending('vod', 999) === 0, 'Deleted content is discarded without a false successful-write count');
    $redis->set($key('vod'), 'wrong-type');
    $check(!HitsBuffer::bump('vod', 1), 'Rejected initial increment requests caller fallback');
    $check(HitsBuffer::flush('vod') === 0, 'Wrong-type Redis data cannot hang flush');
    $redis->del($key('vod'));
    echo "OK {$checks} HitsBuffer checks on PHP " . PHP_VERSION . " with real MySQL/Redis\n";
} finally {
    foreach ($workers as [$process, $pipes]) {
        proc_terminate($process);
        foreach ($pipes as $pipe) { if (is_resource($pipe)) { fclose($pipe); } }
        proc_close($process);
    }
    foreach ($barriers as $barrier) { unlink($barrier); }
    foreach (['vod', 'art'] as $kind) {
        Db::execute('DROP TABLE IF EXISTS audit_' . $kind);
        $redis->del($key($kind));
    }
    $redis->hDel('mac_hits_buf:vod', '1');
}
