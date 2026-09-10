<?php
/** Real Cj controller/model/ThinkPHP MySQL collections, disposable database only. */
declare(strict_types=1);
namespace app\common\util {
    function mac_curl_get($url) {
        if ($url === 'https://fixture.invalid/list') {
            return '<a href="/1">One</a><a href="/2">Two</a><a href="/3">Three</a>';
        }
        if (preg_match('~^https://fixture.invalid/(\d+)$~D', $url, $match)) {
            if ((int)$match[1] === ($GLOBALS['collection_audit_fault'] ?? 0)) { return false; }
            if (-(int)$match[1] === ($GLOBALS['collection_audit_fault'] ?? 0)) { return "<article>invalid \xff</article>"; }
            return '<article>content ' . $match[1] . '</article>';
        }
        return false;
    }
}
namespace app\admin\controller {
    function mac_echo($message) { $GLOBALS['collection_audit_output'][] = $message; }
    function mac_jump($url, $delay) { $GLOBALS['collection_audit_redirect'] = $url; }
    function url($path) { return '/' . $path; }
    function lang($message, $args = []) { return $message; }
}
namespace {
    use think\facade\Db;
    $database = getenv('COLLECTION_AUDIT_DATABASE') ?: '';
    if (!preg_match('/^maccms_audit_collection_[a-f0-9]+$/D', $database)
        || getenv('COLLECTION_AUDIT_MYSQL_SOCKET') !== '/audit/mysql.sock') {
        throw new \RuntimeException('Only the dedicated disposable audit database is allowed');
    }
    require dirname(__DIR__) . '/vendor/autoload.php';
    require dirname(__DIR__) . '/vendor/topthink/framework/src/helper.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });
    $app = new \think\App('/audit/runtime-' . getmypid() . '/');
    \think\Container::setInstance($app);
    $manager = new \think\DbManager();
    $manager->setConfig(['default' => 'audit', 'auto_timestamp' => false, 'connections' => ['audit' => [
        'type' => 'mysql', 'socket' => '/audit/mysql.sock', 'database' => $database,
        'username' => 'root', 'password' => getenv('COLLECTION_AUDIT_PASSWORD'), 'prefix' => 'audit_',
        'charset' => 'utf8mb4', 'trigger_sql' => false, 'fields_cache' => false,
    ]]]);
    $app->instance('think\DbManager', $manager);
    class CollectionAuditController extends \app\admin\controller\Cj {
        public array $assigned = [];
        public function __construct() {}
        protected function error($msg = '', $url = null, $data = '', $wait = 3) {
            $GLOBALS['collection_audit_error'] = $msg;
            return ['code' => 1001, 'msg' => $msg];
        }
        protected function assign($name, $value = ''): void { $this->assigned[$name] = $value; }
        protected function fetch(string $template = '', array $vars = []): string { return 'fixture-view'; }
    }
    if (($argv[1] ?? '') === 'worker') {
        $action = $argv[2];
        $params = json_decode(base64_decode($argv[3], true), true, 512, JSON_THROW_ON_ERROR);
        $GLOBALS['collection_audit_fault'] = (int)($argv[4] ?? 0);
        $controller = new CollectionAuditController();
        $app->request->withGet($params)->setMethod('GET');
        register_shutdown_function(static function () use ($controller): void {
            echo json_encode([
                'error' => $GLOBALS['collection_audit_error'] ?? null,
                'exception' => $GLOBALS['collection_audit_exception'] ?? null,
                'redirect' => $GLOBALS['collection_audit_redirect'] ?? null,
                'assigned' => $controller->assigned,
                'output' => $GLOBALS['collection_audit_output'] ?? [],
            ], JSON_THROW_ON_ERROR);
        });
        try { $controller->$action($params); }
        catch (\Throwable $error) { $GLOBALS['collection_audit_exception'] = get_class($error) . ': ' . $error->getMessage(); }
        exit;
    }
    $checks = 0;
    $check = static function ($condition, string $message) use (&$checks): void {
        if (!$condition) { throw new \RuntimeException($message); }
        $checks++;
    };
    $run = static function (string $action, array $params, int $fault = 0): array {
        $pipes = [];
        $process = proc_open([PHP_BINARY, __FILE__, 'worker', $action, base64_encode(json_encode($params, JSON_THROW_ON_ERROR)), (string)$fault],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]); $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        $code = proc_close($process);
        if ($code !== 0 || $errors !== '') { throw new \RuntimeException('Controller process failed: ' . $errors . $output); }
        $response = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        if ($response['exception'] !== null) { throw new \RuntimeException('Controller exception: ' . $response['exception']); }
        return $response;
    };
    try {
        Db::execute('CREATE TABLE audit_cj_node (nodeid INT PRIMARY KEY, sourcetype INT DEFAULT 3, urlpage TEXT, content_rule TEXT, lastdate INT DEFAULT 0)');
        Db::execute('CREATE TABLE audit_cj_history (id INT AUTO_INCREMENT PRIMARY KEY, md5 CHAR(32))');
        Db::execute('CREATE TABLE audit_cj_content (id INT AUTO_INCREMENT PRIMARY KEY, nodeid INT, status INT DEFAULT 1, url TEXT, title TEXT, data LONGTEXT)');
        Db::name('cj_node')->insert(['nodeid' => 1, 'sourcetype' => 3, 'urlpage' => 'https://fixture.invalid/list', 'content_rule' => '<article>[内容]</article>']);
        $result = $run('col_url', ['id' => 1, 'page' => 1]);
        $check($result['error'] === null && $result['assigned']['total'] === 3, 'Real controller renders three successful URL results');
        $check(Db::name('cj_content')->where('status', 1)->count() === 3 && Db::name('cj_history')->count() === 3, 'Real model inserts collection records and history');
        $result = $run('col_url', ['id' => 1]);
        $check($result['assigned']['re'] === 3 && Db::name('cj_content')->count() === 3, 'Existing URL history prevents duplicate insertion');
        foreach ([['id' => 1, 'page' => 0], ['id' => 1, 'page' => 2], ['id' => 1, 'page' => []], ['id' => []]] as $param) {
            $check($run('col_url', $param)['error'] === 'param_err', 'Invalid URL-page/id input returns a controlled error');
        }
        Db::name('cj_node')->where('nodeid', 1)->update(['urlpage' => 'https://fixture.invalid/unavailable', 'lastdate' => 0]);
        $check($run('col_url', ['id' => 1])['error'] === 'obtain_err', 'A failed fetch does not call count(false)');
        $check((int)Db::name('cj_node')->where('nodeid', 1)->value('lastdate') === 0, 'Failed URL fetch does not update the completion timestamp');
        $check(Db::name('cj_content')->count() === 3, 'Failed URL fetch creates no content rows');
        $check($run('show_url', ['data' => ['sourcetype' => []]])['error'] === 'param_err', 'Preview rejects nested source types');
        $check($run('show_url', ['data' => ['sourcetype' => '3'], 'urlpage3' => []])['error'] === 'param_err', 'Preview rejects a non-string URL');
        $check($run('show_url', ['data' => ['sourcetype' => '1', 'pagesize_start' => 1, 'pagesize_end' => 10, 'par_num' => 0], 'urlpage1' => 'https://fixture.invalid/(*)'])['error'] === 'admin/cj/url_list_err', 'Preview rejects an invalid sequence instead of hanging');
        $result = $run('show_url', ['data' => ['sourcetype' => '3'], 'urlpage3' => 'https://fixture.invalid/list']);
        $check($result['assigned']['urls'] === ['https://fixture.invalid/list'], 'Valid URL preview remains usable');

        Db::name('cj_content')->delete(true);
        for ($id = 1; $id <= 25; $id++) {
            Db::name('cj_content')->insert(['id' => $id, 'nodeid' => 1, 'status' => 1, 'url' => 'https://fixture.invalid/' . $id, 'title' => 'item ' . $id]);
        }
        $result = $run('col_content', ['id' => 1, 'page' => 1], 2);
        $check($result['error'] === 'obtain_err', 'Failed content fetch reaches the controller error path');
        $check(Db::name('cj_content')->where('status', 2)->count() === 1 && Db::name('cj_content')->where('status', 1)->count() === 24,
            'Only the already successful row changes state; the failed row and later rows remain pending');
        $check(Db::name('cj_content')->where('id', 2)->value('data') === null, 'Failed content never stores JSON false as a success');
        $check((int)Db::name('cj_node')->where('nodeid', 1)->value('lastdate') === 0, 'Content failure does not mark the node completed');
        $result = $run('col_content', ['id' => 1, 'page' => 1]);
        $check($result['error'] === null && str_contains($result['redirect'], 'page=2'), 'More than twenty pending rows schedule a second batch');
        $check(Db::name('cj_content')->where('status', 2)->count() === 21 && Db::name('cj_content')->where('status', 1)->count() === 4,
            'The real ThinkPHP collection is iterated and the first twenty pending rows drain');
        $result = $run('col_content', ['id' => 1, 'page' => 2]);
        $check($result['error'] === null && $result['redirect'] === null, 'Final batch completes without an extra pagination redirect');
        $check(Db::name('cj_content')->where('status', 2)->count() === 25, 'Changing pending state never skips later rows through offset pagination');
        $check((int)Db::name('cj_node')->where('nodeid', 1)->value('lastdate') > 0, 'Completion timestamp is updated after the successful final batch');
        foreach ([1, 2, 21, 25] as $id) {
            $fields = json_decode(Db::name('cj_content')->where('id', $id)->value('data'), true, 512, JSON_THROW_ON_ERROR);
            $check($fields['content'] === 'content ' . $id, 'Real extraction results are persisted to the correct row');
        }
        $check($run('col_content', ['id' => 1, 'page' => []])['error'] === 'param_err', 'Content pagination rejects an array before any query');
        Db::name('cj_content')->insert(['id' => 26, 'nodeid' => 1, 'status' => 1, 'url' => 'https://fixture.invalid/26', 'title' => 'invalid encoding']);
        $check($run('col_content', ['id' => 1], -26)['error'] === 'obtain_err', 'Invalid UTF-8 collection content produces a controlled error');
        $check((int)Db::name('cj_content')->where('id', 26)->value('status') === 1 && Db::name('cj_content')->where('id', 26)->value('data') === null,
            'JSON encoding failure leaves the original pending row intact');
        echo "OK {$checks} Collection controller/MySQL checks on PHP " . PHP_VERSION . "\n";
    } finally {
        foreach (['audit_cj_content', 'audit_cj_history', 'audit_cj_node'] as $table) { Db::execute('DROP TABLE IF EXISTS ' . $table); }
    }
}
