<?php
/** Controller behavior fixtures with real Think ORM and an in-memory SQLite database. */
namespace app\common\controller {
    class All
    {
        public $request;
        public array $assigned = [];
        protected function error($message) { return ['ok' => false, 'message' => $message]; }
        protected function success($message, $url = null, $data = []) { return ['ok' => true, 'message' => $message, 'data' => $data]; }
        protected function assign($name, $value = ''): void { $this->assigned[$name] = $value; }
        protected function fetch(string $template = '', array $vars = []): string { return $template; }
        public function label_maccms() {}
        public function label_art_detail($row, $mode) { return ['art_tpl' => 'fixture']; }
    }
}
namespace think\facade {
    class Request
    {
        public static array $input = [];
        public static function param($key = null) { return $key === null ? self::$input : (self::$input[$key] ?? null); }
        public static function post() { return self::$input; }
    }
}
namespace app\common\model {
    trait RuntimeModel
    {
        private function kind(): string { return strtolower((new \ReflectionClass($this))->getShortName()); }
        public function saveData($data) {
            $kind = $this->kind();
            $GLOBALS['runtime_saves'][$kind][] = $data;
            $fail = ($GLOBALS['runtime_save_fail_at'] ?? 0) === count($GLOBALS['runtime_saves'][$kind]);
            return ['code' => $fail ? 1002 : 1, 'msg' => $fail ? 'save failed' : 'saved'];
        }
        public function getCache($key = '') { return $GLOBALS['runtime_cache'][$this->kind()] ?? []; }
        public function countData($where) { return count($GLOBALS['runtime_lists'][$this->kind()] ?? []); }
        public function listData($where, $order, $page, $limit) {
            $kind = $this->kind();
            $GLOBALS['runtime_queries'][$kind][] = compact('where', 'order', 'page', 'limit');
            $list = $GLOBALS['runtime_lists'][$kind] ?? [];
            return ['list' => $list, 'total' => count($list), 'pagecount' => 1, 'page' => $page];
        }
    }
    class Link { use RuntimeModel; }
    class Type { use RuntimeModel; }
    class Art { use RuntimeModel; }
    class Vod { use RuntimeModel; }
    class Topic { use RuntimeModel; }
    class Actor { use RuntimeModel; }
    class Role { use RuntimeModel; }
    class Website { use RuntimeModel; }
    class Manga { use RuntimeModel; }
    class Image
    {
        public function watermark($path, $config, $kind) { throw new \RuntimeException('fixture watermark failure'); }
        public function makethumb($path, $config, $kind) { throw new \RuntimeException('fixture thumbnail failure'); }
    }
    class Upload
    {
        public function api($path, $config) { throw new \RuntimeException('fixture storage failure'); }
    }
}
namespace app\common\util {
    class UeditorAiCsrf { public static function validate($token) { return $token === 'fixture-csrf'; } }
    class UeditorAiProxy
    {
        public static function complete($ai, $system, $user) {
            if (($GLOBALS['runtime_proxy_mode'] ?? '') === 'throw') { throw new \RuntimeException('fixture upstream exception'); }
            return $GLOBALS['runtime_proxy_reply'];
        }
    }
    class MeilisearchSync { public static function afterVodSave($id): void {} }
}
namespace app\common\extend\urlsend {
    class Fixture
    {
        public function submit($data) {
            $GLOBALS['runtime_submissions'][] = $data;
            return ['code' => 1, 'msg' => 'submitted'];
        }
    }
}
namespace {
    require_once __DIR__ . '/security_audit_test_helpers.php';
    require dirname(__DIR__, 2) . '/vendor/autoload.php';
    function lang($key, $vars = []) { return $key; }
    function config($key) { return $GLOBALS['runtime_config'][$key] ?? []; }
    function cache($key, ...$args) { return 0; }
    function json($data, $status = 200) { return ['status' => $status, 'data' => $data]; }
    function mac_echo($message) { $GLOBALS['runtime_output'][] = $message; }
    function mac_jump($url, $seconds) { $GLOBALS['runtime_redirects'][] = $url; }
    function url($route, $params = []) { return $route; }
    function mac_like_arr($value) { return array_map(static fn($part) => '%' . $part . '%', explode(',', $value)); }
    function mac_get_aid($kind, $action) { return 1; }
    function mac_substring($value, $length) { return substr($value, 0, $length); }
    function mac_art_list($title, $note, $content) {
        if ($content === '') { return []; }
        $parts = explode('$$$', $content);
        $rows = [];
        foreach ($parts as $index => $part) { $rows[$index + 1] = ['page' => $index + 1, 'content' => $part]; }
        return $rows;
    }
    function mac_tpl_fetch($kind, $template, $action) { return $template; }
    function mac_url_art_detail($row, $params = []) { return '/art/' . $row['art_id'] . '/' . ($params['page'] ?? 1); }
    function mac_url_vod_detail($row) { return '/vod/' . $row['vod_id']; }
    function mac_url_topic_detail($row) { return '/topic/' . $row['topic_id']; }
    function mac_url_actor_detail($row) { return '/actor/' . $row['actor_id']; }
    function mac_url_role_detail($row) { return '/role/' . $row['role_id']; }
    function mac_url_website_detail($row) { return '/website/' . $row['website_id']; }
    function mac_url_manga_detail($row) { return '/manga/' . $row['manga_id']; }
    class RuntimeAuditDb extends \think\DbManager
    {
        public function query($sql, array $bind = [], bool $master = false): array {
            if (str_contains($sql, 'information_schema.columns')) { return $GLOBALS['runtime_schema'] ?? []; }
            return $this->connect()->query($sql, $bind, $master);
        }
    }
    class RuntimeAuditCache { public function delete($key) { return true; } }
    class RuntimeAuditLogger
    {
        public array $events = [];
        public function error($message) { $this->events[] = ['error', $message]; }
        public function record($message, $level) { $this->events[] = [$level, $message]; }
        public function write($message, $level) { $this->events[] = [$level, $message]; }
    }
    if (!extension_loaded('pdo_sqlite')) { throw new \RuntimeException('pdo_sqlite is required'); }
    $manager = new RuntimeAuditDb();
    $manager->setConfig(['default' => 'audit', 'connections' => ['audit' => [
        'type' => 'sqlite', 'database' => ':memory:', 'prefix' => 'audit_',
        'trigger_sql' => false, 'fields_cache' => false,
    ]]]);
    \think\Container::getInstance()->instance('think\DbManager', $manager);
    \think\Container::getInstance()->instance('cache', new RuntimeAuditCache());
    $logger = new RuntimeAuditLogger();
    \think\Container::getInstance()->instance('log', $logger);
    $GLOBALS['runtime_config']['database.connections.mysql.prefix'] = 'audit_';
    require dirname(__DIR__, 2) . '/application/admin/controller/Base.php';
}
