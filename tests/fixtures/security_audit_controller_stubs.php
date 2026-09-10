<?php
/** Controller-only dependency stubs; no application bootstrap or deployment configuration. */
namespace app\common\controller {
    class All
    {
        public $request;
        public $_cl;
        public $_ac;
        public array $assigned = [];
        public function __construct() { $this->_cl = 'Update'; $this->_ac = 'step2'; }
        protected function error($message) { return ['ok' => false, 'message' => $message]; }
        protected function success($message) { return ['ok' => true, 'message' => $message]; }
        protected function assign($name, $value = ''): void { $this->assigned[$name] = $value; }
        protected function fetch(string $template = '', array $vars = []): string { return $template; }
    }
}
namespace think\facade {
    class Db
    {
        public static function name($name) { return new \AuditQuery(); }
        public static function connect() { return new \AuditQuery(); }
        public static function query($sql, $bind = []) { return [['TABLE_NAME' => 'mac_vod', 'COLUMN_NAME' => 'vod_id']]; }
    }
    class Request
    {
        public static array $input = [];
        public static function param($key = null) { return $key === null ? self::$input : (self::$input[$key] ?? null); }
        public static function post() { return self::$input; }
    }
    class Session
    {
        public static function has($key): bool { return isset($GLOBALS['audit_session'][$key]); }
        public static function get($key) { return $GLOBALS['audit_session'][$key] ?? null; }
    }
}
namespace app\common\model {
    class Admin
    {
        public function checkLogin() { return ['code' => 1, 'info' => ['admin_id' => 2, 'admin_auth' => '']]; }
    }
    class Annex
    {
        public function countData($where) { return 501; }
        public function infoData($where) { return ['code' => 1002]; }
        public function insertAll($rows) { $GLOBALS['audit_inserts'][] = $rows; }
    }
}
namespace think\exception {
    class HttpResponseException extends \RuntimeException
    {
        public function __construct(public $response) { parent::__construct('Response'); }
    }
}
namespace {
    require_once __DIR__ . '/security_audit_test_helpers.php';
    function lang($key) { return $key; }
    function session($key) { return $GLOBALS['audit_session'][$key] ?? null; }
    function json($data, $status = 200) { return ['status' => $status, 'data' => $data]; }
    function response($data, $status = 200) { return ['status' => $status, 'data' => $data]; }
    function Request() { return $GLOBALS['audit_request']; }
    function config($key) { return $key === 'database.connections.mysql.prefix' ? 'mac_' : []; }
    function mac_echo($message) {}
    function mac_jump($url, $seconds) {}
    function url($route) { return $route; }
    function model($name) { return new \app\common\model\Annex(); }
    function mac_security_auto_migrate() {}
    function mac_meili_settings_auto_sync() {}
    final class AuditQuery
    {
        public function field($value) { return $this; }
        public function where($value) { return $this; }
        public function orderRaw($value) { return $this; }
        public function limit($offset, $limit) { $GLOBALS['audit_limit'] = [$offset, $limit]; return $this; }
        public function select() {
            $rows = $GLOBALS['audit_rows'] ?? [];
            return empty($GLOBALS['audit_select_collection']) ? $rows : new class($rows) extends \ArrayObject {
                public function toArray(): array { return $this->getArrayCopy(); }
            };
        }
        public function getConfig($key) { return 'audit'; }
    }

    final class AuditRequest
    {
        public function __construct(public string $route = '', public bool $post = false, public string $body = '') {}
        public function pathinfo() { return $this->route; }
        public function isPost(): bool { return $this->post; }
        public function isGet(): bool { return !$this->post; }
        public function isAjax(): bool { return true; }
        public function header($name) { return $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $name))] ?? ''; }
        public function param($key) { return null; }
        public function getContent(): string { return $this->body; }
        public function cookie($key) { return $_COOKIE[$key] ?? null; }
    }

}
