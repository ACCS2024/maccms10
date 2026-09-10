<?php
/** Actual collector pagination with bounded substitutes for remote IO; no application bootstrap. */
declare(strict_types=1);

namespace app\common\model {
    class Type { public function getCache($key) { return []; } }
    class VodSearch {
        public $maxIdCount = 100;
        public function isCollectEnabled() { return false; }
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        throw new ErrorException($message, 0, $level, $file, $line);
    });
    define('ENTRANCE', 'api');
    $GLOBALS['config']['app']['cache_flag'] = 'isolated-audit';
    function lang($key, $vars = []) { return $key; }
    function mac_txt_explain($text, $flag = false) { return []; }
    function mac_echo($text) { $GLOBALS['audit_messages'][] = $text; }
    function config($key, $default = null) {
        return $key === 'maccms.collect'
            ? array_fill_keys(['vod','art','actor','role','website','comment','manga'], []) : [];
    }
    class AuditCache { public function delete($key) { return true; } }
    think\Container::getInstance()->instance('cache', new AuditCache());

    class AuditCollect extends app\common\model\Collect {
        public array $calls = [];
        public function __construct() {}
        private function nextPage($module, $param) {
            $this->calls[] = [$module, $param['page']];
            return $param['page'] < 3
                ? ['code'=>1,'data'=>[],'page'=>['page'=>2,'pagecount'=>3,'url'=>'https://example.test/']]
                : ['code'=>1008,'msg'=>'controlled remote failure'];
        }
        public function vod($param) { return $this->nextPage('vod', $param); }
        public function art($param) { return $this->nextPage('art', $param); }
        public function actor($param) { return $this->nextPage('actor', $param); }
        public function role($param) { return $this->nextPage('role', $param); }
        public function website($param) { return $this->nextPage('website', $param); }
        public function comment_json($param) { return $this->nextPage('comment', $param); }
        public function manga($param) { return $this->nextPage('manga', $param); }
    }
    $checks = 0;
    function auditExpect($ok, $message) {
        global $checks;
        ++$checks;
        if (!$ok) { throw new RuntimeException($message); }
    }
    foreach (['vod','art','actor','role','website','comment','manga'] as $module) {
        $collector = new AuditCollect();
        $GLOBALS['audit_messages'] = [];
        $result = $collector->{$module . '_data'}([], ['data'=>[],'page'=>['page'=>1,'pagecount'=>3,'url'=>'https://example.test/']], 0);
        auditExpect($result === ['code'=>1008,'msg'=>'controlled remote failure'], $module . ': upstream failure must propagate across recursive pages');
        auditExpect($collector->calls === [[$module,2],[$module,3]], $module . ': pagination must use the matching module');
        auditExpect(!in_array('model/collect/is_over', $GLOBALS['audit_messages'], true), $module . ': failure must not announce completion');
    }

    echo 'framework_audit_collection_paging: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . "\n";
}
