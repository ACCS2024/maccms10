<?php
namespace app\common\model {
    class Type {
        public static array $rows = [];
        public function getCache($key) { return self::$rows; }
    }
}
namespace {
    // Exercise helpers without application boot, persistent storage or network.
    function config($key) { return $key === 'database.connections.mysql.prefix' ? 'mac_' : null; }
    function url($model, $params = []) { return '/' . $model . ($params ? '?' . http_build_query($params) : ''); }
    define('ENTRANCE', 'index');
    define('IN_FILE', '/index.php');
    define('MAC_PATH', '/');
    define('MAC_PAGE_SP', '-');
    require dirname(__DIR__) . '/application/common.php';
    set_error_handler(static function ($severity, $message, $file, $line) {
        if (!(error_reporting() & $severity)) { return false; }
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    $checks = 0;
    function check($expected, $actual, $label) {
        global $checks;
        if ($expected !== $actual) { throw new RuntimeException('FAIL: ' . $label); }
        ++$checks;
    }
    $GLOBALS['config'] = include dirname(__DIR__) . '/application/data/config/maccms.example.php';
    $GLOBALS['mctheme'] = ['theme' => ['list_cover' => ['vod' => []]]];
    \app\common\model\Type::$rows = [1 => ['type_pid' => 2], 2 => ['type_pid' => 1]];
    check('v', mac_tpl_vod_type_cover(1), 'cyclic categories terminate with default');
    $GLOBALS['mctheme']['theme']['list_cover']['vod'] = [['id' => 2, 'cover' => 'h']];
    check('h', mac_tpl_vod_type_cover(1), 'ancestor cover still resolves');
    check('v', mac_tpl_vod_type_cover(999), 'missing category uses default');
    $GLOBALS['config']['view']['website_detail'] = 2;
    $GLOBALS['config']['path']['website_detail'] = '';
    check(true, mac_url('website/detail', [], ['website_id' => 1]) !== '', 'empty static path has usable dynamic URL');

    echo "Core helper contracts: {$checks} checks passed on PHP " . PHP_VERSION . "\n";
}
