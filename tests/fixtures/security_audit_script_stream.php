<?php
/** HTTP-only fixture for controllers that flush or exit before returning a response. */
namespace think\facade {
    final class Config
    {
        public static function get($key, $default = []) {
            return $key === 'maccms.app' ? ['security_script_sources' => 'https://assets.example.invalid'] : $default;
        }
    }
}
namespace {
    require dirname(__DIR__, 2) . '/application/common.php';
    require dirname(__DIR__, 2) . '/application/middleware/SecurityHeaders.php';
    define('ENTRANCE', 'install');
    $GLOBALS['config'] = ['app' => ['security_csp' => '0']];
    (new \app\middleware\SecurityHeaders())->handle(new \stdClass(), static function () {
        echo 'STREAMED-POLICY-FIXTURE';
        flush();
        if (($_SERVER['REQUEST_URI'] ?? '') === '/exit') { exit; }
        return new \stdClass();
    });
}
