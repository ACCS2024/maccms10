<?php
/**
 * 轻量 HTTP 冒烟:在进程内启动 TP8 应用并对单个 URL 跑一次完整请求,
 * 打印 HTTP 状态码(或异常),用于在无 Web 服务器的环境(CI)下抓
 * 「改动把站点改崩」级别的回归(路由/中间件/控制器/模板/ORM 全链路)。
 *
 * 用法:  php tests/http_smoke.php <app> <url> [expected_status=200] [required_body_text]
 *   <app> = index | api | admin
 *   <url> = 形如 /vod/type/id/1.html
 * 退出码:0 = 状态/内容契约通过;1 = 不符合契约或异常。控制器直接 exit 也必须验证。
 *
 * 需先完成安装(application/data/install/install.lock 存在)且 .env 指向可用数据库。
 */

$app  = $argv[1] ?? 'index';
$url  = $argv[2] ?? '/';
$root = dirname(__DIR__) . '/';
$expectedStatus = isset($argv[3]) ? (int) $argv[3] : 200;
$requiredText = $argv[4] ?? '';
if (!in_array($app, ['index', 'api', 'admin'], true) || $expectedStatus < 100 || $expectedStatus > 599) {
    fwrite(STDERR, "Invalid smoke test arguments\n");
    exit(2);
}
$verified = false;
$verify = static function (int $code, string $content) use ($app, $url, $expectedStatus, $requiredText): int {
    $contentErr = str_contains($content, '<title>系统发生错误</title>')
        || (strlen($content) < 300 && str_contains($content, '系统核心功能异常'));
    $ok = $code === $expectedStatus && !$contentErr
        && ($code !== 200 || trim($content) !== '')
        && ($requiredText === '' || str_contains($content, $requiredText));
    printf("[%s] %-44s -> HTTP %d %s\n", $app, $url, $code, $ok ? 'PASS' : 'FAIL (status/body contract)');
    return $ok ? 0 : 1;
};
ob_start();
register_shutdown_function(static function () use (&$verified, $verify): void {
    if ($verified) {
        return;
    }
    $body = (string) ob_get_clean();
    $last = error_get_last();
    if ($last && in_array($last['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        fwrite(STDERR, "Unverified fatal exit: " . $last['message'] . "\n");
        exit(1);
    }
    $verified = true;
    exit($verify(http_response_code() ?: 200, $body));
});

$path = parse_url($url, PHP_URL_PATH) ?: '/';

$_SERVER['REQUEST_METHOD']  = 'GET';
$_SERVER['REQUEST_URI']     = $url;
$_SERVER['SCRIPT_NAME']     = '/' . $app . '.php';
$_SERVER['SCRIPT_FILENAME'] = $root . $app . '.php';
$_SERVER['PATH_INFO']       = $path;
$_SERVER['HTTP_HOST']       = $_SERVER['HTTP_HOST'] ?? '127.0.0.1';
$_GET = $_POST = [];
parse_str((string) parse_url($url, PHP_URL_QUERY), $_GET);

define('ROOT_PATH',      $root);
define('APP_PATH',       $root . 'application/');
define('RUNTIME_PATH',   $root . 'runtime/');
define('ADDON_PATH',     $root . 'addons/');
define('MAC_COMM',       $root . 'application/common/common/');
define('MAC_HOME_COMM',  $root . 'application/index/common/');
define('MAC_ADMIN_COMM', $root . 'application/admin/common/');
define('MAC_START_TIME', microtime(true));
define('ENTRANCE',       $app);
define('DS',             DIRECTORY_SEPARATOR);
define('EXT',            '.php');
define('IN_FILE',        '/' . $app . '.php');

require $root . 'vendor/autoload.php';

try {
    $application = new \app\MacApp(ROOT_PATH);
    $application->setAppPath(APP_PATH);
    $response = $application->http->name($app)->path(APP_PATH . $app . '/')->run();
    $code = $response->getCode();
    $content = (string) $response->getContent();
    $content = (string) ob_get_clean() . $content;
    $verified = true;
    exit($verify($code, $content));
} catch (\Throwable $e) {
    ob_end_clean();
    $verified = true;
    printf("[%s] %-44s -> EXC %s: %s @ %s:%d\n",
        $app, $url, get_class($e), $e->getMessage(),
        str_replace($root, '', $e->getFile()), $e->getLine());
    exit(1);
}
