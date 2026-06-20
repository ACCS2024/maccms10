<?php
/**
 * 轻量 HTTP 冒烟:在进程内启动 TP8 应用并对单个 URL 跑一次完整请求,
 * 打印 HTTP 状态码(或异常),用于在无 Web 服务器的环境(CI)下抓
 * 「改动把站点改崩」级别的回归(路由/中间件/控制器/模板/ORM 全链路)。
 *
 * 用法:  php tests/http_smoke.php <app> <url>
 *   <app> = index | api | admin
 *   <url> = 形如 /vod/type/id/1.html
 * 退出码:0 = 非 5xx(通过);1 = 5xx 或抛异常(失败)。
 *
 * 需先完成安装(application/data/install/install.lock 存在)且 .env 指向可用数据库。
 */

$app  = $argv[1] ?? 'index';
$url  = $argv[2] ?? '/';
$root = dirname(__DIR__) . '/';

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
    // 不只看状态码:完整性守卫/部分异常会以 HTTP 200 返回错误内容,需按内容兜底。
    $content    = (string) $response->getContent();
    $contentErr = (strpos($content, '<title>系统发生错误</title>') !== false)
        || (strlen($content) < 300 && strpos($content, '系统核心功能异常') !== false);
    printf("[%s] %-44s -> HTTP %d%s\n", $app, $url, $code, $contentErr ? ' (内容错误页)' : '');
    exit(($code >= 500 || $contentErr) ? 1 : 0);
} catch (\Throwable $e) {
    printf("[%s] %-44s -> EXC %s: %s @ %s:%d\n",
        $app, $url, get_class($e), $e->getMessage(),
        str_replace($root, '', $e->getFile()), $e->getLine());
    exit(1);
}
