<?php
/*
'软件名称：苹果CMS  源码库：https://github.com/magicblack
'--------------------------------------------------------
'Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
'遵循Apache2开源协议发布，并提供免费使用。
'--------------------------------------------------------
*/
header('Content-Type:text/html;charset=utf-8');
if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    die('PHP >= 8.0 required');
}

ini_set('max_execution_time', '120');   // 前台请求 2 分钟上限，防慢查询耗尽 worker
ini_set('memory_limit', '256M');        // 256M 足够前台页面渲染，防内存泄漏打垮 FPM

define('ROOT_PATH',       __DIR__ . '/');
define('APP_PATH',        __DIR__ . '/application/');
define('RUNTIME_PATH',    __DIR__ . '/runtime/');
define('ADDON_PATH',      __DIR__ . '/addons/');
define('MAC_COMM',        __DIR__ . '/application/common/common/');
define('MAC_HOME_COMM',   __DIR__ . '/application/index/common/');
define('MAC_ADMIN_COMM',  __DIR__ . '/application/admin/common/');
define('MAC_START_TIME',  microtime(true));
define('ENTRANCE',        'index');
define('DS',              DIRECTORY_SEPARATOR);
define('EXT',             '.php');

$in_file = rtrim($_SERVER['SCRIPT_NAME'] ?? '', '/');
$_php_pos = strpos($in_file, '.php');
if ($_php_pos !== false && substr($in_file, $_php_pos) !== '.php') {
    $in_file = substr($in_file, 0, $_php_pos) . '.php';
}
unset($_php_pos);
define('IN_FILE', $in_file ?: '/');

if (!is_file('./application/data/install/install.lock')) {
    header('Location: ./install.php');
    exit;
}

if (isset($_SERVER['PATH_INFO']) && !mb_check_encoding($_SERVER['PATH_INFO'], 'utf-8')) {
    $_SERVER['PATH_INFO'] = mb_convert_encoding($_SERVER['PATH_INFO'], 'UTF-8', 'GBK');
}

require __DIR__ . '/vendor/autoload.php';
$app      = new \app\MacApp(ROOT_PATH);
$app->setAppPath(APP_PATH);
// debug 模式由 config/app.php（app_debug=false，已提交）控制生产默认值；
// 开发者可在本地 .env（gitignore）写 APP_DEBUG=true 覆盖，用于前台调试。
// ExceptionHandle 本身已是安全边界：无论 debug 开关，对外永不泄露堆栈/路径。
$http     = $app->http;
$response = $http->name('index')->path(APP_PATH . 'index/')->run();
$response->send();
$http->end($response);
