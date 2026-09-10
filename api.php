<?php
/*
'软件名称：苹果CMS  源码库：https://github.com/magicblack
'--------------------------------------------------------
'Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
'遵循Apache2开源协议发布，并提供免费使用。
'--------------------------------------------------------
*/
header('Content-Type:text/html;charset=utf-8');
if (version_compare(PHP_VERSION, '8.3.0', '<')) {
    die('PHP >= 8.3 required');
}

// HTTP 侧:30 秒上限,超时按超时处理而非永久占 worker;256M 防泄漏。
// CLI 侧(bin/timming 触发的定时任务)必须放开 —— 一次采集动辄几分钟、上万条,
// 30 秒会把采集拦腰截断,而且截断点不确定,表现为"每次都只采一部分"。
$__isCli = PHP_SAPI === 'cli';
ini_set('max_execution_time', $__isCli ? '0'    : '30');
ini_set('memory_limit',       $__isCli ? '1024M': '256M');
unset($__isCli);

define('ROOT_PATH',       __DIR__ . '/');
define('APP_PATH',        __DIR__ . '/application/');
define('RUNTIME_PATH',    __DIR__ . '/runtime/');
define('ADDON_PATH',      __DIR__ . '/addons/');
define('MAC_COMM',        __DIR__ . '/application/common/common/');
define('MAC_HOME_COMM',   __DIR__ . '/application/index/common/');
define('MAC_ADMIN_COMM',  __DIR__ . '/application/admin/common/');
define('MAC_START_TIME',  microtime(true));
define('ENTRANCE',        'api');
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
// 同 index.php：生产默认由 config/app.php 保证 false，本地 .env 可覆盖调试。
$http     = $app->http;
$response = $http->name('api')->path(APP_PATH . 'api/')->run();
$response->send();
$http->end($response);
