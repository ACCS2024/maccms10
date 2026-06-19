<?php
/*
'软件名称：苹果CMS 源码库：https://github.com/magicblack
'--------------------------------------------------------
'Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
'遵循Apache2开源协议发布，并提供免费使用。
'--------------------------------------------------------
*/
header('Content-Type:text/html;charset=utf-8');
if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    die('PHP >= 8.0 required');
}

ini_set('max_execution_time', '0');
ini_set('memory_limit', '-1');

define('ROOT_PATH',     __DIR__ . '/');
define('APP_PATH',      __DIR__ . '/application/');
define('RUNTIME_PATH',  __DIR__ . '/runtime/');
define('MAC_COMM',      __DIR__ . '/application/common/common/');
define('MAC_HOME_COMM', __DIR__ . '/application/index/common/');
define('MAC_ADMIN_COMM',__DIR__ . '/application/admin/common/');
define('MAC_START_TIME', microtime(true));
define('BIND_MODULE',   'install');
define('ENTRANCE',      'install');
define('DS',            DIRECTORY_SEPARATOR);
define('EXT',           '.php');

$in_file = rtrim($_SERVER['SCRIPT_NAME'] ?? '', '/');
$_php_pos = strpos($in_file, '.php');
if ($_php_pos !== false && substr($in_file, $_php_pos) !== '.php') {
    $in_file = substr($in_file, 0, $_php_pos) . '.php';
}
unset($_php_pos);
define('IN_FILE', $in_file ?: '/install.php');

if (is_file('./application/data/install/install.lock')) {
    echo '如需重新安装请删除【To re install, please remove】 >>> /application/data/install/install.lock';
    exit;
}

if (!is_writable('./runtime')) {
    echo '请开启[runtime]目录的读写权限【Please turn on the read and write permissions of the [runtime] folder】';
    exit;
}

require __DIR__ . '/vendor/autoload.php';
$app = new \think\App(ROOT_PATH);
$app->setAppPath(APP_PATH);
$http     = $app->http;
$response = $http->name('install')->path(APP_PATH . 'install/')->run();
$response->send();
$http->end($response);
