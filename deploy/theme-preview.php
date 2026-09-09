<?php
// Copy to <site>/theme-preview-20260909-a7c4/live/index.php for an isolated preview.
// The production entry, template selection and configuration files are not modified.
if (!in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['GET', 'HEAD'], true)) {
    http_response_code(405); header('Allow: GET, HEAD'); exit;
}
$previewSiteRoot = dirname(__DIR__, 2) . '/';
if (!is_file($previewSiteRoot . 'vendor/autoload.php')) {
    http_response_code(503); exit('Preview installation is incomplete.');
}
$previewPath = trim((string)($_SERVER['PATH_INFO'] ?? $_GET['s'] ?? ''), '/');
if ($previewPath !== '' && !preg_match('~^(?:index(?:/index)?|rep/index|macrep|vod/(?:index|type|show|search|detail|play|player)|art/(?:index|type|show|search|detail)|vod(?:type|show|search|detail|play|player)|art(?:type|show|search|detail))(?:[/.\-]|$)~i', $previewPath)) {
    http_response_code(404); exit;
}
chdir($previewSiteRoot);
ini_set('max_execution_time', '120');
ini_set('memory_limit', '256M');
define('ROOT_PATH', $previewSiteRoot);
define('APP_PATH', ROOT_PATH . 'application/');
define('RUNTIME_PATH', ROOT_PATH . 'runtime/theme-preview-v2/');
define('ADDON_PATH', ROOT_PATH . 'addons/');
define('MAC_COMM', APP_PATH . 'common/common/');
define('MAC_HOME_COMM', APP_PATH . 'index/common/');
define('MAC_ADMIN_COMM', APP_PATH . 'admin/common/');
define('MAC_START_TIME', microtime(true));
define('ENTRANCE', 'index');
define('DS', DIRECTORY_SEPARATOR);
define('EXT', '.php');
define('IN_FILE', preg_replace('~\.php.*$~', '.php', $_SERVER['SCRIPT_NAME'] ?? '/index.php'));
require ROOT_PATH . 'vendor/autoload.php';
$previewApp = new \app\MacApp(ROOT_PATH);
$previewApp->setAppPath(APP_PATH);
$previewApp->setRuntimePath(RUNTIME_PATH);
$previewApp->initialize();
$previewConfig = $previewApp->config->get('maccms');
$previewConfig['site']['template_dir'] = 'm1938pc3_v2';
$previewConfig['site']['html_dir'] = 'html9';
$previewConfig['site']['mob_status'] = '0';
$previewConfig['site']['site_publish_status'] = '0';
$previewConfig['app']['cache_time_page'] = '0';
$previewConfig['app']['cache_flag'] .= '_theme_preview_v2';
$previewConfig['rewrite']['status'] = '0';
$previewConfig['rewrite']['suffix_hide'] = '0';
foreach ($previewConfig['view'] as $key => $value) { $previewConfig['view'][$key] = '0'; }
$previewApp->config->set($previewConfig, 'maccms');
$previewApp->config->set(['domain' => []]);
$previewApp->config->set(['name' => 'ZYTHEMEPREVIEW', 'prefix' => 'zy_theme_preview_', 'path' => RUNTIME_PATH . 'session/'], 'session');
$previewApp->config->set(['tpl_cache' => false, 'cache_path' => RUNTIME_PATH . 'temp/'], 'view');
$previewHttp = $previewApp->http;
$previewResponse = $previewHttp->name('index')->path(APP_PATH . 'index/')->run();
$previewResponse->header(['Cache-Control' => 'no-store', 'X-Robots-Tag' => 'noindex, nofollow']);
$previewResponse->send();
$previewHttp->end($previewResponse);
