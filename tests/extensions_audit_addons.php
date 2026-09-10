<?php
/** Strict PHP checks with a fresh container and temporary addon/view configuration. */
$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/maccms-addons-' . bin2hex(random_bytes(5));
mkdir($tmp . '/addons/aicontent/view/admin', 0700, true);
mkdir($tmp . '/addons/adminloginbg', 0700, true);
mkdir($tmp . '/runtime', 0700, true);
define('ROOT_PATH', $tmp . '/');
define('APP_PATH', $tmp . '/application/');
define('ADDON_PATH', $tmp . '/addons/');
define('RUNTIME_PATH', $tmp . '/runtime/');
define('DS', DIRECTORY_SEPARATOR);
file_put_contents(ADDON_PATH . 'aicontent/config.php', '<?php return [];');
file_put_contents(ADDON_PATH . 'adminloginbg/info.ini', "name = adminloginbg\nstate = 1\n");
file_put_contents(ADDON_PATH . 'adminloginbg/config.php', "<?php return [['name'=>'mode','value'=>'daily']];");
foreach (glob($root . '/addons/aicontent/view/admin/*.html') as $view) {
    copy($view, ADDON_PATH . 'aicontent/view/admin/' . basename($view));
}
require $root . '/vendor/autoload.php';
require_once $root . '/vendor/topthink/framework/src/helper.php';
$app = new \think\App($tmp . '/');
\think\Container::setInstance($app);
$app->config->set(['type' => 'Think', 'cache_path' => RUNTIME_PATH . 'temp/', 'tpl_cache' => false, 'default_filter' => 'htmlspecialchars'], 'view');
$app->config->set(['default' => 'file', 'stores' => ['file' => ['type' => 'File', 'path' => RUNTIME_PATH . 'cache/']]], 'cache');
$app->config->set(['site' => ['install_dir' => '/subdir']], 'maccms');
$app->config->set(['default_lang' => 'en'], 'lang');
$app->config->set(['url_html_suffix' => 'html'], 'route');
$app->request->withServer(['SCRIPT_NAME' => '/index.php', 'HTTP_HOST' => 'site.invalid', 'SERVER_PORT' => '80'])->setMethod('GET');
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new \ErrorException($message, 0, $level, $file, $line);
});
$checks = 0;
$check = static function ($condition, $message) use (&$checks) {
    if (!$condition) { throw new \RuntimeException($message); }
    $checks++;
};
$cleanup = static function ($dir) use (&$cleanup) {
    foreach (scandir($dir) as $name) {
        if ($name === '.' || $name === '..') { continue; }
        $path = $dir . '/' . $name;
        if (is_dir($path) && !is_link($path)) { $cleanup($path); } else { unlink($path); }
    }
    rmdir($dir);
};
try {
    $bg = new \addons\adminloginbg\Adminloginbg();
    $ai = new \addons\aicontent\Aicontent();
    $check($bg->enable() && $bg->disable() && $ai->disable(), 'All abstract lifecycle contracts are implemented');
    $check($bg->getInfo()['name'] === 'adminloginbg' && $bg->getConfig()['mode'] === 'daily', 'Default addon configuration uses lowercase directory');
    $check($ai->addons_path === ADDON_PATH . 'aicontent/', 'AI plugin resource directory');
    $check(\addons\aicontent\service\AdminAccess::allows(['admin_id' => 1], ['addon/config']), 'Super administrator can use plugin');
    $check(\addons\aicontent\service\AdminAccess::allows(['admin_id' => 2, 'admin_auth' => ',vod/info,'], ['addon/config', 'vod/info']), 'Content editor can enhance authorized content');
    $check(!\addons\aicontent\service\AdminAccess::allows(['admin_id' => 2, 'admin_auth' => ',newvod/info,'], ['vod/info']), 'Permission comparisons do not accept substrings');
    $check(!\addons\aicontent\service\AdminAccess::allows(['admin_id' => 2, 'admin_auth' => ',vod/info,'], ['addon/config']), 'Content editor cannot inspect global AI task history');

    $generator = (new \ReflectionClass(\addons\aicontent\service\ContentGenerator::class))->newInstanceWithoutConstructor();
    $result = $generator->parseResponse('{"description":[],"seo_title":{},"tags":["good",["nested"],null,0]}');
    $check($result['description'] === '' && $result['seo_title'] === '' && $result['tags'] === ['good', '0'], 'Untrusted AI JSON becomes flat strings');
    $result = $generator->parseResponse('{"tags":"one,,two"}');
    $check($result['tags'] === ['one', 'two'], 'Comma tags return a JSON list');
    $model = new class('audit-key', 'audit-model') extends \addons\aicontent\service\models\BaseModel {
        public function generate(string $prompt): string { return ''; }
        public function getAvailableModels(): array { return []; }
        public function decode(string $body): array { return $this->parseJson($body); }
    };
    foreach (['null', '1', '"text"'] as $invalid) {
        try { $model->decode($invalid); throw new \LogicException('Scalar JSON accepted'); }
        catch (\RuntimeException $expected) { $checks++; }
    }

    foreach ([\addons\aicontent\controller\Api::class => ['generate', 'batch', 'enhance', 'testkey'], \addons\aicontent\controller\Admin::class => ['delete']] as $class => $methods) {
        $controller = (new \ReflectionClass($class))->newInstanceWithoutConstructor();
        $property = new \ReflectionProperty(\think\addons\Controller::class, 'request');
        $property->setValue($controller, $app->request);
        foreach ($methods as $method) {
            $response = $controller->$method();
            $check($response->getCode() === 405, 'GET cannot execute ' . $method);
        }
    }

    $admin = (new \ReflectionClass(\addons\aicontent\controller\Admin::class))->newInstanceWithoutConstructor();
    $fetch = new \ReflectionMethod(\think\addons\Controller::class, 'fetch');
    $html = $fetch->invoke($admin, 'admin/index', ['tasks' => [], 'total' => 0, 'page' => 1, 'stats' => ['total' => 0, 'done' => 0, 'pending' => 0, 'error' => 0], 'jsLang' => '{}', 'csrfToken' => 'audit-csrf']);
    $check(str_contains($html, 'audit-csrf') && str_contains($html, '/subdir/static/addons/aicontent'), 'Dashboard renders with local layout, subdirectory and CSRF token');
    $check($app->config->get('view.view_path') === null, 'Addon rendering does not replace global view configuration');
    echo "OK {$checks} addon checks on PHP " . PHP_VERSION . "\n";
} finally {
    $cleanup($tmp);
}
