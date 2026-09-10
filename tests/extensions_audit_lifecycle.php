<?php
$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/maccms-lifecycle-' . bin2hex(random_bytes(5));
mkdir($tmp . '/addons/auditfixture', 0700, true);
mkdir($tmp . '/application/extra', 0700, true);
mkdir($tmp . '/runtime', 0700, true);
define('ROOT_PATH', $tmp . '/');
define('APP_PATH', $tmp . '/application/');
define('ADDON_PATH', $tmp . '/addons/');
define('RUNTIME_PATH', $tmp . '/runtime/');
define('DS', DIRECTORY_SEPARATOR);
file_put_contents(ADDON_PATH . 'auditfixture/info.ini', "name = auditfixture\ntitle = \"A fixture plugin\"\nversion = 1\nstate = 0\n");
file_put_contents(ADDON_PATH . 'auditfixture/config.php', '<?php return [];');
$fixture = <<<'PHP'
<?php
namespace addons\auditfixture;
class Auditfixture extends \think\Addons {
    public static array $calls = [];
    public static bool $failEnable = false;
    public function install(): bool { self::$calls[] = 'install'; file_put_contents($this->addons_path . 'installed.txt', 'installed'); return true; }
    public function uninstall(): bool { self::$calls[] = 'uninstall'; unlink($this->addons_path . 'installed.txt'); return true; }
    public function enable(): bool { self::$calls[] = 'enable'; return !self::$failEnable; }
    public function disable(): bool { self::$calls[] = 'disable'; return true; }
    public function appInit(): void { self::$calls[] = 'appInit'; }
    public function viewFilter(&$content): void { $content .= '-filtered'; }
    public static function helper(): string { return 'not a hook'; }
}
PHP;
file_put_contents(ADDON_PATH . 'auditfixture/Auditfixture.php', $fixture);
require $root . '/vendor/autoload.php';
require_once $root . '/vendor/topthink/framework/src/helper.php';
spl_autoload_register(static function ($class) {
    if ($class === 'addons\\auditfixture\\Auditfixture') { require ADDON_PATH . 'auditfixture/Auditfixture.php'; }
}, true, true);
$app = new \think\App($tmp . '/');
\think\Container::setInstance($app);
$app->config->set(['default' => 'file', 'stores' => ['file' => ['type' => 'File', 'path' => RUNTIME_PATH . 'cache/']]], 'cache');
$app->config->set(['type' => 'Think', 'cache_path' => RUNTIME_PATH . 'temp/'], 'view');
$app->config->set(['url_html_suffix' => 'html'], 'route');
$app->config->set(['autoload' => false, 'hooks' => [], 'route' => []], 'addons');
$app->request->withServer(['SCRIPT_NAME' => '/index.php', 'HTTP_HOST' => 'site.invalid', 'SERVER_PORT' => '80']);
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new \ErrorException($message, 0, $level, $file, $line);
});
$checks = 0;
$check = static function ($condition, $message) use (&$checks) { if (!$condition) { throw new \RuntimeException($message); } $checks++; };
$cleanup = static function ($dir) use (&$cleanup) {
    foreach (scandir($dir) as $name) {
        if ($name === '.' || $name === '..') { continue; }
        $path = $dir . '/' . $name;
        if (is_dir($path) && !is_link($path)) { $cleanup($path); } else { unlink($path); }
    }
    rmdir($dir);
};
try {
    \think\addons\Service::install('auditfixture');
    $check(is_file(ADDON_PATH . 'auditfixture/installed.txt'), 'Installation callback writes only temporary fixture');
    $info = get_addon_info('auditfixture');
    $check((int)$info['state'] === 1 && (int)$info['installed'] === 1, 'Installation persists state');
    $hooks = $app->config->get('addons.hooks');
    $check(isset($hooks['app_init'], $hooks['view_filter']) && !isset($hooks['helper']), 'Public instance hooks are mapped and static helpers excluded');
    addons_boot();
    $check(count(array_filter(\addons\auditfixture\Auditfixture::$calls, static fn($call) => $call === 'appInit')) === 1, 'appInit callback executes exactly once');
    $check(\think\facade\View::display('body') === 'body-filtered', 'TP8 view filter invokes plugin method');
    \think\addons\Service::disable('auditfixture');
    $check((int)get_addon_info('auditfixture')['state'] === 0 && $app->config->get('addons.hooks') === [], 'Disable removes hooks and persists state');
    \addons\auditfixture\Auditfixture::$failEnable = true;
    try { \think\addons\Service::enable('auditfixture'); throw new \LogicException('False callback accepted'); }
    catch (\think\addons\AddonException $expected) { $checks++; }
    $check((int)get_addon_info('auditfixture')['state'] === 0, 'Failed callback cannot report enabled state');
    \addons\auditfixture\Auditfixture::$failEnable = false;
    \think\addons\Service::enable('auditfixture');
    $check((int)get_addon_info('auditfixture')['state'] === 1, 'Enable succeeds');
    \think\addons\Service::uninstall('auditfixture');
    $check(!is_file(ADDON_PATH . 'auditfixture/installed.txt') && is_file(ADDON_PATH . 'auditfixture/Auditfixture.php'), 'Uninstall runs callback and retains reviewed source');
    $check((int)get_addon_info('auditfixture')['installed'] === 0, 'Uninstall persists installed marker');
    foreach ([static fn() => \think\addons\Service::install('../outside'), static fn() => \think\addons\Service::install([]), static fn() => \think\addons\Service::install('missing'), static fn() => \think\addons\Service::upgrade('auditfixture'), static fn() => \think\addons\Service::enable('auditfixture')] as $reject) {
        try { $reject(); throw new \LogicException('Invalid/retired operation accepted'); }
        catch (\think\addons\AddonException $expected) { $checks++; }
    }
    \think\addons\Service::install('auditfixture');
    $check(is_file(ADDON_PATH . 'auditfixture/installed.txt'), 'Reviewed local source can be reinstalled');
    $info = get_addon_info('auditfixture');
    $info['title'] = 'Quoted "plugin"; value';
    set_addon_info('auditfixture', $info);
    $check(get_addon_info('auditfixture')['title'] === $info['title'], 'INI metadata round-trips quotes and delimiters');
    $before = file_get_contents(ADDON_PATH . 'auditfixture/info.ini');
    $info['title'] = "bad\nstate = 1";
    try { set_addon_info('auditfixture', $info); throw new \LogicException('INI newline accepted'); }
    catch (\RuntimeException $expected) { $checks++; }
    $check(file_get_contents(ADDON_PATH . 'auditfixture/info.ini') === $before, 'Rejected metadata leaves file intact');
    echo "OK {$checks} lifecycle checks on PHP " . PHP_VERSION . "\n";
} finally { $cleanup($tmp); }
