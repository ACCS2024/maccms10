<?php
/** Resource directory behavior without a database, deployment configuration, or network. */
declare(strict_types=1);

namespace think\facade {
    final class Cache
    {
        public static function get($key) { throw new \RuntimeException('Legacy cloud cache read: ' . $key); }
        public static function set(...$args) { throw new \RuntimeException('Unexpected cache write'); }
    }
    final class Request
    {
        public static array $input = [];
        public static function post() { return self::$input; }
        public static function param() { return self::$input; }
    }
}
namespace app\common\util {
    function dns_get_record($host, $type) {
        $GLOBALS['resource_audit_dns'][] = $host;
        if ($host !== 'custom.example') { throw new \RuntimeException('Unexpected DNS: ' . $host); }
        return [['ip' => '8.8.8.8']];
    }
    function gethostbynamel($host) { throw new \RuntimeException('Unexpected fallback DNS'); }
}
namespace app\admin\controller {
    class Base
    {
        public array $assigned = [];
        public function __construct() {}
        protected function assign($key, $value = ''): void { $this->assigned[$key] = $value; }
        protected function fetch(string $template = '', array $vars = []): string { return $template; }
    }
    function file_get_contents($file, ...$args) {
        if (preg_match('~^(?:https?:)?//~i', $file)) { throw new \RuntimeException('Direct remote file read'); }
        return \file_get_contents($file, ...$args);
    }
    function gethostbyname($host) { throw new \RuntimeException('Uncontrolled DNS lookup'); }
    function mac_curl_get($url) {
        $target = \app\common\util\PublicHttpClient::resolve($url);
        if ($target === null) { return false; }
        if ($target['host'] !== 'custom.example') { throw new \RuntimeException('Unexpected resource request'); }
        $GLOBALS['resource_audit_requests'][] = $url;
        return '{"list":[],"total":7}';
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    require dirname(__DIR__) . '/application/common.php';
    require dirname(__DIR__) . '/application/admin/controller/ResourceHub.php';
    require dirname(__DIR__) . '/application/admin/controller/Safety.php';
    require dirname(__DIR__) . '/application/admin/controller/Update.php';
    function lang($key) { return $key; }
    function json($data) { return $data; }
    function url($path) { return '/' . $path; }
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });

    $root = sys_get_temp_dir() . '/maccms-resource-local-' . bin2hex(random_bytes(6));
    mkdir($root . '/extra', 0700, true);
    define('APP_PATH', $root . '/');
    $catalog = $root . '/extra/resource_sites_custom.php';
    $marker = $root . '/executed';
    $GLOBALS['resource_audit_dns'] = [];
    $GLOBALS['resource_audit_requests'] = [];
    $checks = 0;
    $check = static function ($condition, string $message) use (&$checks): void {
        if (!$condition) { throw new \RuntimeException($message); }
        $checks++;
    };
    $controller = new class extends \app\admin\controller\ResourceHub { public function __construct() {} };
    $render = static function (array $sites) use ($root): string {
        $source = file_get_contents(dirname(__DIR__) . '/application/admin/view/resourcehub/index.html');
        // Render the actual directory view; shared application chrome needs a full login bootstrap.
        $source = preg_replace('/\{include\b[^}]+\}/', '', $source);
        $template = new \think\Template(['cache_path' => $root . '/template/', 'tpl_cache' => false, 'default_filter' => '']);
        ob_start();
        try { $template->display($source, ['sites' => $sites]); return ob_get_contents(); }
        finally { ob_end_clean(); }
    };
    try {
        $check($controller->index() === 'resourcehub/index', 'Directory route still renders its view');
        $check($controller->assigned['sites'] === [], 'Missing local catalog remains empty without a cloud fallback');
        $emptyHtml = $render($controller->assigned['sites']);
        $check(substr_count($emptyHtml, 'id="addCustomSite"') === 1, 'An empty catalog must offer its first add action');
        $check(!str_contains($emptyHtml, 'cloud_fetch_fail'), 'Local empty state must not claim a cloud/network failure');
        $check($GLOBALS['resource_audit_dns'] === [] && $GLOBALS['resource_audit_requests'] === [], 'Opening the directory must be entirely local');

        \think\facade\Request::$input = ['name' => 'Owned API', 'url' => 'https://custom.example/api', 'desc' => 'Local'];
        $check($controller->addCustomSite()['code'] === 1, 'Custom API addition still works');
        $controller->index();
        $check(count($controller->assigned['sites']) === 1 && $controller->assigned['sites'][0]['name'] === 'Owned API', 'The saved custom site survives a fresh local read');
        $saved = file_get_contents($catalog);
        foreach (['https://update.maccms.la/v10/', 'https://UPDATE.MACCMS.LA./v10/', 'https://api.maccms.ai/sites.json', 'https://code.jquecy.com/', 'http://127.0.0.1/', 'file:///etc/passwd'] as $url) {
            $beforeDns = count($GLOBALS['resource_audit_dns']);
            \think\facade\Request::$input = ['name' => 'Rejected', 'url' => $url];
            $check($controller->addCustomSite()['code'] === 0, 'Unsafe/upstream API must not be stored');
            $check(file_get_contents($catalog) === $saved, 'Rejected entries must leave the local catalog unchanged');
            $check(count($GLOBALS['resource_audit_dns']) === $beforeDns, 'Blocked addresses must be rejected before DNS');
            \think\facade\Request::$input = ['url' => $url];
            $check($controller->check()['code'] === 0, 'API health checks must also reject unsafe/upstream addresses');
        }
        \think\facade\Request::$input = ['name' => [], 'url' => 'https://custom.example/api'];
        $check($controller->addCustomSite()['code'] === 0 && file_get_contents($catalog) === $saved, 'Malformed input cannot corrupt the catalog');
        \think\facade\Request::$input = ['url' => 'https://custom.example/api'];
        $result = $controller->check();
        $check($result['code'] === 1 && $result['data']['total'] === 7, 'An explicitly requested custom API check still works');
        $check($GLOBALS['resource_audit_requests'] === ['https://custom.example/api?ac=list&pg=1'], 'Only the requested custom API is contacted');

        $injected = ['name' => '"><img src=x onerror=alert(1)>', 'url' => 'https://custom.example/?x=" onmouseover="alert(1)', 'type' => '2', 'mid' => '1', 'desc' => '<script>alert(1)</script>'];
        mac_arr2file($catalog, [$injected, ['name' => 'Second', 'url' => 'https://custom.example/second']]);
        $controller->index();
        $html = $render($controller->assigned['sites']);
        $document = new \DOMDocument();
        @$document->loadHTML($html);
        $xpath = new \DOMXPath($document);
        $check($xpath->query('//*[@onerror or @onmouseover]')->length === 0, 'Local entry fields cannot create event-handler attributes');
        $check($document->getElementsByTagName('img')->length === 0, 'Local entry names cannot inject HTML nodes');
        $check(!str_contains($html, '<script>alert(1)</script>'), 'Descriptions remain inert text');
        $check($xpath->query('//*[@data-name]')->item(0)->getAttribute('data-name') === $injected['name'], 'Escaping preserves the original action data');
        $check($xpath->query('//*[contains(@class,"btn-del-custom")]')->length === 2, 'Every local site exposes its delete action');
        \think\facade\Request::$input = ['index' => '0'];
        $check($controller->delCustomSite()['code'] === 1, 'Custom deletion still works');
        $controller->index();
        $check(count($controller->assigned['sites']) === 1 && $controller->assigned['sites'][0]['name'] === 'Second', 'Delete indices address the rendered local rows');

        file_put_contents($catalog, '<?php file_put_contents(' . var_export($marker, true) . ', "bad"); return [];');
        $rejected = false;
        try { $controller->index(); } catch (\RuntimeException $error) { $rejected = true; }
        $check($rejected && !file_exists($marker), 'A poisoned local PHP catalog is rejected without executing it');
        $synonyms = $root . '/extra/type_synonyms.php';
        $matchType = new \ReflectionMethod($controller, 'fuzzyMatchType');
        mac_arr2file($synonyms, []);
        $check($matchType->invoke($controller, '动作片', [['type_name' => '动作', 'type_id' => 7]]) === 7, 'Local category matching still works');
        file_put_contents($synonyms, '<?php file_put_contents(' . var_export($marker, true) . ', "bad"); return [];');
        $rejected = false;
        try { $matchType->invoke($controller, '动作片', []); } catch (\RuntimeException $error) { $rejected = true; }
        $check($rejected && !file_exists($marker), 'A poisoned category-synonym file cannot execute during matching');
        $safety = new \app\admin\controller\Safety();
        \think\facade\Request::$input = ['ck' => 1, 'ft' => [1, 2]];
        $check($safety->file() === 'admin@safety/file', 'Legacy integrity-check requests remain local');
        // A previously downloaded payload in the old writable update directory must stay inert.
        mkdir($root . '/application/data/update', 0700, true);
        $legacyPayload = $root . '/application/data/update/database.php';
        file_put_contents($legacyPayload, '<?php file_put_contents(' . var_export($marker, true) . ', "bad");');
        $cwd = getcwd();
        chdir($root);
        try {
            $update = new \app\admin\controller\Update();
            foreach (['index', 'step1', 'step2', 'step3'] as $action) {
                $check($update->$action() === 'admin@update/index', 'Every legacy update route renders the local instructions');
            }
            $check(!file_exists($marker) && is_file($legacyPayload), 'Legacy update routes neither execute nor destroy a downloaded payload');
        } finally { chdir($cwd); }
        $version = \app\common\util\DataConfig::read(dirname(__DIR__) . '/application/extra/version.php');
        $check($version['update_hash'] === md5_file(dirname(__DIR__) . '/application/admin/controller/Update.php'), 'The update controller integrity hash remains synchronized');
        echo 'Local resource directory: ' . $checks . " assertions passed\n";
    } finally {
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) { $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); }
        rmdir($root);
    }
}
