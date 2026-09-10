<?php
namespace Qiniu {
    class Auth { public function __construct(...$args) {} public function uploadToken(...$args) { return 'audit-token'; } }
}
namespace Qiniu\Storage {
    class UploadManager { public function putFile(...$args) { return $GLOBALS['uploadFails'] ? [null, new \RuntimeException('fixture failure')] : [['key' => 'uploaded'], null]; } }
}
namespace Upyun {
    class Config { public function __construct(...$args) {} }
    class Upyun { public function __construct(...$args) {} public function write($path, $stream) { if ($GLOBALS['uploadFails']) { throw new \RuntimeException('fixture failure'); } return []; } }
}
namespace Aws\S3 {
    class S3Client { public function __construct(...$args) {} public function putObject(array $args) { if ($GLOBALS['uploadFails']) { throw new \RuntimeException('fixture failure'); } return ['ObjectURL' => 'https://cdn.invalid/uploaded']; } }
}
namespace app\common\util {
    class Ftp { public function __construct(...$args) {} public function connect() { return $this; } public function put(...$args) { return !$GLOBALS['uploadFails']; } }
    class SinaUpload {
        public array $_config = ['cookie' => 'audit-cookie'];
        public function config($config) {}
        public function check() { return ['code' => $GLOBALS['uploadFails'] ? 2 : 1, 'msg' => 'fixture']; }
        public function upload(...$args) { return ['url' => 'https://cdn.invalid/uploaded']; }
    }
}
namespace app\common\extend\upload {
    function curl_init() { return new \stdClass(); }
    function curl_setopt($handle, $option, $value) { $GLOBALS['curlOptions'][$option] = $value; return true; }
    function curl_exec($handle) { return $GLOBALS['uploadFails'] ? '{}' : '{"code":0,"url":"https://cdn.invalid/uploaded"}'; }
    function curl_close($handle) {}
    function mac_curl_post($url, $data) { return $GLOBALS['uploadFails'] ? '{}' : '{"code":1,"imgurl":"https://cdn.invalid/uploaded"}'; }
}
namespace {
    $root = dirname(__DIR__);
    $tmp = sys_get_temp_dir() . '/maccms-uploads-' . bin2hex(random_bytes(5));
    mkdir($tmp . '/upload', 0700, true);
    mkdir($tmp . '/extend/qiniu', 0700, true);
    mkdir($tmp . '/extend/upyun/vendor', 0700, true);
    file_put_contents($tmp . '/extend/qiniu/autoload.php', '<?php');
    file_put_contents($tmp . '/extend/upyun/vendor/autoload.php', '<?php');
    define('ROOT_PATH', $tmp . '/');
    require $root . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });
    $settings = ['bucket' => 'audit', 'accesskey' => 'audit', 'secretkey' => 'audit', 'region' => 'us-east-1', 'username' => 'audit', 'pwd' => 'audit', 'url' => 'https://cdn.invalid', 'type' => 'ali', 'openid' => 'audit', 'key' => 'audit', 'host' => 'audit', 'port' => 21, 'user' => 'audit', 'path' => '/'];
    foreach (['qiniu', 'upyun', 's3', 'alibaba', 'uomg', 'weibo', 'ftp'] as $provider) { $GLOBALS['config']['upload']['api'][$provider] = $settings; }
    $checks = 0;
    $check = static function ($condition, $message) use (&$checks) { if (!$condition) { throw new \RuntimeException($message); } $checks++; };
    $cleanup = static function ($dir) use (&$cleanup) {
        foreach (scandir($dir) as $name) {
            if ($name === '.' || $name === '..') { continue; }
            $path = $dir . '/' . $name;
            if (is_dir($path)) { $cleanup($path); } else { unlink($path); }
        }
        rmdir($dir);
    };
    try {
        foreach (['Qiniu', 'Upyun', 'S3', 'Alibaba', 'Uomg', 'Weibo', 'Ftp'] as $provider) {
            $class = 'app\\common\\extend\\upload\\' . $provider;
            foreach (['fail' => [true, false], 'success' => [false, false], 'keep' => [false, true]] as $case => [$fail, $keep]) {
                $GLOBALS['uploadFails'] = $fail;
                $GLOBALS['config']['upload']['api']['ftp']['host'] = $case;
                $path = 'upload/' . $provider . '-' . $case . '.txt';
                file_put_contents(ROOT_PATH . $path, 'source bytes');
                ob_start();
                $result = (new $class(['keep_local' => $keep]))->submit($path);
                $output = ob_get_clean();
                $check($output === '', $provider . ' does not emit provider errors');
                $check($fail ? $result === $path : str_starts_with($result, 'https://cdn.invalid/'), $provider . ' reports the actual local/remote object');
                $check(is_file(ROOT_PATH . $path) === ($fail || $keep), $provider . ' retains source on failure/keep_local');
            }
        }
        $check($GLOBALS['curlOptions'][CURLOPT_SSL_VERIFYPEER] === true && $GLOBALS['curlOptions'][CURLOPT_SSL_VERIFYHOST] === 2, 'Alibaba verifies TLS');
        file_put_contents(ROOT_PATH . 'upload/invalid.txt', 'source');
        $check(\app\common\extend\upload\StorageResult::complete('upload/invalid.txt', 'javascript:alert(1)', []) === 'upload/invalid.txt' && is_file(ROOT_PATH . 'upload/invalid.txt'), 'Invalid remote URL cannot delete source');
        echo "OK {$checks} upload adapter checks on PHP " . PHP_VERSION . "\n";
    } finally { $cleanup($tmp); }
}
