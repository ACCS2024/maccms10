<?php
/** Real loopback HTTP responses; repository stays read-only and no application bootstrap is used. */
declare(strict_types=1);
$output = getenv('QRCODE_AUDIT_OUTPUT') ?: sys_get_temp_dir() . '/qr-http-' . bin2hex(random_bytes(5));
if (is_dir($output) || !mkdir($output, 0700)) { throw new RuntimeException('Use a fresh HTTP fixture directory'); }
$keepOutput = getenv('QRCODE_AUDIT_OUTPUT') !== false;
$root = dirname(__DIR__);
$router = <<<'PHP'
<?php
namespace app\common\util {
    function ImagePng($image, $filename = null) {
        if (($GLOBALS['qr_audit_fault'] ?? '') === 'output') {
            \header('Content-Type: image/png');
            \ob_start();
            echo 'partial image';
            throw new \RuntimeException('fixture output failure');
        }
        if (($GLOBALS['qr_audit_fault'] ?? '') === 'empty') { return true; }
        return \imagepng($image, $filename);
    }
}
namespace {
    require __AUDIT_ROOT__ . '/vendor/autoload.php';
    require __AUDIT_ROOT__ . '/vendor/topthink/framework/src/helper.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });
    $app = new \think\App(__DIR__ . '/temporary-app/');
    \think\Container::setInstance($app);
    $app->request->withGet($_GET)->setMethod('GET');
    $GLOBALS['qr_audit_fault'] = $_GET['audit_fault'] ?? '';
    header('Content-Type: application/x-audit-before');
    ob_start();
    echo 'caller-owned-prefix';
    $depth = ob_get_level();
    if (($_GET['audit_target'] ?? '') === 'user') {
        $controller = (new \ReflectionClass(\app\index\controller\User::class))->newInstanceWithoutConstructor();
        $response = $controller->qrcode();
    } else {
        $response = (new \app\index\controller\Qrcode())->index();
    }
    $bufferPreserved = ob_get_level() === $depth && ob_get_contents() === 'caller-owned-prefix';
    ob_end_clean();
    $headerPreserved = in_array('Content-Type: application/x-audit-before', headers_list(), true);
    $response->header([
        'X-Audit-Buffer-Preserved' => $bufferPreserved ? 'yes' : 'no',
        'X-Audit-Header-Preserved' => $headerPreserved ? 'yes' : 'no',
    ])->send();
}
PHP;
file_put_contents($output . '/router.php', str_replace('__AUDIT_ROOT__', var_export($root, true), $router));
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
$address = stream_socket_get_name($socket, false);
fclose($socket);
$pipes = [];
$process = proc_open([PHP_BINARY, '-S', $address, $output . '/router.php'],
    [0 => ['pipe', 'r'], 1 => ['file', $output . '/server.log', 'a'], 2 => ['file', $output . '/server.log', 'a']], $pipes, $output);
fclose($pipes[0]);
$checks = 0;
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
};
try {
    for ($attempt = 0; $attempt < 100; $attempt++) {
        $ready = @stream_socket_client('tcp://' . $address, $errno, $error, 0.05);
        if ($ready !== false) { fclose($ready); break; }
        usleep(20000);
    }
    $check($ready !== false, 'Loopback HTTP fixture starts');
    $url = 'https://example.invalid/qr?id=123';
    $cases = [
        ['valid', ['url' => $url], 200],
        ['missing', [], 400],
        ['empty', ['url' => ''], 400],
        ['array', ['url' => ['nested']], 400],
        ['invalid', ['url' => 'not a URL'], 400],
        ['byte-capacity', ['url' => 'https://example.invalid/' . str_repeat('x', 3000)], 400],
        ['overall-capacity', ['url' => 'https://example.invalid/' . str_repeat('7', 7100)], 400],
        ['output-failure', ['url' => $url, 'audit_fault' => 'output'], 500],
        ['empty-output', ['url' => $url, 'audit_fault' => 'empty'], 500],
        ['user-valid', ['audit_target' => 'user', 'data' => 'weixin://fixture'], 200],
        ['user-missing', ['audit_target' => 'user'], 400],
        ['user-array', ['audit_target' => 'user', 'data' => ['nested']], 400],
        ['user-invalid', ['audit_target' => 'user', 'data' => 'weixin-other'], 400],
        ['user-overflow', ['audit_target' => 'user', 'data' => 'weixin://' . str_repeat('x', 3000)], 400],
        ['user-output-failure', ['audit_target' => 'user', 'data' => 'weixin://fixture', 'audit_fault' => 'output'], 500],
    ];
    foreach ($cases as [$name, $params, $expectedStatus]) {
        $headers = [];
        $curl = curl_init('http://' . $address . '/?' . http_build_query($params));
        curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headers): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $headers[strtolower($name)] = trim($value);
                }
                return strlen($line);
            }]);
        $body = curl_exec($curl);
        $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        $check(is_string($body) && $status === $expectedStatus, $name . ' returns its expected HTTP status; actual=' . $status . ' body=' . substr((string)$body, 0, 800));
        $check(($headers['x-audit-buffer-preserved'] ?? '') === 'yes', $name . ' preserves caller buffers');
        $check(($headers['x-audit-header-preserved'] ?? '') === 'yes', $name . ' removes encoder Content-Type side effects');
        if ($expectedStatus === 200) {
            $check(($headers['content-type'] ?? '') === 'image/png' && str_starts_with($body, "\x89PNG\r\n\x1a\n"),
                'Successful HTTP response contains a clean PNG');
            file_put_contents($output . '/' . $name . '.png', $body);
        } else {
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
            $check(str_starts_with($headers['content-type'] ?? '', 'application/json') && ($data['code'] ?? 0) > 1
                && !str_contains($body, 'partial image') && !str_contains($body, 'fixture output failure'),
                $name . ' returns JSON without partial image output or exception details');
        }
    }
    file_put_contents($output . '/manifest.json', json_encode(['checks' => $checks, 'php' => PHP_VERSION,
        'images' => [['file' => 'valid.png', 'text' => $url], ['file' => 'user-valid.png', 'text' => 'weixin://fixture']]], JSON_THROW_ON_ERROR));
    echo "OK {$checks} Qrcode HTTP checks on PHP " . PHP_VERSION . "\n";
} finally {
    proc_terminate($process);
    proc_close($process);
    if (!$keepOutput) {
        foreach (glob($output . '/*') as $file) { unlink($file); }
        rmdir($output);
    }
}
