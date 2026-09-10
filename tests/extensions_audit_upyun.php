<?php
/** Real Upyun/Guzzle loopback contracts. Pass embedded-first to reverse autoload order. */
namespace {
    $root = dirname(__DIR__);
    if (($argv[1] ?? '') === 'embedded-first') {
        require $root . '/extend/upyun/vendor/autoload.php';
        interface_exists(\Psr\Http\Message\ResponseInterface::class);
        class_exists(\GuzzleHttp\Client::class);
        require $root . '/vendor/autoload.php';
    } else {
        require $root . '/vendor/autoload.php';
        interface_exists(\Psr\Http\Message\ResponseInterface::class);
        class_exists(\GuzzleHttp\Client::class);
        require $root . '/extend/upyun/vendor/autoload.php';
    }
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });
    error_reporting(E_ALL);
    $checks = 0;
    $check = static function ($condition, $message) use (&$checks) {
        if (!$condition) { throw new \RuntimeException($message); }
        $checks++;
    };
    $check(\Upyun\Util::trim([' a ', [' b ']]) === ['a', ['b']], 'Namespaced recursive callback');

    $tmp = sys_get_temp_dir() . '/maccms-transport-' . bin2hex(random_bytes(5));
    mkdir($tmp, 0700);
    $router = <<<'PHP'
<?php
$stage = $_SERVER['HTTP_X_UPYUN_MULTI_STAGE'] ?? '';
if ($stage === 'initiate') { http_response_code(204); header('X-Upyun-Multi-Uuid: test-id'); }
elseif ($stage === 'upload') { http_response_code(204); header('X-Upyun-Next-Part-Id: -1'); }
elseif ($stage === 'complete') { http_response_code(201); }
elseif ($_SERVER['REQUEST_METHOD'] === 'GET') { echo 'download-body'; }
else { header('X-Upyun-Width: 10'); echo '{}'; }
PHP;
    file_put_contents($tmp . '/router.php', $router);
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $pipes = [];
    $process = proc_open([PHP_BINARY, '-S', $address, $tmp . '/router.php'], [0 => ['pipe', 'r'], 1 => ['file', $tmp . '/server.log', 'a'], 2 => ['file', $tmp . '/server.log', 'a']], $pipes, $tmp);
    fclose($pipes[0]);
    try {
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $ready = @stream_socket_client('tcp://' . $address, $errno, $error, .05);
            if ($ready !== false) { fclose($ready); break; }
            usleep(20000);
        }
        $check($ready !== false, 'Isolated loopback fixture starts');
        $config = new \Upyun\Config('audit-bucket', 'audit-operator', 'audit-password');
        $check($config->getProtocol() === 'https://', 'Upyun defaults to HTTPS');
        $config->useSsl = false; // Only the isolated loopback fixture uses HTTP.
        \Upyun\Config::$restApiEndPoint = $address;
        $client = new \Upyun\Upyun($config);
        $check($client->write('/test.txt', 'upload-body')['x-upyun-width'] === '10', 'REST upload response contract');
        $check($client->read('/test.txt') === 'download-body', 'Download string contract');
        $stream = fopen('php://temp', 'w+');
        $check($client->read('/test.txt', $stream) === true, 'Download resource contract');
        rewind($stream);
        $check(stream_get_contents($stream) === 'download-body', 'Downloaded bytes preserved');
        fclose($stream);
        $config->uploadType = 'BLOCK';
        $check(is_array($client->write('/block.txt', 'block-body')), 'Block upload contract');
        $check($client->write('/form.txt', 'form-body', [], true) === true, 'Multipart upload contract');

        $guzzle = new \GuzzleHttp\Client();
        $requests = [
            $guzzle->getAsync('http://' . $address . '/one'),
            $guzzle->getAsync('http://' . $address . '/two'),
        ];
        $responses = \GuzzleHttp\Promise\Utils::all($requests)->wait();
        $check(count($responses) === 2 && (string) $responses[0]->getBody() === 'download-body' && (string) $responses[1]->getBody() === 'download-body', 'Concurrent CurlHandle requests remain distinct');
        try {
            new \GuzzleHttp\Psr7\Request('GET', 'https://example.invalid', ['X-Test' => "ok\nInjected: value"]);
            throw new \RuntimeException('CRLF header unexpectedly accepted');
        } catch (\InvalidArgumentException $expected) { $checks++; }
        echo "OK {$checks} Upyun dependency checks on PHP " . PHP_VERSION . "\n";
    } finally {
        proc_terminate($process);
        proc_close($process);
        foreach (glob($tmp . '/*') as $file) { unlink($file); }
        rmdir($tmp);
    }
}
