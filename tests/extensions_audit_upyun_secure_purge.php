<?php
/** Real legacy purge signing/return contract; the Guzzle transport is a local response stub. */
namespace GuzzleHttp {
    class Client {
        public function __construct(array $options = []) {
            ++$GLOBALS['purge_clients'];
            $GLOBALS['purge_options'] = $options;
        }
        public function request($method, $url, array $options = []) {
            ++$GLOBALS['purge_requests'];
            $GLOBALS['purge_request'] = [$method, $url, $options];
            return new \GuzzleHttp\Psr7\Response(200, ['Content-Type' => 'application/json'],
                '{"invalid_domain_of_url":["https://foreign.invalid/fixture"]}');
        }
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    require dirname(__DIR__) . '/extend/upyun/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (error_reporting() & $level) { throw new \ErrorException($message, 0, $level, $file, $line); }
        return false;
    });
    $checks = 0;
    $GLOBALS['purge_clients'] = $GLOBALS['purge_requests'] = 0;
    function verify($ok, string $message): void {
        global $checks;
        if (!$ok) { throw new \RuntimeException($message); }
        ++$checks;
    }
    $config = new \Upyun\Config('fixture-bucket', 'fixture-operator', 'fixture-password');
    $client = new \Upyun\Upyun($config);
    if (($argv[1] ?? '') === 'baseline') {
        $client->purge('https://cdn.invalid/fixture');
        verify($config->useSsl === true && $GLOBALS['purge_requests'] === 1 && str_starts_with($GLOBALS['purge_request'][1], 'http://'),
            'Original default HTTPS configuration silently sends the purge signature over HTTP');
        echo "OK {$checks} original secure purge reproduction on PHP " . PHP_VERSION . "\n";
        exit;
    }
    foreach ([true, null, 0, ''] as $setting) {
        $config->useSsl = $setting;
        $thrown = false;
        try { $client->purge('https://cdn.invalid/fixture'); }
        catch (\RuntimeException $e) { $thrown = $e->getMessage() === 'Secure purge endpoint is not supported by this SDK'; }
        verify($thrown && $GLOBALS['purge_clients'] === 0 && $GLOBALS['purge_requests'] === 0, 'Secure purge fails before constructing transport or signing/sending a request');
    }
    $config->useSsl = false;
    $result = $client->purge(['https://cdn.invalid/one', 'https://cdn.invalid/two']);
    verify($result === ['https://foreign.invalid/fixture'], 'Explicit legacy mode preserves the original invalid URL result');
    [$method, $url, $request] = $GLOBALS['purge_request'];
    verify($GLOBALS['purge_requests'] === 1 && $method === 'POST' && $url === 'http://purge.upyun.com/purge/', 'Only explicit false retains the documented legacy HTTP endpoint');
    verify($request['form_params']['purge'] === "https://cdn.invalid/one\nhttps://cdn.invalid/two" && isset($request['headers']['Authorization'], $request['headers']['Date']), 'Legacy body joining and signature header contract stay intact');
    verify($GLOBALS['purge_options']['allow_redirects'] === false, 'Explicit legacy mode still cannot follow redirects');
    echo "OK {$checks} secure purge checks on PHP " . PHP_VERSION . "\n";
}
