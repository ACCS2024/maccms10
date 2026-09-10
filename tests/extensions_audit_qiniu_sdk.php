<?php
/** Qiniu TLS and response parsing contract; curl is isolated with namespace stubs. */
namespace Qiniu\Http {
    function curl_init() { return new \stdClass(); }
    function curl_setopt($handle, $option, $value) { return true; }
    function curl_setopt_array($handle, $options) { $GLOBALS['qiniuOptions'] = $options; return true; }
    function curl_exec($handle) { return "HTTP/1.1 200 OK\r\nLocation: https://example.invalid:8443/a\r\n\r\n{}"; }
    function curl_errno($handle) { return 0; }
    function curl_getinfo($handle, $key) { return $key === CURLINFO_HTTP_CODE ? 200 : strlen("HTTP/1.1 200 OK\r\nLocation: https://example.invalid:8443/a\r\n\r\n"); }
    function curl_close($handle) {}
}
namespace {
    $root = dirname(__DIR__);
    require $root . '/extend/qiniu/autoload.php';
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
    $response = \Qiniu\Http\Client::get('https://storage.invalid');
    $check($GLOBALS['qiniuOptions'][CURLOPT_SSL_VERIFYPEER] === true && $GLOBALS['qiniuOptions'][CURLOPT_SSL_VERIFYHOST] === 2, 'Qiniu TLS validation');
    $check($response->headers['Location'] === 'https://example.invalid:8443/a', 'Header values retain colons');
    $check((new \Qiniu\Config())->useHTTPS === true, 'Qiniu defaults to HTTPS');
    echo "OK {$checks} Qiniu SDK checks on PHP " . PHP_VERSION . "\n";
}
