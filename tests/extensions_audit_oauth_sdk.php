<?php
/** OAuth SDK state and TLS contract; no network or application initialization. */
namespace login {
    function config($key) { return ['qq' => ['key' => 'audit', 'secret' => 'audit'], 'weixin' => ['key' => 'audit', 'secret' => 'audit']]; }
    function curl_init() { return new \stdClass(); }
    function curl_setopt_array($handle, $options) { $GLOBALS['oauthOptions'] = $options; return true; }
    function curl_exec($handle) { return 'audit-response'; }
    function curl_error($handle) { return ''; }
    function curl_close($handle) {}
}
namespace {
    $root = dirname(__DIR__);
    require_once $root . '/extend/login/ThinkOauth.php';
    require_once $root . '/extend/login/sdk/QqSDK.php';
    require_once $root . '/extend/login/sdk/WeixinSDK.php';
    define('THIRD_LOGIN_CALLBACK', 'https://site.invalid/callback/');
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
    foreach ([new \login\sdk\QqSDK(), new \login\sdk\WeixinSDK()] as $sdk) {
        parse_str(parse_url($sdk->getRequestCodeURL('one-time-state'), PHP_URL_QUERY), $query);
        $check(($query['state'] ?? '') === 'one-time-state', 'OAuth state must reach provider');
        $http = new \ReflectionMethod($sdk, 'http');
        $http->invoke($sdk, 'https://provider.invalid', [], 'POST');
        $check($GLOBALS['oauthOptions'][CURLOPT_SSL_VERIFYPEER] === true && $GLOBALS['oauthOptions'][CURLOPT_SSL_VERIFYHOST] === 2, 'OAuth TLS validation');
    }
    echo "OK {$checks} OAuth SDK checks on PHP " . PHP_VERSION . "\n";
}
