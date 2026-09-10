<?php
/** Deterministic cURL transport contract tests plus an actual loopback denial probe. */
namespace app\common\util {
    final class AuditCurl
    {
        public array $options = [];
        public array $reply;
        public function __construct(public string $url) { $this->reply = array_shift($GLOBALS['http_replies']) ?? []; }
    }
    function dns_get_record($host, $type) {
        $GLOBALS['http_dns_calls'][$host] = ($GLOBALS['http_dns_calls'][$host] ?? 0) + 1;
        if (!empty($GLOBALS['http_dns_delay'])) { $GLOBALS['http_clock'] += $GLOBALS['http_dns_delay']; }
        return match ($host) {
            'public.example', 'rebind.example' => [['ip' => '8.8.8.8']],
            'other.example' => [['ip' => '1.1.1.1']],
            'mixed.example' => [['ip' => '8.8.8.8'], ['ip' => '127.0.0.1']],
            default => [],
        };
    }
    function gethostbynamel($host) { return false; }
    function microtime($float = false) { return $GLOBALS['http_clock'] ?? \microtime($float); }
    function curl_init($url) {
        if (!empty($GLOBALS['http_real_curl'])) { return \curl_init($url); }
        $ch = new AuditCurl($url);
        $GLOBALS['http_requests'][] = $ch;
        return $ch;
    }
    function curl_setopt_array($ch, $options) {
        if ($ch instanceof \CurlHandle) { return \curl_setopt_array($ch, $options); }
        $ch->options = $options;
        return true;
    }
    function curl_exec($ch) {
        if ($ch instanceof \CurlHandle) { return \curl_exec($ch); }
        if (!empty($ch->reply['error'])) { return false; }
        $lines = ['HTTP/1.1 ' . ($ch->reply['status'] ?? 200) . " response\r\n"];
        if (isset($ch->reply['location'])) { $lines[] = 'Location: ' . $ch->reply['location'] . "\r\n"; }
        if (isset($ch->reply['huge_header'])) { $lines[] = 'X-Huge: ' . str_repeat('x', 65536) . "\r\n"; }
        foreach ($lines as $line) {
            if (($ch->options[CURLOPT_HEADERFUNCTION])($ch, $line) !== strlen($line)) { return false; }
        }
        $body = $ch->reply['body'] ?? 'OK';
        return ($ch->options[CURLOPT_WRITEFUNCTION])($ch, $body) === strlen($body);
    }
    function curl_getinfo($ch, $option) {
        if ($ch instanceof \CurlHandle) { return \curl_getinfo($ch, $option); }
        if ($option === CURLINFO_RESPONSE_CODE) { return $ch->reply['status'] ?? 200; }
        if ($option === CURLINFO_PRIMARY_IP) { return $ch->reply['peer'] ?? '8.8.8.8'; }
        return null;
    }
    function curl_close($ch) { if ($ch instanceof \CurlHandle) { \curl_close($ch); } }
}
namespace {
    use app\common\util\PublicHttpClient;
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        if (!(error_reporting() & $severity)) { return false; }
        throw new \ErrorException($message, 0, $severity, $file, $line);
    });
    require dirname(__DIR__) . '/application/common/util/PublicHttpClient.php';
    require dirname(__DIR__) . '/application/common.php';
    $checks = 0;
    function check($ok, $message): void {
        $GLOBALS['checks']++;
        if (!$ok) { throw new \RuntimeException($message); }
    }
    function resetHttp(array $replies = []): void {
        $GLOBALS['http_replies'] = $replies;
        $GLOBALS['http_requests'] = [];
        $GLOBALS['http_dns_calls'] = [];
        $GLOBALS['http_dns_delay'] = 0;
        unset($GLOBALS['http_clock']);
    }
    foreach (['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '192.0.0.1', '198.18.0.1',
        '224.0.0.1', '::1', '::ffff:127.0.0.1', '::ffff:8.8.8.8', '2002:7f00:1::', 'fe80::1'] as $ip) {
        check(!mac_ip_is_public($ip), 'Non-public HTTP address allowed: ' . $ip);
    }
    foreach (['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'] as $ip) {
        check(mac_ip_is_public($ip), 'Valid public IP blocked');
    }
    resetHttp();
    foreach (['file:///etc/passwd', 'http://127.0.0.1/', 'http://2130706433/', 'http://0177.0.0.1/',
        'https://user:pass@public.example/', 'https://mixed.example/', 'https://public.example\\@127.0.0.1/',
        "https://public.example/\r\nHost: x", 'https://update.maccms.la./payload', []] as $url) {
        check(PublicHttpClient::request($url) === false, 'Unsafe URL reached transport');
    }
    check($GLOBALS['http_requests'] === [], 'Blocked URL opened a connection');
    check(mac_curl_get([]) === false, 'Array URL did not fail cleanly');
    check(mac_curl_post('https://public.example/', ['nested' => ['bad']]) === false, 'Nested multipart data did not fail cleanly');
    check(mac_curl_get('https://public.example/', ["X-Test: a\r\nHost: internal"]) === false, 'Header injection accepted');
    check($GLOBALS['http_requests'] === [], 'Malformed input opened a connection');

    resetHttp([['body' => 'accepted']]);
    check(mac_curl_get('https://rebind.example/resource') === 'accepted', 'Public GET failed');
    $opts = $GLOBALS['http_requests'][0]->options;
    check($opts[CURLOPT_RESOLVE] === ['rebind.example:443:8.8.8.8'], 'Validated DNS was not pinned into cURL');
    check($GLOBALS['http_dns_calls']['rebind.example'] === 1, 'Transport performed a separate uncontrolled DNS resolution');
    check($opts[CURLOPT_SSL_VERIFYPEER] === true && $opts[CURLOPT_SSL_VERIFYHOST] === 2, 'TLS verification disabled');
    check($opts[CURLOPT_PROXY] === '' && $opts[CURLOPT_FOLLOWLOCATION] === false, 'Proxy or automatic redirects bypass pinning');

    resetHttp([['status' => 302, 'location' => 'http://127.0.0.1/private']]);
    check(mac_curl_get('http://public.example/start') === false && count($GLOBALS['http_requests']) === 1, 'Redirect accessed loopback');
    resetHttp([['status' => 302, 'location' => 'https://update.maccms.la./payload']]);
    check(mac_curl_get('https://public.example/start') === false && count($GLOBALS['http_requests']) === 1, 'Redirect bypassed blocked upstream host');
    resetHttp([['status' => 302, 'location' => 'http://public.example/plain']]);
    check(mac_curl_get('https://public.example/start') === false, 'HTTPS downgrade allowed');

    resetHttp([['status' => 302, 'location' => 'https://other.example/final'], ['peer' => '1.1.1.1', 'body' => 'redirected']]);
    check(mac_curl_post('https://public.example/start', 'secret-body', ['Authorization: secret', 'X-API-Key: secret', 'Accept: application/json'], 'session=secret') === 'redirected', 'Safe redirect failed');
    $opts = $GLOBALS['http_requests'][1]->options;
    check($opts[CURLOPT_HTTPHEADER] === ['Accept: application/json'] && $opts[CURLOPT_COOKIE] === '', 'Cross-origin redirect leaked headers/cookie');
    check(isset($opts[CURLOPT_HTTPGET]) && !isset($opts[CURLOPT_POSTFIELDS]), '302 redirect retained POST data');

    resetHttp([['status' => 307, 'location' => 'https://other.example/final']]);
    check(mac_curl_post('https://public.example/start', 'secret') === false && count($GLOBALS['http_requests']) === 1, '307 forwarded a secret body to another origin');
    resetHttp([['status' => 307, 'location' => '../next?x=1'], ['body' => 'same-origin']]);
    check(mac_curl_post('https://public.example/a/start', 'retained') === 'same-origin', 'Same-origin 307 failed');
    check($GLOBALS['http_requests'][1]->url === 'https://public.example/next?x=1'
        && $GLOBALS['http_requests'][1]->options[CURLOPT_POSTFIELDS] === 'retained', 'Relative redirect or 307 semantics changed');

    resetHttp([['body' => str_repeat('x', 10)]]);
    check(PublicHttpClient::request('https://public.example/', maxBytes: 5) === false, 'Response byte limit ignored');
    resetHttp([['huge_header' => true]]);
    check(PublicHttpClient::request('https://public.example/') === false, 'Header byte limit ignored');
    resetHttp([['peer' => '127.0.0.1']]);
    check(PublicHttpClient::request('https://public.example/') === false, 'Unexpected connected peer accepted');
    resetHttp([['error' => true]]);
    check(PublicHttpClient::request('https://public.example/') === false, 'Transport failure reported as success');
    resetHttp(array_fill(0, 7, ['status' => 302, 'location' => '/again']));
    check(PublicHttpClient::request('https://public.example/') === false && count($GLOBALS['http_requests']) === 6, 'Redirect count unbounded');
    resetHttp(); $GLOBALS['http_clock'] = 1000; $GLOBALS['http_dns_delay'] = 2;
    check(PublicHttpClient::request('https://public.example/', timeout: 1) === false && $GLOBALS['http_requests'] === [], 'DNS time did not consume the request deadline');

    resetHttp(); $GLOBALS['http_real_curl'] = true;
    $listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    if ($listener === false) { throw new \RuntimeException('Could not create loopback fixture'); }
    try {
        $address = stream_socket_get_name($listener, false);
        check(mac_curl_get('http://' . $address . '/sensitive') === false, 'Actual loopback target accepted');
        $connection = @stream_socket_accept($listener, 0);
        check($connection === false, 'Loopback received an unexpected connection');
        if (is_resource($connection)) { fclose($connection); }
    } finally { fclose($listener); }
    echo 'Public HTTP regressions: ' . $checks . " assertions passed\n";
}
