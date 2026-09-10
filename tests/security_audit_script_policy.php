<?php
/** Every rendered entrance retains an enforced script boundary even with optional CSP disabled. */
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/application/common.php';
require dirname(__DIR__) . '/application/middleware/SecurityHeaders.php';
error_reporting(E_ALL);
define('ENTRANCE', 'install');
class ScriptPolicyResponse
{
    public array $headers = [];
    public function header(array $values) { $this->headers = array_replace($this->headers, $values); return $this; }
    public function getHeader($name) { return $this->headers[$name] ?? ''; }
}
$request = new stdClass();
$middleware = new app\middleware\SecurityHeaders();
foreach (['0', '', '1', '2'] as $mode) {
    $GLOBALS['config'] = ['app' => ['security_csp' => $mode]];
    $response = $middleware->handle($request, static fn () => new ScriptPolicyResponse());
    $policy = $response->getHeader('Content-Security-Policy');
    check(str_starts_with($policy, "script-src 'self' 'unsafe-inline' 'unsafe-eval';"), 'Installation/legacy setting disabled local script enforcement');
    check(str_contains($policy, "object-src 'none';") && str_contains($policy, "worker-src 'self' blob:;"), 'Mandatory plugin/worker boundary absent');
    check(($mode === '2') === ($response->getHeader('Content-Security-Policy-Report-Only') !== ''), 'Optional reporting changed enforcement');
}
$policy = app\middleware\SecurityHeaders::scriptCspPolicy(['security_script_sources' => [
    'https://assets.example.invalid/', 'https://Assets.Example.Invalid', 'https://assets.example.invalid:8443',
    'https://update.maccms.la.', 'https://CDN.BOOTCDN.NET', 'https://bucket.service.generate.110.nz',
    'https://*.example.invalid', 'http://external.invalid', "https://assets.invalid; script-src *", 'https://user@assets.invalid',
    "https://assets.invalid\r\nX-Evil: true", 'https://assets.invalid/path', 'https://assets.invalid?foo', [],
]]);
check(str_contains($policy, 'https://assets.example.invalid ') && str_contains($policy, 'https://assets.example.invalid:8443'), 'Approved origins were not normalized/preserved');
foreach (['maccms', 'bootcdn', '110.nz', '*', 'external.invalid', 'assets.invalid', 'X-Evil', 'user@'] as $denied) {
    check(!str_contains($policy, $denied), 'Invalid or compromised script source accepted: ' . $denied);
}
$GLOBALS['config'] = ['app' => ['security_csp' => '1', 'security_csp_policy' => "script-src * 'unsafe-inline';"]];
$response = $middleware->handle($request, static fn () => new ScriptPolicyResponse());
check(str_contains($response->getHeader('Content-Security-Policy'), ", script-src * 'unsafe-inline';"), 'Additional policy must intersect with the mandatory first policy');
$default = app\middleware\SecurityHeaders::defaultCspPolicy();
check(str_contains($default, "; base-uri 'self'; object-src 'none'; script-src "), 'CSP directives lost semicolon separators');
foreach (['https://SERVICE.CLIENT.110.NZ./', 'https://js.mirrors163.com/', 'https://polyfill-js.cn/', 'https://cdn.staticfile.net/'] as $url) {
    check(mac_is_official_url($url), 'Known supply-chain host bypassed normalization');
}
check(!mac_is_official_url('https://api.github.com/') && !mac_is_official_url('https://movie.douban.com/'), 'Unrelated official providers were denied');

// Verify actual outgoing headers, including an exit that never returns to the middleware.
// The PHP built-in server listens on loopback only and reads an isolated fixture; no DB/app bootstrap.
$listener = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if ($listener === false) { throw new RuntimeException('Cannot allocate the loopback CSP fixture'); }
$address = stream_socket_get_name($listener, false);
fclose($listener);
$serverLog = tempnam(sys_get_temp_dir(), 'maccms-csp-http-');
if ($serverLog === false) { throw new RuntimeException('Cannot allocate the CSP fixture log'); }
$server = null;
try {
    $server = proc_open([PHP_BINARY, '-d', 'output_buffering=0', '-d', 'display_errors=1', '-S', $address,
        __DIR__ . '/fixtures/security_audit_script_stream.php'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', $serverLog, 'a'], 2 => ['file', $serverLog, 'a']], $pipes, dirname(__DIR__));
    if (!is_resource($server)) { throw new RuntimeException('Cannot start the CSP HTTP fixture'); }
    foreach (['/stream', '/exit'] as $route) {
        $socket = false;
        $deadline = microtime(true) + 5;
        do {
            $socket = @stream_socket_client('tcp://' . $address, $errno, $error, 0.2);
            if (is_resource($socket)) { break; }
            usleep(25000);
        } while (microtime(true) < $deadline);
        if (!is_resource($socket)) { throw new RuntimeException('CSP fixture did not become ready: ' . file_get_contents($serverLog)); }
        stream_set_timeout($socket, 3);
        fwrite($socket, 'GET ' . $route . " HTTP/1.1\r\nHost: " . $address . "\r\nConnection: close\r\n\r\n");
        $raw = stream_get_contents($socket);
        $timedOut = stream_get_meta_data($socket)['timed_out'];
        fclose($socket);
        check(!$timedOut && is_string($raw), 'Streaming CSP response timed out');
        [$headers, $body] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
        check(str_contains($headers, ' 200 ') && $body === 'STREAMED-POLICY-FIXTURE', 'Streaming fixture did not execute its controller');
        check((bool)preg_match('/^Content-Security-Policy: (.+)$/mi', $headers, $matches), 'Flushed/exited response lost its enforced CSP header');
        $streamPolicy = trim($matches[1] ?? '');
        check(str_starts_with($streamPolicy, "script-src 'self' 'unsafe-inline' 'unsafe-eval'")
            && str_contains($streamPolicy, 'https://assets.example.invalid;')
            && str_contains($streamPolicy, "object-src 'none';"), 'Streaming policy did not use the early configuration and mandatory boundary');
    }
} finally {
    if (is_resource($server)) { proc_terminate($server); proc_close($server); }
    @unlink($serverLog);
}
echo "Script source policy: {$checks} assertions passed on PHP " . PHP_VERSION . "\n";
