<?php
/** Real Qiniu response/multipart path, with only the cURL transport isolated. */
namespace Qiniu\Http {
    function curl_init() { return new \stdClass(); }
    function curl_setopt($handle, $option, $value) { return true; }
    function curl_setopt_array($handle, $options) { $GLOBALS['response_options'] = $options; return true; }
    function curl_exec($handle) {
        ++$GLOBALS['response_requests'];
        return $GLOBALS['response_fixture']['raw'];
    }
    function curl_errno($handle) { return $GLOBALS['response_fixture']['errno'] ?? 0; }
    function curl_error($handle) { return 'isolated transport error'; }
    function curl_getinfo($handle, $key) {
        return $key === CURLINFO_HTTP_CODE ? $GLOBALS['response_fixture']['code'] : $GLOBALS['response_fixture']['header_size'];
    }
    function curl_close($handle) {}
}
namespace {
    require dirname(__DIR__) . '/extend/qiniu/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (error_reporting() & $level) { throw new \ErrorException($message, 0, $level, $file, $line); }
        return false;
    });
    $checks = 0;
    $GLOBALS['response_requests'] = 0;
    function verify($condition, string $message): void {
        global $checks;
        if (!$condition) { throw new \RuntimeException($message); }
        ++$checks;
    }
    function fixture(int $code, string $headers, string $body, string $previous = ''): void {
        $head = $previous . 'HTTP/1.1 ' . $code . " Fixture\r\n" . $headers . "\r\n";
        $GLOBALS['response_fixture'] = ['code' => $code, 'header_size' => strlen($head), 'raw' => $head . $body];
    }
    if (($argv[1] ?? '') === 'baseline') {
        foreach ([
            static fn() => new \Qiniu\Http\Response(612, 0),
            static fn() => new \Qiniu\Http\Response(400, 0, ['Content-Type' => 'application/json'], '{}'),
            static fn() => new \Qiniu\Http\Response(400, 0, ['Content-Type' => 'application/json'], '["failure"]'),
            static fn() => new \Qiniu\Http\Response(400, 0, ['Content-Type' => 'application/json'], '"failure"'),
            static fn() => (new \Qiniu\Http\Response(200, 0))->xVia(),
            static fn() => (new \Qiniu\Http\Response(200, 0))->xLog(),
            static fn() => (new \Qiniu\Http\Response(200, 0))->xReqId(),
        ] as $broken) {
            $thrown = false;
            try { $broken(); } catch (\Throwable $e) { $thrown = true; }
            verify($thrown, 'Original parser must reproduce a strict-error failure');
        }
        verify((new \Qiniu\Http\Response(200, 0, ['content-type' => 'application/json'], '{"key":"fixture"}'))->json() === null,
            'Original lowercase header loses successful JSON');
        verify((new \Qiniu\Http\Response(503, 0))->needRetry() !== true, 'Original 503 retry classification fails');
        fixture(200, '', '{}', "HTTP/1.1 100 Continue\r\nContent-Type: application/json\r\nX-Reqid: previous\r\n\r\n");
        $response = \Qiniu\Http\Client::get('https://upload.invalid');
        verify($response->json() === [] && $response->xReqId() === 'previous', 'Original parser leaks previous HTTP block headers');
        echo "OK {$checks} original Qiniu response reproductions on PHP " . PHP_VERSION . "\n";
        exit;
    }

    foreach ([null, ''] as $body) {
        $response = new \Qiniu\Http\Response(612, 0, [], $body);
        verify(!$response->ok() && is_string($response->error) && $response->error !== '', 'Unknown empty HTTP failure needs a useful message');
    }
    verify((new \Qiniu\Http\Response(503, 0))->error === 'Service Unavailable', 'Known status text remains stable');
    foreach (['{}', '[]', '["failure"]', '"failure"', '0', 'false', 'null', '{"error":null}', '{"error":[]}', '{"error":{"detail":"x"}}', '{"error":0}', '{"error":false}', '{"error":""}'] as $body) {
        $response = new \Qiniu\Http\Response(400, 0, ['Content-Type' => 'application/json'], $body);
        verify(!$response->ok() && is_string($response->error) && $response->error === $body, 'Unexpected error schema must remain a controlled HTTP failure: ' . $body);
    }
    $response = new \Qiniu\Http\Response(400, 0, ['Content-Type' => 'application/json'], '{"error":"fixture denial","request":"x"}');
    verify($response->error === 'fixture denial' && $response->json()['request'] === 'x', 'String API error and decoded payload remain available');
    foreach (['Content-Type', 'content-type', 'CONTENT-TYPE', 'CoNtEnT-TyPe'] as $name) {
        foreach (['application/json', 'Application/JSON; charset=utf-8', ' application/json ; charset=UTF-8 '] as $type) {
            $response = new \Qiniu\Http\Response(200, 0, [$name => $type], '{"key":"fixture"}');
            verify($response->ok() && $response->json() === ['key' => 'fixture'], 'JSON media type/field names are case-insensitive');
            verify($response->headers[$name] === $type, 'Public headers retain their original spelling/value');
        }
    }
    foreach (['application/jsonp', 'text/plain', 'application/json-unknown'] as $type) {
        verify((new \Qiniu\Http\Response(200, 0, ['Content-Type' => $type], '{}'))->json() === null, 'Unrelated media types are not JSON');
    }
    $response = new \Qiniu\Http\Response(200, 0);
    verify($response->xVia() === null && $response->xLog() === null && $response->xReqId() === null, 'Absent diagnostic headers return null');
    foreach ([['fw-via' => 'firewall'], ['X-pX' => 'proxy', 'FW-VIA' => 'firewall'], ['x-VIA' => 'edge', 'x-px' => 'proxy']] as $headers) {
        $response = new \Qiniu\Http\Response(200, 0, $headers + ['x-log' => 'log', 'X-REQID' => 'request']);
        verify($response->xVia() === reset($headers) && $response->xLog() === 'log' && $response->xReqId() === 'request', 'Diagnostic header lookup and via precedence');
    }
    foreach ([200 => false, 204 => false, 400 => false, 429 => false, 499 => false, 500 => true, 501 => true, 503 => true, 579 => false, 599 => true, 600 => false, 996 => true, -1 => true] as $code => $retry) {
        verify((new \Qiniu\Http\Response($code, 0))->needRetry() === $retry, 'Retry result must be a boolean with legacy 579/996 exceptions: ' . $code);
    }
    foreach (['', '{invalid', "{\"error\":\"\xff\"}"] as $body) {
        $response = new \Qiniu\Http\Response(200, 0, ['content-type' => 'application/json'], $body);
        verify(!$response->ok() && is_string($response->error), 'Invalid advertised JSON cannot be successful');
    }
    foreach (['0' => 0, 'false' => false, 'null' => null, '[]' => [], '"text"' => 'text'] as $body => $expected) {
        $response = new \Qiniu\Http\Response(200, 0, ['Content-Type' => 'application/json'], (string)$body);
        verify($response->ok() && $response->json() === $expected, 'Valid JSON values retain their decoded value');
    }
    verify((new \Qiniu\Http\Response(204, 0))->ok(), 'Bodyless successful response remains valid');
    $response = new \Qiniu\Http\Response(-1, 0, [], null, 'transport fixture');
    verify(!$response->ok() && $response->error === 'transport fixture', 'Transport errors bypass body parsing');

    foreach (["HTTP/1.1 100 Continue", "HTTP/1.1 200 Connection established", "HTTP/2 302"] as $statusLine) {
        fixture(200, "content-type: application/json\r\nx-reqid: final\r\nLocation: https://fixture.invalid:8443/a\r\n", '{"key":"fixture"}',
            $statusLine . "\r\nContent-Type: text/plain\r\nX-Reqid: previous\r\nX-Log: stale\r\n\r\n");
        $response = \Qiniu\Http\Client::get('https://upload.invalid');
        verify($response->ok() && $response->json() === ['key' => 'fixture'], 'Final HTTP block controls JSON parsing');
        verify($response->xReqId() === 'final' && $response->xLog() === null && !isset($response->headers['Content-Type']), 'Previous HTTP block headers cannot leak');
        verify($response->headers['Location'] === 'https://fixture.invalid:8443/a', 'Header values retain embedded colons');
    }
    fixture(200, '', '{}', "HTTP/1.1 100 Continue\r\nContent-Type: application/json\r\n\r\n");
    verify(\Qiniu\Http\Client::get('https://upload.invalid')->json() === null, 'Previous block cannot supply a missing final content type');
    fixture(200, "content-type: text/plain\r\nContent-Type: text/html\r\ncontent-type: application/json\r\n", '{"key":"fixture"}');
    $response = \Qiniu\Http\Client::get('https://upload.invalid');
    verify($response->json() === ['key' => 'fixture'] && $response->headers === ['content-type' => 'application/json'],
        'Repeated field names retain only their final value regardless of casing');

    $zone = new \Qiniu\Zone(['upload.invalid'], ['upload.invalid'], 'io.invalid', 'rs.invalid', 'rsf.invalid', 'api.invalid');
    $manager = new \Qiniu\Storage\UploadManager(new \Qiniu\Config($zone));
    $token = 'fixture-access:fixture-signature:' . \Qiniu\base64_urlSafeEncode(json_encode(['scope' => 'fixture-bucket']));
    fixture(200, "content-type: APPLICATION/JSON; charset=utf-8\r\nx-reqid: upload-request\r\n", '{"key":"fixture-key","hash":"fixture-hash"}');
    [$result, $error] = $manager->put($token, 'fixture-key', 'fixture body', null, 'text/plain', 'fixture.txt');
    verify($error === null && $result === ['key' => 'fixture-key', 'hash' => 'fixture-hash'], 'Actual UploadManager/FormUploader accepts lowercase JSON response');
    $options = $GLOBALS['response_options'];
    verify($options[CURLOPT_SSL_VERIFYPEER] === true && $options[CURLOPT_SSL_VERIFYHOST] === 2, 'TLS peer/hostname verification stays enabled');
    verify($options[CURLOPT_URL] === 'https://upload.invalid' && $options[CURLOPT_CUSTOMREQUEST] === 'POST', 'Configured HTTPS multipart endpoint is retained');
    verify(str_contains($options[CURLOPT_POSTFIELDS], 'filename="fixture.txt"') && str_contains($options[CURLOPT_POSTFIELDS], 'fixture body'), 'Actual multipart payload is preserved');
    foreach ([[503, '{}'], [612, ''], [400, '"failure"'], [200, '{invalid']] as [$code, $body]) {
        fixture($code, "content-type: application/json\r\n", $body);
        $before = $GLOBALS['response_requests'];
        [$result, $error] = $manager->put($token, 'fixture-key', 'fixture body');
        verify($result === null && $error instanceof \Qiniu\Http\Error, 'Malformed/HTTP failure returns the SDK Error contract');
        verify($GLOBALS['response_requests'] === $before + 1, 'Response parsing must not add multipart retries');
    }
    $GLOBALS['response_fixture'] = ['raw' => false, 'errno' => 60];
    $response = \Qiniu\Http\Client::get('https://upload.invalid');
    verify(!$response->ok() && $response->statusCode === -1 && $response->error === 'isolated transport error', 'cURL TLS failure stays an SDK transport failure');
    echo "OK {$checks} Qiniu response checks on PHP " . PHP_VERSION . "\n";
}
