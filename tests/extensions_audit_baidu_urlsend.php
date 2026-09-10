<?php
/** Real cURL/HTTP/TLS against fixture Unix sockets; run with run_baidu_urlsend_audit.py. */
declare(strict_types=1);
namespace app\common\extend\urlsend {
    function curl_setopt_array($handle, $options) {
        if (getenv('BAIDU_AUDIT_SOCKET_FIXTURE') !== '1') { throw new \RuntimeException('Missing isolated TLS fixture'); }
        $GLOBALS['baidu_audit_options'][] = $options;
        $GLOBALS['baidu_audit_apis'][] = \curl_getinfo($handle, CURLINFO_EFFECTIVE_URL);
        // The production URL, host checks, protocol allowlist, redirects and request remain untouched.
        // Only connect to a disposable Unix socket and trust its test-only CA.
        $mode = $GLOBALS['baidu_audit_tls'] ?? 'valid';
        $options[CURLOPT_UNIX_SOCKET_PATH] = '/audit/' . ($mode === 'wrong-host' ? 'wrong-host' : 'valid') . '.sock';
        if ($mode !== 'untrusted') { $options[CURLOPT_CAINFO] = '/audit/ca.pem'; }
        if ($mode === 'timeout') { $options[CURLOPT_TIMEOUT_MS] = 100; }
        return \curl_setopt_array($handle, $options);
    }
}
namespace {
    use app\common\extend\urlsend\Baidu;
    use app\common\extend\urlsend\Baidufast;
    if (getenv('BAIDU_AUDIT_SOCKET_FIXTURE') !== '1' || !file_exists('/audit/valid.sock')) {
        throw new \RuntimeException('Run through the dedicated TLS fixture harness');
    }
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });
    $checks = 0;
    $check = static function ($condition, string $message) use (&$checks): void {
        if (!$condition) { throw new \RuntimeException($message); }
        $checks++;
    };
    $fixtureToken = 'fixture-secret&extra=value#fragment';
    $baselineConfig = ['urlsend' => ['baidu' => ['token' => $fixtureToken], 'baidufast' => ['token' => 'retired-secret']],
        'site' => ['site_url' => 'example.invalid']];
    $GLOBALS['config'] = $baselineConfig;
    $GLOBALS['http_type'] = 'https://';
    $GLOBALS['baidu_audit_options'] = [];
    $GLOBALS['baidu_audit_apis'] = [];
    $urls = ['urls' => [11 => 'https://example.invalid/1', 22 => 'https://example.invalid/2?a=1&b=2']];
    $response = static function ($body, int $status = 200, array $extra = []): void {
        file_put_contents('/audit/response.json', json_encode(['status' => $status,
            'body' => is_string($body) ? $body : json_encode($body, JSON_THROW_ON_ERROR)] + $extra, JSON_THROW_ON_ERROR));
    };
    $requests = static function (): array {
        return array_map(static fn($line) => json_decode($line, true, 512, JSON_THROW_ON_ERROR),
            file('/audit/requests.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    };
    $send = static function ($data = null) use ($urls, $requests, $check, $fixtureToken): array {
        $before = count($requests());
        ob_start();
        $result = (new Baidu())->submit($data ?? $urls);
        $output = ob_get_clean();
        $check($output === '', 'Adapter never echoes remote bodies or cURL output');
        $serialized = json_encode($result, JSON_THROW_ON_ERROR);
        $check(!str_contains($serialized, $fixtureToken) && !str_contains($serialized, 'fixture-secret')
            && !str_contains($serialized, '<script') && !str_contains($serialized, 'remote-private'),
            'Result never discloses query credentials, untrusted remote text or HTML');
        $check(count($requests()) - $before <= 1, 'Each submit call makes at most one HTTP request');
        return $result;
    };

    $response(['success' => 2, 'remain' => 7]);
    $before = count($requests());
    $result = $send();
    $check($result['code'] === 1 && $result['success'] === 2 && $result['remain'] === 7
        && str_contains($result['msg'], '推送成功2条') && str_contains($result['msg'], '剩余可推7条'), 'Successful counts keep their documented meanings');
    $check(count($requests()) === $before + 1, 'Successful batch sends exactly once');
    $request = $requests()[array_key_last($requests())];
    parse_str(parse_url($request['path'], PHP_URL_QUERY), $query);
    $check($query === ['site' => 'https://example.invalid', 'token' => $fixtureToken], 'Opaque token is encoded as one query value without injection');
    $check($request['body'] === implode("\n", $urls['urls']) && $request['headers']['Content-Type'] === 'text/plain', 'Associative content IDs produce the expected newline-separated request body');
    $options = $GLOBALS['baidu_audit_options'][0];
    $check($options[CURLOPT_SSL_VERIFYPEER] === true && $options[CURLOPT_SSL_VERIFYHOST] === 2
        && $options[CURLOPT_FOLLOWLOCATION] === false && $options[CURLOPT_PROXY] === '' && $options[CURLOPT_NOPROXY] === '*',
        'Production TLS verification, no redirect and no implicit proxy settings remain active');
    $check($options[CURLOPT_CONNECTTIMEOUT_MS] > 0 && $options[CURLOPT_TIMEOUT_MS] > 0
        && (isset($options[CURLOPT_PROTOCOLS_STR]) ? $options[CURLOPT_PROTOCOLS_STR] === 'https' : $options[CURLOPT_PROTOCOLS] === CURLPROTO_HTTPS),
        'Production transport is bounded and HTTPS only');
    $check(str_starts_with($GLOBALS['baidu_audit_apis'][0], 'https://data.zz.baidu.com/urls?'), 'Adapter uses the fixed reviewed service');
    $check($GLOBALS['config'] === $baselineConfig, 'Submission never rewrites stored configuration');

    foreach (['https://example.invalid/', 'http://example.invalid'] as $site) {
        $GLOBALS['config']['site']['site_url'] = $site;
        $check($send()['code'] === 1, 'An already absolute site configuration is accepted');
        $request = $requests()[array_key_last($requests())];
        parse_str(parse_url($request['path'], PHP_URL_QUERY), $query);
        $check($query['site'] === rtrim($site, '/'), 'Existing site scheme is preserved without double-prefixing');
    }
    $GLOBALS['config'] = $baselineConfig;
    $duplicate = $urls;
    $duplicate['urls'][99] = $urls['urls'][11];
    $result = $send($duplicate);
    $check($result['submitted'] === 2 && $result['code'] === 1, 'Exact duplicate URLs are submitted once within a batch');

    foreach ([[], ['urls' => []], ['urls' => 'text'], ['urls' => [[]]], ['urls' => [null]], ['urls' => [123]],
        ['urls' => ['https://example.invalid/1' . "\n" . 'https://other.invalid/2']], ['urls' => ['javascript:alert(1)']],
        ['urls' => ['https://user:password@example.invalid/1']], ['urls' => array_fill(0, 2001, 'https://example.invalid/1')]] as $bad) {
        $before = count($requests());
        $check($send($bad)['code'] === 100 && count($requests()) === $before, 'Invalid URL inputs fail before any HTTP request');
    }
    foreach ([[], ['site' => ['site_url' => 'example.invalid']],
        array_replace_recursive($baselineConfig, ['urlsend' => ['baidu' => ['token' => []]]]),
        array_replace_recursive($baselineConfig, ['urlsend' => ['baidu' => ['token' => "bad\nvalue"]]]),
        array_replace_recursive($baselineConfig, ['site' => ['site_url' => 'https://https://example.invalid']]),
        array_replace_recursive($baselineConfig, ['site' => ['site_url' => 'https://example.invalid/path']]),
        array_replace_recursive($baselineConfig, ['site' => ['site_url' => 'https://example.invalid/?token=wrong']])
    ] as $badConfig) {
        $GLOBALS['config'] = $badConfig;
        $before = count($requests());
        $check($send()['code'] === 100 && count($requests()) === $before, 'Invalid/missing configuration fails before transport');
    }
    $GLOBALS['config'] = $baselineConfig;

    foreach (['', 'not JSON remote-private <script>fixture-secret</script>', 'null', '[]', '{}',
        ['success' => 1], ['remain' => 1], ['success' => '2', 'remain' => 1], ['success' => -1, 'remain' => 1],
        ['success' => 3, 'remain' => 1], ['success' => 2, 'remain' => -1], ['success' => 2, 'remain' => []],
        ['success' => 2, 'remain' => 1, 'not_same_site' => null], ['success' => 2, 'remain' => 1, 'not_valid' => ['unexpected' => 'text']],
        ['success' => 2, 'remain' => 1, 'not_valid' => [[]]], ['success' => 2, 'remain' => 1, 'not_valid' => ['not a URL']],
    ] as $index => $body) {
        $response($body);
        $actual = $send();
        $check($actual['code'] === 101, 'Malformed response case ' . $index . ' has code ' . $actual['code']);
    }
    foreach ([[400, ['error' => 400, 'message' => 'over quota']], [401, ['error' => 401, 'message' => 'token is not valid']],
        [500, ['success' => 2, 'remain' => 7]], [400, ['error' => 400, 'message' => '<script>remote-private fixture-secret</script>']],
        [200, ['error' => 400, 'message' => 'site error']]] as [$status, $body]) {
        $response($body, $status);
        $check($send()['code'] === 102, 'HTTP/provider failures are never mistaken for successful stats');
    }
    foreach ([['success' => 1, 'remain' => 0], ['success' => 2, 'remain' => 0], ['success' => 0, 'remain' => 10],
        ['success' => 1, 'remain' => 8, 'not_same_site' => ['https://other.invalid/1']]] as $body) {
        $response($body);
        $before = count($requests());
        $result = $send();
        $check($result['code'] === 103 && $result['success'] === $body['success'] && $result['remain'] === $body['remain']
            && count($requests()) === $before + 1, 'Quota exhaustion/partial acknowledgement stops caller pagination without replay or guessed accepted IDs');
    }
    foreach (['http://other.invalid/steal?token=fixture-secret', 'https://other.invalid/steal?token=fixture-secret',
        'https://data.zz.baidu.com/urls?token=fixture-secret'] as $location) {
        $response(['success' => 2, 'remain' => 7], 307, ['headers' => ['Location' => $location]]);
        $check($send()['code'] === 102, 'Downgrade/cross-host/same-host redirects never forward the request or token');
    }
    $response(['success' => 2, 'remain' => 7]);
    foreach (['untrusted', 'wrong-host'] as $mode) {
        $GLOBALS['baidu_audit_tls'] = $mode;
        $before = count($requests());
        $result = $send();
        $check($result['code'] === 101 && str_contains($result['msg'], 'HTTPS') && count($requests()) === $before,
            'Real TLS rejects an untrusted certificate or wrong hostname before HTTP/token transmission');
    }
    $GLOBALS['baidu_audit_tls'] = 'valid';
    $response(str_repeat('remote-private fixture-secret', 4000));
    $check($send()['code'] === 101, 'Oversized response is bounded and never included in errors');
    $response('', 200, ['disconnect' => true]);
    $check($send()['code'] === 101, 'Connection close after request acknowledgement is uncertain and never automatically retried');
    $response(['success' => 2, 'remain' => 7], 200, ['delay' => 0.3]);
    $GLOBALS['baidu_audit_tls'] = 'timeout';
    $check($send()['code'] === 101, 'Timeout remains a controlled uncertain result without retry');
    $GLOBALS['baidu_audit_tls'] = 'valid';

    $before = count($requests());
    $calls = count($GLOBALS['baidu_audit_options']);
    $snapshot = $GLOBALS['config'];
    foreach ([$urls, [], ['urls' => []], 'invalid', null] as $data) {
        $result = (new Baidufast())->submit($data);
        $check($result['code'] === 105 && str_contains($result['msg'], '下线') && str_contains($result['msg'], '本次未发送'),
            'Retired fast inclusion adapter has a clear controlled result for any legacy call');
    }
    $check(count($requests()) === $before && count($GLOBALS['baidu_audit_options']) === $calls && $GLOBALS['config'] === $snapshot,
        'Retired fast adapter makes no request and never borrows ordinary-channel tokens or rewrites configuration');
    echo "OK {$checks} Baidu URL submission checks on PHP " . PHP_VERSION . "\n";
}
