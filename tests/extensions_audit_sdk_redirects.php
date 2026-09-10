<?php
/** Only route cURL through a disposable Unix socket; keep real SDKs and redirect/TLS options. */
namespace Qiniu\Http {
    function curl_setopt_array($handle, $options) {
        $GLOBALS['redirect_qiniu_options'] = $options;
        return \curl_setopt_array($handle, \fixtureCurlOptions($options));
    }
}
namespace GuzzleHttp\Handler {
    function curl_setopt($handle, $option, $value) {
        $GLOBALS['redirect_guzzle_options'][$option] = $value;
        $success = \curl_setopt($handle, $option, $value);
        \curl_setopt_array($handle, \fixtureCurlOptions([]));
        return $success;
    }
}
namespace {
    if (!is_file('/audit/ca.pem') || !file_exists('/audit/server.sock')) { throw new \RuntimeException('Run the isolated redirect harness'); }
    require '/app/vendor/autoload.php';
    require '/app/extend/upyun/vendor/autoload.php';
    require '/app/extend/qiniu/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (error_reporting() & $level) { throw new \ErrorException($message, 0, $level, $file, $line); }
        return false;
    });
    $checks = 0;
    function verify($ok, string $message): void {
        global $checks;
        if (!$ok) { throw new \RuntimeException($message); }
        ++$checks;
    }
    function fixtureCurlOptions(array $options): array {
        // Real cURL still follows/doesn't follow redirects and validates every certificate.
        $options[CURLOPT_UNIX_SOCKET_PATH] = '/audit/server.sock';
        $options[CURLOPT_CAINFO] = $GLOBALS['redirect_ca'] ?? '/audit/ca.pem';
        $options[CURLOPT_PROXY] = '';
        $options[CURLOPT_TIMEOUT] = 5;
        return $options;
    }
    function response(int $status = 200, string $scheme = 'https'): void {
        file_put_contents('/audit/requests.jsonl', '');
        file_put_contents('/audit/response.json', json_encode(['status' => $status, 'location' => $scheme . '://collector.invalid/received?fixture=1']));
    }
    function requests(): array {
        return array_map(static fn($line) => json_decode($line, true, 512, JSON_THROW_ON_ERROR), file('/audit/requests.jsonl'));
    }
    function qiniuUpload(string $host = 'upload.invalid'): array {
        $config = new \Qiniu\Config(new \Qiniu\Zone([$host], [$host]));
        $token = 'fixture-ak:fixture-signature:' . \Qiniu\base64_urlSafeEncode(json_encode(['scope' => 'fixture-bucket']));
        return (new \Qiniu\Storage\UploadManager($config))->put($token, 'fixture-key', 'PRIVATE_UPLOAD_FIXTURE');
    }
    function upyunConfig(string $host = 'upload.invalid'): \Upyun\Config {
        $config = new \Upyun\Config('fixture-bucket', 'fixture-operator', 'fixture-password');
        \Upyun\Config::$restApiEndPoint = $host;
        $config->processNotifyUrl = 'https://notify.invalid/fixture';
        return $config;
    }
    if (($argv[1] ?? '') === 'baseline') {
        foreach (['https', 'http'] as $scheme) {
            foreach (['qiniu', 'upyun-rest', 'upyun-form'] as $sdk) {
                response(307, $scheme);
                if ($sdk === 'qiniu') { qiniuUpload(); }
                else { (new \Upyun\Upyun(upyunConfig()))->write('/fixture.txt', 'PRIVATE_UPLOAD_FIXTURE', [], $sdk === 'upyun-form'); }
                $rows = requests();
                verify(count($rows) === 2 && $rows[1]['host'] === 'collector.invalid', 'Original SDK follows a remote-selected target');
                verify($rows[1]['tls'] === ($scheme === 'https') && str_contains($rows[1]['body'], 'PRIVATE_UPLOAD_FIXTURE'), 'Original 307 replays upload bytes across host/protocol');
                if ($sdk !== 'upyun-rest') {
                    verify(str_contains($rows[1]['body'], $sdk === 'qiniu' ? 'fixture-ak:fixture-signature:' : 'name="authorization"'), 'Multipart credential field follows the body');
                }
            }
        }
        echo "OK {$checks} original SDK redirect reproductions on PHP " . PHP_VERSION . "\n";
        exit;
    }
    foreach ([301, 302, 303, 307, 308] as $status) {
        foreach (['https', 'http'] as $scheme) {
            response($status, $scheme);
            [$result, $error] = qiniuUpload();
            verify($result === null && $error instanceof \Qiniu\Http\Error && $error->code() === $status && $error->message() === 'Unexpected redirect from Qiniu API', 'Qiniu redirects return a useful SDK failure');
            verify(count(requests()) === 1 && requests()[0]['tls'] === true, 'Qiniu upload/token does not reach redirect destination');
            response($status, $scheme); $thrown = false;
            try { (new \Upyun\Upyun(upyunConfig()))->write('/fixture.txt', 'PRIVATE_UPLOAD_FIXTURE'); }
            catch (\RuntimeException $e) { $thrown = $e->getMessage() === 'Unexpected redirect from Upyun API'; }
            verify($thrown && count(requests()) === 1 && requests()[0]['tls'] === true, 'Upyun REST redirect cannot become a successful empty-header result');
            response($status, $scheme);
            $result = (new \Upyun\Upyun(upyunConfig()))->write('/fixture.txt', 'PRIVATE_UPLOAD_FIXTURE', [], true);
            verify($result === false && count(requests()) === 1, 'Upyun multipart redirect retains false failure and does not replay credentials');
        }
    }
    foreach (['pretreat', 'query', 'sync', 'purge'] as $api) {
        response(307, 'http'); $config = upyunConfig(); $thrown = false;
        if ($api === 'purge') { $config->useSsl = false; } // Explicit legacy HTTP path; secure purge is audited separately.
        try {
            match ($api) {
                'pretreat' => (new \Upyun\Api\Pretreat($config))->process([['type' => 'fixture']]),
                'query' => (new \Upyun\Api\Pretreat($config))->query(['fixture-task'], '/status/'),
                'sync' => (new \Upyun\Api\SyncVideo($config))->process(['fixture' => 'task'], '/process/'),
                'purge' => (new \Upyun\Upyun($config))->purge(['https://cdn.invalid/fixture']),
            };
        } catch (\RuntimeException $e) { $thrown = $e->getMessage() === 'Unexpected redirect from Upyun API'; }
        verify($thrown && count(requests()) === 1 && requests()[0]['tls'] === ($api !== 'purge'), 'Every signed Upyun API rejects a redirect before parsing success: ' . $api);
    }
    response(); [$result, $error] = qiniuUpload();
    verify($error === null && $result['key'] === 'fixture-key' && count(requests()) === 1, 'Direct Qiniu HTTPS upload still succeeds');
    verify($GLOBALS['redirect_qiniu_options'][CURLOPT_SSL_VERIFYPEER] === true && $GLOBALS['redirect_qiniu_options'][CURLOPT_SSL_VERIFYHOST] === 2, 'Qiniu keeps peer and hostname verification');
    foreach ([false, true] as $form) {
        response(); $result = (new \Upyun\Upyun(upyunConfig()))->write('/fixture.txt', 'PRIVATE_UPLOAD_FIXTURE', [], $form);
        verify(($form ? $result === true : $result === ['x-upyun-width' => '10']) && count(requests()) === 1, 'Direct Upyun HTTPS result contract remains valid');
    }
    foreach (['qiniu', 'upyun'] as $sdk) {
        foreach (['wrong-host', 'untrusted'] as $failure) {
            response(); $GLOBALS['redirect_ca'] = $failure === 'untrusted' ? '/audit/untrusted.pem' : '/audit/ca.pem';
            $host = $failure === 'wrong-host' ? 'wrong-host.invalid' : 'upload.invalid';
            $failed = false;
            try {
                if ($sdk === 'qiniu') { [$result, $error] = qiniuUpload($host); $failed = $result === null && $error instanceof \Qiniu\Http\Error; }
                else { (new \Upyun\Upyun(upyunConfig($host)))->write('/fixture.txt', 'PRIVATE_UPLOAD_FIXTURE'); }
            } catch (\GuzzleHttp\Exception\ConnectException|\GuzzleHttp\Exception\RequestException $e) {
                $failed = ($e->getHandlerContext()['errno'] ?? 0) === 60;
            }
            verify($failed && requests() === [], 'TLS verification rejects the request before exposing body: ' . $sdk . '/' . $failure);
        }
    }
    unset($GLOBALS['redirect_ca']);
    $tmp = sys_get_temp_dir() . '/sdk-redirect-source-' . bin2hex(random_bytes(4));
    mkdir($tmp); mkdir($tmp . '/upload'); symlink('/app/extend', $tmp . '/extend');
    define('ROOT_PATH', $tmp . '/');
    require '/app/application/common/extend/upload/Upyun.php';
    $GLOBALS['config'] = ['upload' => ['api' => ['upyun' => ['bucket' => 'fixture-bucket', 'username' => 'fixture-operator', 'pwd' => 'fixture-password', 'url' => 'https://cdn.invalid']]]];
    try {
        file_put_contents($tmp . '/upload/fixture.txt', 'PRIVATE_UPLOAD_FIXTURE'); response(307, 'http');
        $result = (new \app\common\extend\upload\Upyun())->submit('upload/fixture.txt');
        verify($result === 'upload/fixture.txt' && is_file($tmp . '/upload/fixture.txt') && count(requests()) === 1,
            'Actual application adapter preserves its source and local URL when SDK rejects a redirect');
    } finally { unlink($tmp . '/upload/fixture.txt'); rmdir($tmp . '/upload'); unlink($tmp . '/extend'); rmdir($tmp); }
    echo "OK {$checks} SDK redirect checks on PHP " . PHP_VERSION . "\n";
}
