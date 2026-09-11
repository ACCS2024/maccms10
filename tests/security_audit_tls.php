<?php
/** Inspect direct-client cURL options and failure contracts without external traffic. */
namespace app\common\util {
    function curl_init($url = null) { return \audit_tls_init($url); }
    function curl_setopt($handle, $option, $value) { return \audit_tls_option($handle, $option, $value); }
    function curl_setopt_array($handle, $options) { foreach ($options as $option => $value) { \audit_tls_option($handle, $option, $value); } return true; }
    function curl_exec($handle) { return \audit_tls_exec($handle); }
    function curl_getinfo($handle, $option) { return $option === CURLINFO_PRIMARY_IP ? '1.1.1.1' : ($GLOBALS['tls_failure'] ? 0 : 200); }
    function curl_error($handle) { return $GLOBALS['tls_failure'] ? 'fixture certificate failure https://fixture.invalid/private' : ''; }
    function curl_close($handle) {}
}
namespace app\admin\controller {
    class Base {}
    function curl_init($url = null) { return \audit_tls_init($url); }
    function curl_setopt($handle, $option, $value) { return \audit_tls_option($handle, $option, $value); }
    function curl_exec($handle) { return \audit_tls_exec($handle); }
    function curl_close($handle) {}
}
namespace app\api\controller {
    class Base {}
    function curl_init($url = null) { return \audit_tls_init($url); }
    function curl_setopt($handle, $option, $value) { return \audit_tls_option($handle, $option, $value); }
    function curl_exec($handle) { return \audit_tls_exec($handle); }
    function curl_errno($handle) { return $GLOBALS['tls_failure'] ? 60 : 0; } // libcurl certificate verification error.
    function curl_error($handle) { return $GLOBALS['tls_failure'] ? 'fixture certificate failure' : ''; }
    function curl_close($handle) {}
}
namespace {
    require __DIR__ . '/fixtures/security_audit_test_helpers.php';
    require dirname(__DIR__) . '/application/common/util/UeditorAiProxy.php';
    require dirname(__DIR__) . '/application/common/util/PublicHttpClient.php';
    require dirname(__DIR__) . '/application/common/util/VodAiCover.php';
    require dirname(__DIR__) . '/application/admin/controller/Meilisearch.php';
    require dirname(__DIR__) . '/application/api/controller/Ppvod.php';
    if (!extension_loaded('curl')) { throw new RuntimeException('curl is required'); }
    $temporaryRoot = audit_temp_dir('tls');
    define('RUNTIME_PATH', $temporaryRoot . '/');
    function cache($key, ...$args) { return ''; }
    function audit_tls_init($url) {
        $handle = new stdClass();
        $handle->options = $url === null ? [] : [CURLOPT_URL => $url];
        $GLOBALS['tls_handles'][] = $handle;
        return $handle;
    }
    function audit_tls_option($handle, $option, $value) { $handle->options[$option] = $value; return true; }
    function audit_tls_exec($handle) {
        if ($GLOBALS['tls_failure']) { return false; }
        $body = '{"tag_name":"v1.2.3"}';
        if (isset($handle->options[CURLOPT_WRITEFUNCTION])) {
            $handle->options[CURLOPT_HEADERFUNCTION]($handle, "HTTP/1.1 200 OK\r\n");
            return $handle->options[CURLOPT_WRITEFUNCTION]($handle, $body) === strlen($body);
        }
        return $body;
    }
    function audit_tls_verified(): void {
        $handle = $GLOBALS['tls_handles'][array_key_last($GLOBALS['tls_handles'])];
        check(($handle->options[CURLOPT_SSL_VERIFYPEER] ?? null) === true, 'Client disabled certificate chain verification');
        check(($handle->options[CURLOPT_SSL_VERIFYHOST] ?? null) === 2, 'Client disabled certificate hostname verification');
    }
    $ueditor = new ReflectionMethod(app\common\util\UeditorAiProxy::class, 'httpPostJson');
    $cover = new ReflectionMethod(app\common\util\VodAiCover::class, 'curlPostJson');
    $meili = (new ReflectionClass(app\admin\controller\Meilisearch::class))->newInstanceWithoutConstructor();
    $version = new ReflectionMethod($meili, 'fetchLatestMeiliVersion');
    $ppvod = (new ReflectionClass(app\api\controller\Ppvod::class))->newInstanceWithoutConstructor();
    $ppvodConfig = new ReflectionProperty($ppvod, '_cfg');
    $fetch = new ReflectionMethod($ppvod, 'fetchImageWithTryCatch');
    try {
        foreach ([false, true] as $failure) {
            $GLOBALS['tls_failure'] = $failure;
            $result = $ueditor->invoke(null, 'https://fixture.invalid/', [], '{}', 10);
            audit_tls_verified();
            check($result['status'] === ($failure ? 0 : 200), 'Editor HTTP status contract changed');
            check(!$failure || $result['body'] === '' && !str_contains($result['curl_error'], 'https://'), 'Editor transport failure returned a body or unredacted URL');
            $result = $cover->invoke(null, 'https://1.1.1.1/', '{}', [], 10);
            audit_tls_verified();
            check($result === ($failure ? false : '{"tag_name":"v1.2.3"}'), 'Cover transport failure/bounded response contract changed');
            $result = $version->invoke($meili);
            audit_tls_verified();
            check($result === ($failure ? '' : '1.2.3'), 'Version check did not handle the transport result');
            $ppvodConfig->setValue($ppvod, ['pic_fetch_api' => 'https://fixture.invalid/?url=', 'pic_fetch_timeout' => 999]);
            check($fetch->invoke($ppvod, 'https://image.invalid/1.jpg') === null, 'Image prefetch should terminate without a response');
            audit_tls_verified();
            $options = $GLOBALS['tls_handles'][array_key_last($GLOBALS['tls_handles'])]->options;
            check($options[CURLOPT_CONNECTTIMEOUT] === 5 && $options[CURLOPT_TIMEOUT] === 60, 'Image prefetch timeout was not capped');
        }
        $logs = glob($temporaryRoot . '/api/ppvod/*.log');
        check(count($logs) === 1 && str_contains(file_get_contents($logs[0]), 'fixture certificate failure'), 'Image prefetch certificate failure was not logged');
        $GLOBALS['tls_failure'] = false;
        $ppvodConfig->setValue($ppvod, ['pic_fetch_api' => 'https://fixture.invalid/?url=', 'pic_fetch_timeout' => 0]);
        $fetch->invoke($ppvod, 'https://image.invalid/1.jpg');
        $options = $GLOBALS['tls_handles'][array_key_last($GLOBALS['tls_handles'])]->options;
        check($options[CURLOPT_TIMEOUT] === 1, 'Image prefetch accepted an unlimited zero timeout');
        $count = count($GLOBALS['tls_handles']);
        $ppvodConfig->setValue($ppvod, []);
        $fetch->invoke($ppvod, 'https://image.invalid/1.jpg');
        check(count($GLOBALS['tls_handles']) === $count, 'Unconfigured image prefetch started a transfer');
    } finally {
        audit_remove_temp($temporaryRoot);
    }
    echo 'Direct-client TLS regressions: ' . $checks . " assertions passed\n";
}
