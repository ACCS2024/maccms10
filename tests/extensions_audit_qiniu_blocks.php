<?php
/** Real Qiniu region and block protocol, with only cURL and controlled short reads isolated. */
namespace Qiniu\Http {
    function curl_init() { return new \stdClass(); }
    function curl_setopt($handle, $option, $value) { return true; }
    function curl_setopt_array($handle, $options) { $handle->options = $options; return true; }
    function curl_exec($handle) {
        $options = $handle->options;
        $GLOBALS['block_requests'][] = $options;
        $next = array_shift($GLOBALS['block_queue']);
        if ($next === null) {
            $body = $options[CURLOPT_POSTFIELDS] ?? '';
            $next = ['code' => 200, 'json' => str_contains($options[CURLOPT_URL], '/mkblk/')
                ? ['crc32' => (int)\Qiniu\crc32_data($body), 'ctx' => 'ctx-' . strlen($body), 'offset' => strlen($body)]
                : ['key' => 'fixture-key']];
        }
        if (is_callable($next)) { $next = $next($options); }
        $handle->fixture = $next;
        if (isset($next['errno'])) { return false; }
        $head = 'HTTP/1.1 ' . $next['code'] . " Fixture\r\ncontent-type: application/json\r\n\r\n";
        $handle->headerSize = strlen($head);
        return $head . ($next['body'] ?? json_encode($next['json'], JSON_THROW_ON_ERROR));
    }
    function curl_errno($handle) { return $handle->fixture['errno'] ?? 0; }
    function curl_error($handle) { return 'isolated transport failure'; }
    function curl_getinfo($handle, $option) { return $option === CURLINFO_HTTP_CODE ? $handle->fixture['code'] : $handle->headerSize; }
    function curl_close($handle) {}
}
namespace Qiniu\Storage {
    function fread($stream, $size) {
        if (!empty($GLOBALS['block_read_fail'])) { return false; }
        return \fread($stream, isset($GLOBALS['block_read_limit']) ? min($size, $GLOBALS['block_read_limit']) : $size);
    }
    function fopen($path, $mode) { return $GLOBALS['block_file'] = \fopen($path, $mode); }
}
namespace {
    require dirname(__DIR__) . '/extend/qiniu/autoload.php';
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
    function resetTransport(array $queue = []): void { $GLOBALS['block_queue'] = $queue; $GLOBALS['block_requests'] = []; }
    function zoneBody(): array {
        return ['io' => ['src' => ['main' => ['iovip-z1.qbox.me']]],
            'up' => ['src' => ['main' => ['up-z1.qiniup.com'], 'backup' => ['up-backup.qiniup.com']],
                'acc' => ['main' => ['upload-z1.qiniup.com'], 'backup' => ['upload-backup.qiniup.com']]]];
    }
    function configFixture(): \Qiniu\Config {
        return new \Qiniu\Config(new \Qiniu\Zone(['primary.invalid'], ['backup.invalid']));
    }
    function tokenFixture(string $scope = 'fixture-bucket'): string {
        return 'fixture-ak:fixture-signature:' . \Qiniu\base64_urlSafeEncode(json_encode(['scope' => $scope]));
    }
    function uploadFixture(string $body = 'sample', ?int $size = null): array {
        $stream = fopen('php://temp', 'w+b'); fwrite($stream, $body); rewind($stream);
        try {
            $up = new \Qiniu\Storage\ResumeUploader(tokenFixture(), 'fixture-key', $stream, $size ?? strlen($body), null, 'text/plain', configFixture());
            return $up->upload('fixture.txt');
        } finally { fclose($stream); }
    }
    if (($argv[1] ?? '') === 'baseline') {
        foreach ([
            static function () { resetTransport([['code' => 200, 'json' => []]]); \Qiniu\Zone::queryZone('fixture', 'bucket'); },
            static function () { resetTransport([['code' => 503, 'json' => ['error' => 'fixture']]]); (new \Qiniu\Config())->getUpHost('fixture', 'bucket'); },
            static function () { resetTransport([['code' => 200, 'json' => ['crc32' => (int)\Qiniu\crc32_data('sample')]]]); uploadFixture(); },
            static function () { \Qiniu\explodeUpToken('ak:sig:' . base64_encode('{}')); },
        ] as $broken) {
            $thrown = false;
            try { $broken(); } catch (\Throwable $e) { $thrown = true; }
            verify($thrown, 'Original malformed region/token/block response raises a strict error');
        }
        resetTransport();
        [$result, $error] = uploadFixture('abc', 4);
        verify($error === null && $result['key'] === 'fixture-key' && strlen($GLOBALS['block_requests'][0][CURLOPT_POSTFIELDS]) === 3,
            'Original uploader sends a short block then completes the advertised larger file');
        resetTransport([['code' => 401, 'json' => ['error' => 'denied']], ['code' => 401, 'json' => ['error' => 'denied']]]);
        uploadFixture();
        verify(count($GLOBALS['block_requests']) === 2, 'Original uploader resends a nonretryable denied block');
        echo "OK {$checks} original Qiniu region/block reproductions on PHP " . PHP_VERSION . "\n";
        exit;
    }

    foreach (['', 'bad', 'a:b:c:d', ':sig:e30=', 'ak::e30=', "ak\r\n:sig:e30=", 'ak:sig with space:e30=', 'ak:sig:###', 'ak:sig:' . base64_encode('{bad'),
        'ak:sig:' . base64_encode('{}'), 'ak:sig:' . base64_encode('null'), 'ak:sig:' . base64_encode('{"scope":[]}'),
        'ak:sig:' . base64_encode('{"scope":""}'), 'ak:sig:' . base64_encode('{"scope":":key"}'), [], null] as $token) {
        verify(\Qiniu\explodeUpToken($token) === [null, null, 'invalid uptoken'], 'Malformed token returns its historical error tuple');
    }
    verify(\Qiniu\explodeUpToken(tokenFixture('fixture-bucket:path:中文')) === ['fixture-ak', 'fixture-bucket', null], 'Valid key-qualified policy retains bucket');
    $stream = fopen('php://temp', 'w+b');
    try {
        $thrown = false;
        try { new \Qiniu\Storage\ResumeUploader('bad', 'key', $stream, 1, null, 'text/plain', configFixture()); }
        catch (\InvalidArgumentException $e) { $thrown = $e->getMessage() === 'invalid uptoken'; }
        verify($thrown, 'Invalid token cannot leave a partially initialized uploader');
    } finally { fclose($stream); }
    resetTransport([['code' => 200, 'json' => zoneBody()]]);
    $zone = \Qiniu\Zone::queryZone('fixture&ak', 'bucket?name');
    verify($zone instanceof \Qiniu\Zone && $zone->srcUpHosts === ['up-z1.qiniup.com', 'up-backup.qiniup.com'] && $zone->rsHost === 'rs-z1.qiniu.com', 'Valid zone retains primary/backups and regional endpoints');
    verify(str_contains($GLOBALS['block_requests'][0][CURLOPT_URL], 'ak=fixture%26ak&bucket=bucket%3Fname'), 'Query parameters cannot alter each other');
    foreach ([null, [], 'bad', ['io' => []], array_replace_recursive(zoneBody(), ['up' => ['src' => ['main' => [null]]]]),
        array_replace_recursive(zoneBody(), ['up' => ['acc' => ['backup' => ['https://wrong.invalid/path']]]]),
        array_replace_recursive(zoneBody(), ['io' => ['src' => ['main' => ['host.invalid/path']]]])] as $body) {
        resetTransport([['code' => 200, 'json' => $body]]);
        $result = \Qiniu\Zone::queryZone('fixture', 'bucket');
        verify(is_array($result) && $result[0] === null && $result[1] instanceof \Qiniu\Http\Error && $result[1]->message() === 'Invalid zone query response', 'Malformed successful zone returns a controlled SDK error');
    }
    resetTransport([['code' => 503, 'json' => ['error' => 'fixture unavailable']], ['code' => 200, 'json' => zoneBody()]]);
    $config = new \Qiniu\Config();
    $thrown = false;
    try { $config->getUpHost('fixture', 'bucket'); } catch (\RuntimeException $e) { $thrown = str_contains($e->getMessage(), 'zone query failed'); }
    verify($thrown, 'Config converts zone errors before property access');
    verify($config->getUpHost('fixture', 'bucket') === 'https://up-z1.qiniup.com', 'A failed zone query is not cached');
    verify($config->getUpBackupHost('fixture', 'bucket') === 'https://upload-z1.qiniup.com' && count($GLOBALS['block_requests']) === 2, 'Successful zone is cached');

    resetTransport();
    [$result, $error] = uploadFixture();
    verify($error === null && $result['key'] === 'fixture-key' && count($GLOBALS['block_requests']) === 2, 'Normal block and completion succeed');
    verify(in_array('Content-Type: application/octet-stream', $GLOBALS['block_requests'][0][CURLOPT_HTTPHEADER], true), 'Block bytes use the required MIME type');
    verify($GLOBALS['block_requests'][1][CURLOPT_POSTFIELDS] === 'ctx-6', 'Completion carries accepted opaque context');
    foreach ([['crc32' => (int)\Qiniu\crc32_data('sample')], ['crc32' => true, 'ctx' => 'ctx', 'offset' => 6],
        ['crc32' => (int)\Qiniu\crc32_data('sample'), 'ctx' => [], 'offset' => 6],
        ['crc32' => (int)\Qiniu\crc32_data('sample'), 'ctx' => '', 'offset' => 6],
        ['crc32' => (int)\Qiniu\crc32_data('sample'), 'ctx' => 'ctx', 'offset' => 2],
        ['crc32' => 0, 'ctx' => 'ctx', 'offset' => 6], null, 'scalar'] as $invalid) {
        resetTransport([['code' => 200, 'json' => $invalid], ['code' => 200, 'json' => $invalid]]);
        [$result, $error] = uploadFixture();
        verify($result === null && $error instanceof \Qiniu\Http\Error && is_string($error->message()) && $error->message() !== '', 'Invalid block schema/integrity is a useful SDK error');
        verify(count($GLOBALS['block_requests']) === 2 && !str_contains($GLOBALS['block_requests'][1][CURLOPT_URL], '/mkfile/'), 'Invalid blocks get at most one retry and never complete');
    }
    foreach ([401, 579] as $code) {
        resetTransport([['code' => $code, 'json' => ['error' => 'denied']]]);
        [$result, $error] = uploadFixture();
        verify($result === null && $error->code() === $code && count($GLOBALS['block_requests']) === 1, 'Nonretryable block errors do not resend');
    }
    resetTransport([['errno' => 7]]);
    [$result, $error] = uploadFixture();
    verify($error === null && str_starts_with($GLOBALS['block_requests'][1][CURLOPT_URL], 'https://backup.invalid/'), 'Transport failure retries once on configured backup');
    foreach (['crc', '503'] as $mode) {
        resetTransport([$mode === 'crc' ? ['code' => 200, 'json' => ['crc32' => 0]] : ['code' => 503, 'json' => ['error' => 'busy']]]);
        [$result, $error] = uploadFixture();
        verify($error === null && count($GLOBALS['block_requests']) === 3 && $GLOBALS['block_requests'][0][CURLOPT_POSTFIELDS] === $GLOBALS['block_requests'][1][CURLOPT_POSTFIELDS], 'One transient/integrity retry retains the exact block bytes');
    }
    foreach ([null, 2] as $limit) {
        resetTransport(); $GLOBALS['block_read_limit'] = $limit;
        $thrown = false;
        try { uploadFixture('abc', 4); } catch (\RuntimeException $e) { $thrown = true; }
        verify($thrown && $GLOBALS['block_requests'] === [], 'EOF/short read terminates before sending any incomplete block');
    }
    unset($GLOBALS['block_read_limit']);
    resetTransport(); $GLOBALS['block_read_limit'] = 2;
    [$result, $error] = uploadFixture();
    verify($error === null && $GLOBALS['block_requests'][0][CURLOPT_POSTFIELDS] === 'sample', 'Short but progressing reads accumulate the complete block');
    unset($GLOBALS['block_read_limit']);
    resetTransport(); $GLOBALS['block_read_fail'] = true;
    $thrown = false;
    try { uploadFixture(); } catch (\RuntimeException $e) { $thrown = true; }
    verify($thrown && $GLOBALS['block_requests'] === [], 'Read failure stops before network');
    unset($GLOBALS['block_read_fail']);
    resetTransport([null, ['code' => 503, 'json' => ['error' => 'busy']]]);
    [$result, $error] = uploadFixture();
    verify($error === null && count($GLOBALS['block_requests']) === 3, 'Completion retry remains bounded');
    foreach ([false, true] as $completion) {
        $failures = [['code' => 503, 'json' => ['error' => 'busy']], ['code' => 503, 'json' => ['error' => 'busy']]];
        resetTransport($completion ? array_merge([null], $failures) : $failures);
        [$result, $error] = uploadFixture();
        verify($result === null && $error->code() === 503 && count($GLOBALS['block_requests']) === ($completion ? 3 : 2), 'Repeated server failures terminate after the bounded retry');
    }
    $file = tempnam(sys_get_temp_dir(), 'qiniu-blocks-');
    try {
        file_put_contents($file, str_repeat('x', \Qiniu\Config::BLOCK_SIZE) . 'tail');
        resetTransport();
        [$result, $error] = (new \Qiniu\Storage\UploadManager(configFixture()))->putFile(tokenFixture(), 'fixture-key', $file);
        verify($error === null && $result['key'] === 'fixture-key' && count($GLOBALS['block_requests']) === 3, 'Real large-file manager uses two ordered blocks and completion');
        verify(strlen($GLOBALS['block_requests'][0][CURLOPT_POSTFIELDS]) === \Qiniu\Config::BLOCK_SIZE && $GLOBALS['block_requests'][1][CURLOPT_POSTFIELDS] === 'tail', 'Large-file blocks match actual bytes');
        verify($GLOBALS['block_requests'][2][CURLOPT_POSTFIELDS] === 'ctx-4194304,ctx-4' && !is_resource($GLOBALS['block_file']), 'Ordered contexts and final stream closure are preserved');
        resetTransport(); $GLOBALS['block_read_fail'] = true;
        $thrown = false;
        try { (new \Qiniu\Storage\UploadManager(configFixture()))->putFile(tokenFixture(), 'fixture-key', $file); }
        catch (\RuntimeException $e) { $thrown = true; }
        unset($GLOBALS['block_read_fail']);
        verify($thrown && $GLOBALS['block_requests'] === [] && !is_resource($GLOBALS['block_file']) && is_file($file), 'Actual manager closes the failed stream and preserves the local source');
    } finally { unlink($file); }
    echo "OK {$checks} Qiniu region/block checks on PHP " . PHP_VERSION . "\n";
}
