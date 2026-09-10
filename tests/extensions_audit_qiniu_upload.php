<?php
/** Actual UploadManager/FormUploader/multipart encoding; only cURL and the large-file transport are isolated. */
namespace Qiniu\Http {
    function curl_init() { return new \stdClass(); }
    function curl_setopt($handle, $option, $value) { return true; }
    function curl_setopt_array($handle, $options) { $GLOBALS['upload_options'] = $options; return true; }
    function curl_exec($handle) {
        if (!empty($GLOBALS['upload_throw'])) { throw new \RuntimeException('fixture transport failure'); }
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"key\":\"fixture-key\"}";
    }
    function curl_errno($handle) { return 0; }
    function curl_getinfo($handle, $key) { return $key === CURLINFO_HTTP_CODE ? 200 : strlen("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"); }
    function curl_close($handle) {}
}
namespace Qiniu\Storage {
    function fopen($path, $mode) { return $GLOBALS['upload_file'] = \fopen($path, $mode); }
    function fread($file, $length) { return !empty($GLOBALS['upload_short_read']) ? '' : \fread($file, $length); }
    class ResumeUploader {
        private $file;
        public function __construct($token, $key, $file, $size, $params, $mime, $config) { $this->file = $file; }
        public function upload($name) {
            if (!is_resource($this->file)) { throw new \RuntimeException('File closed before streaming'); }
            if (!empty($GLOBALS['upload_throw'])) { throw new \RuntimeException('fixture streaming failure'); }
            return [['key'=>'fixture-key', 'name'=>$name], null];
        }
    }
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
        global $checks; ++$checks;
        if (!$ok) { throw new \RuntimeException($message); }
    }
    $zone = new \Qiniu\Zone(['upload.invalid'], ['upload.invalid'], 'io.invalid', 'rs.invalid', 'rsf.invalid', 'api.invalid');
    $manager = new \Qiniu\Storage\UploadManager(new \Qiniu\Config($zone));
    $token = 'fixture-access:fixture-signature:' . \Qiniu\base64_urlSafeEncode(json_encode(['scope'=>'fixture-bucket']));
    $file = tempnam(sys_get_temp_dir(), 'qiniu-upload-');
    try {
        foreach ([false, true] as $crc) {
            file_put_contents($file, 'sample upload');
            [$result, $error] = $manager->putFile($token, 'fixture-key', $file, ['x:label'=>'fixture'], 'text/plain', $crc);
            $body = $GLOBALS['upload_options'][CURLOPT_POSTFIELDS];
            verify($error === null && $result['key'] === 'fixture-key', 'Small file did not return its upload result');
            verify(str_contains($body, 'filename="' . basename($file) . '"'), 'CRC flag replaced the local filename');
            verify(str_contains($body, "name=\"crc32\"\r\n\r\n" . \Qiniu\crc32_data('sample upload')), 'CRC must describe the complete file body');
            verify(str_contains($body, "name=\"x:label\"\r\n\r\nfixture") && str_contains($body, "Content-Type: text/plain\r\n\r\nsample upload"), 'Metadata or MIME/body changed');
            verify(!is_resource($GLOBALS['upload_file']), 'Small-file stream leaked');
        }
        file_put_contents($file, '');
        [$result, $error] = $manager->putFile($token, 'fixture-key', $file);
        verify($error === null && str_contains($GLOBALS['upload_options'][CURLOPT_POSTFIELDS], 'filename="' . basename($file) . '"'), 'Empty file raised fread length error or lost filename');
        verify(!is_resource($GLOBALS['upload_file']), 'Empty-file stream leaked');
        foreach ([[], [null], ['custom.txt']] as $tail) {
            $manager->put($token, 'fixture-key', 'data', null, 'text/plain', ...$tail);
            $name = $tail[0] ?? 'default_filename';
            verify(str_contains($GLOBALS['upload_options'][CURLOPT_POSTFIELDS], 'filename="' . $name . '"'), 'Default/explicit stream filename is invalid');
        }
        $manager->put($token, null, 'data');
        verify(str_contains($GLOBALS['upload_options'][CURLOPT_POSTFIELDS], 'filename="nullkey"'), 'Legacy null-key behavior changed');
        file_put_contents($file, 'nonempty');
        $GLOBALS['upload_short_read'] = true;
        $thrown = false;
        try { $manager->putFile($token, 'fixture-key', $file); } catch (\RuntimeException $e) { $thrown = true; }
        verify($thrown && !is_resource($GLOBALS['upload_file']), 'Short read was uploaded or left stream open');
        $GLOBALS['upload_short_read'] = false;
        foreach ([16, \Qiniu\Config::BLOCK_SIZE + 1] as $size) {
            $handle = fopen($file, 'wb'); ftruncate($handle, $size); fclose($handle); clearstatcache(true, $file);
            $GLOBALS['upload_throw'] = true;
            $thrown = false;
            try { $manager->putFile($token, 'fixture-key', $file); } catch (\RuntimeException $e) { $thrown = true; }
            verify($thrown && !is_resource($GLOBALS['upload_file']), 'Transport exception left file open');
            $GLOBALS['upload_throw'] = false;
        }
        [$result, $error] = $manager->putFile($token, 'fixture-key', $file);
        verify($error === null && $result['name'] === basename($file) && !is_resource($GLOBALS['upload_file']), 'Streaming upload did not retain filename/close the stream');
        echo "Qiniu upload regressions: $checks checks passed on PHP " . PHP_VERSION . "\n";
    } finally { unlink($file); }
}
