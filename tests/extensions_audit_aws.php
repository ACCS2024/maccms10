<?php
/** Serialize a real S3 command using fixture credentials; no HTTP request is sent. */
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) { return false; }
    throw new ErrorException($message, 0, $severity, $file, $line);
});
$client = new Aws\S3\S3Client([
    'version' => '2006-03-01',
    'region' => 'us-east-1',
    'endpoint' => 'https://storage.invalid',
    'use_path_style_endpoint' => true,
    'credentials' => ['key' => 'audit-fixture-key', 'secret' => 'audit-fixture-secret'],
]);
$request = Aws\serialize($client->getCommand('PutObject', [
    'Bucket' => 'audit-bucket', 'Key' => 'folder/test.txt', 'Body' => 'audit-body',
]));
if ($request->getMethod() !== 'PUT'
    || (string)$request->getUri() !== 'https://storage.invalid/audit-bucket/folder/test.txt'
    || (string)$request->getBody() !== 'audit-body'
    || !str_starts_with($request->getHeaderLine('Authorization'), 'AWS4-HMAC-SHA256 ')) {
    throw new RuntimeException('S3 request serialization or signing contract failed');
}
echo 'AWS S3 serialization and signing passed on PHP ' . PHP_VERSION . "\n";
