#!/usr/bin/env php
<?php
declare(strict_types=1);

$siteRoot = getenv('MACCMS_SITE_ROOT') ?: '/home/wwwroot/selangzy.com';
$host = getenv('MACCMS_TIMMING_HOST') ?: 'selangzy.com';
$task = $argv[1] ?? '';

if (!preg_match('/^[a-zA-Z0-9_-]+$/', $task)) {
    fwrite(STDERR, "A valid task name is required.\n");
    exit(2);
}

$configFile = $siteRoot . '/application/extra/maccms.php';
if (!is_file($configFile)) {
    fwrite(STDERR, "MacCMS config was not found.\n");
    exit(2);
}

$config = require $configFile;
$token = (string)($config['app']['timming_token'] ?? '');
if ($token === '') {
    fwrite(STDERR, "MacCMS timming token is not configured.\n");
    exit(2);
}

$query = http_build_query(['name' => $task]);
$url = 'https://' . $host . '/api.php/timming/index?' . $query;

$curl = curl_init($url);
curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 1800,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_RESOLVE => [$host . ':443:127.0.0.1'],
    CURLOPT_USERAGENT => 'MacCMS-Local-Timming/1.0',
    CURLOPT_HTTPHEADER => ['X-Maccms-Timming-Token: ' . $token],
]);

$body = curl_exec($curl);
$error = curl_error($curl);
$status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
curl_close($curl);

if (!is_string($body) || $status !== 200) {
    fwrite(STDERR, sprintf(
        "%s task=%s http=%d error=%s\n",
        date('c'),
        $task,
        $status,
        $error !== '' ? $error : 'request_failed'
    ));
    exit(1);
}

$plain = trim(preg_replace('/\s+/u', ' ', strip_tags($body)) ?? '');
$applicationFailed = str_contains($plain, 'invalid or missing timming token')
    || str_contains($plain, '服务器错误')
    || preg_match('/\\?"code\\?"\s*:\s*0/', $body) === 1;
if ($applicationFailed) {
    fwrite(STDERR, sprintf(
        "%s task=%s application_failed result=%s\n",
        date('c'),
        $task,
        mb_substr($plain, 0, 300)
    ));
    exit(1);
}

echo sprintf(
    "%s task=%s http=%d bytes=%d sha256=%s result=%s\n",
    date('c'),
    $task,
    $status,
    strlen($body),
    hash('sha256', $body),
    mb_substr($plain, 0, 300)
);
