<?php

require dirname(__DIR__) . '/application/common/util/PpvodLegacyPayload.php';

use app\common\util\PpvodLegacyPayload;

function assertSameValue($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, $message . PHP_EOL);
        fwrite(STDERR, 'Expected: ' . var_export($expected, true) . PHP_EOL);
        fwrite(STDERR, 'Actual:   ' . var_export($actual, true) . PHP_EOL);
        exit(1);
    }
}

assertSameValue(false, PpvodLegacyPayload::enabled([]), 'Legacy mode must default to disabled');
assertSameValue(false, PpvodLegacyPayload::enabled(['legacy_compat' => '0']), 'Explicit zero must stay disabled');
assertSameValue(true, PpvodLegacyPayload::enabled(['legacy_compat' => '1']), 'Explicit one must enable legacy mode');

$payload = [
    'domain' => 'https://play.example.test',
    'picdomain' => 'http://pic.example.test',
    'mp4domain' => '',
    'rpath' => '\\2026\\08\\video-id',
    'path' => 'part001',
    'shareid' => 'share001',
    'category' => 'known',
];
$config = [
    'legacy_compat' => '1',
    'play_domain' => 'https://fixed-play.example.test',
    'pic_domain' => 'https://fixed-pic.example.test',
    'play_name' => 'Online',
    'addr_mode' => 'all',
    'legacy_fallback_type_id' => '20',
];
$result = PpvodLegacyPayload::build($payload, $config, ['status' => 1], ['known' => 7]);

assertSameValue('/2026/08/video-id', $result['video_path'], 'Backslash path normalization changed');
assertSameValue('http://pic.example.test/2026/08/video-id/1.jpg', $result['vod_pic'], 'Legacy picture URL changed');
assertSameValue(
    'Online$https://play.example.test/2026/08/video-id/index.m3u8$$$Online$https://play.example.test/share/share001',
    $result['vod_play_url'],
    'Legacy all-mode play URL changed'
);
assertSameValue('https://play.example.test/2026/08/video-id/mp4/part001.mp4', $result['vod_down_url'], 'MP4 fallback URL changed');
assertSameValue(1, $result['vod_status'], 'Legacy mode must use collect status');
assertSameValue(7, $result['type_id'], 'Known category mapping changed');

$payload['category'] = 'unknown';
$payload['mp4domain'] = 'https://download.example.test';
$config['addr_mode'] = 'share';
$result = PpvodLegacyPayload::build($payload, $config, ['status' => 0], []);
assertSameValue('Online$https://play.example.test/share/share001', $result['vod_play_url'], 'Legacy share mode changed');
assertSameValue('https://download.example.test/2026/08/video-id/mp4/part001.mp4', $result['vod_down_url'], 'Explicit MP4 domain changed');
assertSameValue(20, $result['type_id'], 'Unknown category fallback changed');

foreach ([
    ['domain', 'javascript:alert(1)'],
    ['rpath', '/../escape'],
    ['shareid', 'bad/value'],
] as [$field, $badValue]) {
    $bad = $payload;
    $bad[$field] = $badValue;
    try {
        PpvodLegacyPayload::build($bad, $config, ['status' => 1], []);
        fwrite(STDERR, 'Unsafe field was accepted: ' . $field . PHP_EOL);
        exit(1);
    } catch (InvalidArgumentException $e) {
        assertSameValue($field, $e->getMessage(), 'Rejected field name changed');
    }
}

echo "PPVOD legacy compatibility tests OK\n";
