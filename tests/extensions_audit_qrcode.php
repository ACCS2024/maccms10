<?php
/** Standalone encoder regression; no framework bootstrap or application configuration. */
declare(strict_types=1);

use app\common\util\QRcode;
use app\common\util\QRencode;
use app\common\util\QRimage;
use app\common\util\QRinput;
use app\common\util\QRspec;
use app\common\util\QRtools;

require dirname(__DIR__) . '/application/common/util/Qrcode.php';
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message, 0, $level, $file, $line);
});
$output = getenv('QRCODE_AUDIT_OUTPUT') ?: sys_get_temp_dir() . '/qrcode-audit-' . bin2hex(random_bytes(5));
if (is_dir($output) || !mkdir($output, 0700)) { throw new RuntimeException('Use a fresh QR fixture output directory'); }
$keepOutput = getenv('QRCODE_AUDIT_OUTPUT') !== false;
$checks = 0;
$images = [];
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
};
$reject = static function (callable $call, string $message) use ($check): void {
    $depth = ob_get_level();
    try {
        $call();
    } catch (Exception $expected) {
        $check(!$expected instanceof ErrorException, $message . ' must not emit a PHP warning');
        $check(ob_get_level() === $depth, $message . ' must preserve caller output buffers');
        return;
    }
    throw new RuntimeException($message . ' unexpectedly succeeded');
};
try {
    $reference = json_decode(file_get_contents(__DIR__ . '/fixtures/qrcode_reference.json'), true, 512, JSON_THROW_ON_ERROR);
    $modes = ['numeric' => QR_MODE_NUM, 'alphanumeric' => QR_MODE_AN, 'byte' => QR_MODE_8];
    $levels = ['L' => QR_ECLEVEL_L, 'M' => QR_ECLEVEL_M, 'Q' => QR_ECLEVEL_Q, 'H' => QR_ECLEVEL_H];
    foreach ($reference['cases'] as $case) {
        $data = hex2bin($case['data_hex']);
        $data = str_repeat($data, $case['repeat'] ?? 1);
        $input = new QRinput($case['version'], $levels[$case['level']]);
        $input->append($modes[$case['mode']], strlen($data), str_split($data));
        $code = (new QRcode())->encodeMask($input, $case['mask']);
        $matrix = QRtools::binarize($code->data);
        $check(hash('sha256', implode("\n", $matrix)) === $case['matrix_sha256'],
            'Independent reference mismatch: ' . json_encode([$case['mode'], $case['version'], $case['level'], $case['mask']]));
    }
    $check(QRinput::estimateBitsModeNum(1) === 4 && QRinput::estimateBitsModeNum(2) === 7
        && QRinput::estimateBitsModeNum(3) === 10, 'Numeric bit lengths use integer groups');
    QRspec::newFrame(1);
    $check(QRspec::$frames !== [], 'Frame cache has been populated');
    QRtools::clearCache();
    $check(QRspec::$frames === [], 'clearCache clears the actual QRspec cache');
    $filesBefore = glob($output . '/*');
    $workingDirectory = getcwd();
    chdir($output);
    try { QRtools::buildCache(); } finally { chdir($workingDirectory); }
    $check(glob($output . '/*') === $filesBefore, 'Disabled disk cache does not write cache images');

    mt_srand(20260910); // Keep the library's random mask sampling reproducible in this test only.
    $cases = [
        ['numeric', '012345678901234567890123456789', 'L'],
        ['alphanumeric', 'HELLO WORLD 1234', 'M'],
        ['url', 'https://example.invalid/视频?id=123&name=测试', 'Q'],
        ['multiblock', str_repeat('data-', 30), 'H'],
        ['zero', '0', 'L'],
        ['literal-backslash-zero', '\0', 'M'],
    ];
    foreach ($cases as [$name, $text, $level]) {
        $file = $name . '.png';
        QRcode::png($text, $output . '/' . $file, $level, 6, 4);
        $info = getimagesize($output . '/' . $file);
        $check($info[2] === IMAGETYPE_PNG && $info[0] === $info[1] && $info[0] <= QR_PNG_MAXIMUM_SIZE,
            'Valid square PNG for ' . $name);
        $images[] = ['file' => $file, 'text' => $text];
    }
    $encoder = QRencode::factory('M', 6, 4);
    $encoder->eightbit = true;
    $encoder->encodePNG('强制 byte 模式', $output . '/byte-mode.png');
    $images[] = ['file' => 'byte-mode.png', 'text' => '强制 byte 模式'];
    $kanji = mb_convert_encoding('abcヂ日本語', 'SJIS', 'UTF-8');
    $code = (new QRcode())->encodeString($kanji, 0, QR_ECLEVEL_M, QR_MODE_KANJI, false);
    QRimage::png(QRtools::binarize($code->data), $output . '/kanji.png', 6, 4);
    $images[] = ['file' => 'kanji.png', 'text' => 'ABCヂ日本語', 'encoding' => 'shift_jis'];

    ob_start();
    $depth = ob_get_level();
    QRcode::png('save-and-print', $output . '/save-and-print.png', 'L', 6, 4, true);
    $printed = ob_get_clean();
    $check($printed === file_get_contents($output . '/save-and-print.png') && ob_get_level() === $depth - 1,
        'saveandprint writes and prints the same PNG while preserving caller buffers');
    $images[] = ['file' => 'save-and-print.png', 'text' => 'save-and-print'];
    $matrix = QRcode::text('text-output');
    QRcode::text('text-output', $output . '/matrix.txt');
    $stored = explode("\n", file_get_contents($output . '/matrix.txt'));
    $check(count($stored) === count($matrix) && strspn(implode('', $stored), '01') === count($stored) ** 2,
        'Text output is a square binary matrix');
    $check(QRtools::binarize(QRcode::raw('raw-output')) !== [], 'Raw output remains available');
    $check(count(QRcode::raw(str_repeat('7', 7089))) === 177, 'Maximum numeric capacity remains supported');
    $check((new QRcode())->encodeString8bit(str_repeat('x', 2953), 0, 0)->width === 177, 'Maximum 8-bit capacity remains supported');
    QRimage::jpg($matrix, $output . '/matrix.jpg', 4, 4);
    $check(getimagesize($output . '/matrix.jpg')[2] === IMAGETYPE_JPEG, 'JPEG output remains available');
    QRcode::png('bounded-output', $output . '/bounded.png', 'L', PHP_INT_MAX, 4);
    $check(getimagesize($output . '/bounded.png')[0] <= QR_PNG_MAXIMUM_SIZE, 'Huge requested scale remains bounded');

    $input = new QRinput();
    $input->append(QR_MODE_8, 3, str_split('ABC'));
    $parity = $input->calcParity();
    $check($parity === (ord('A') ^ ord('B') ^ ord('C')), 'Structured append parity uses byte values');
    $check($input->insertStructuredAppendHeader(2, 1, $parity) === 0, 'Structured append header accepts a valid range');
    $header = $input->items[0];
    $header->encodeBitStream(1);
    $check(implode('', $header->bstream->data) === '00110000000101000000', 'Structured header encodes index/count/parity as 20 bits');
    $check($input->calcParity() === $parity, 'Structured headers are excluded from parity');
    $check((new QRinput())->append(QR_MODE_NUM, 1, ['x']) === -1, 'Invalid numeric segment keeps its failure return contract');
    foreach ([['', 'L', 3, 4], [[], 'L', 3, 4], ['data', -1, 3, 4], ['data', [], 3, 4],
        ['data', 'invalid', 3, 4], ['data', 'L', 0, 4], ['data', 'L', 3, -1], ['data', 'L', 3, PHP_INT_MAX],
        [str_repeat('x', 3000), 'L', 3, 4]] as [$text, $level, $size, $margin]) {
        $reject(static fn() => QRcode::png($text, false, $level, $size, $margin), 'Invalid public PNG input');
    }
    foreach ([-1, 41, 1.5] as $version) { $reject(static fn() => new QRinput($version, 0), 'Invalid version'); }
    $reject(static fn() => new QRinput(0, -1), 'Invalid numeric correction level');
    $reject(static fn() => (new QRcode())->encodeString('text', 0, 0, 999, true), 'Invalid mode hint');
    $reject(static fn() => (new QRcode())->encodeString8bit('', 0, 0), 'Empty 8-bit string');
    $reject(static fn() => QRcode::raw(str_repeat('7', 7090)), 'Numeric input beyond version 40 capacity');
    $reject(static fn() => (new QRcode())->encodeString8bit(str_repeat('x', 2954), 0, 0), '8-bit input beyond version 40 capacity');
    $reject(static fn() => (new QRcode())->encodeMask(new QRinput(1, 0), 8), 'Invalid mask');
    foreach ([[0, 1, 0], [2, 3, 0], [2, 1, 256]] as [$size, $index, $parity]) {
        $reject(static fn() => (new QRinput())->insertStructuredAppendHeader($size, $index, $parity), 'Invalid structured header');
    }
    $reject(static fn() => QRcode::png('write-error', $output . '/missing/file.png'), 'PNG destination failure');
    $reject(static fn() => QRcode::text('write-error', $output . '/missing/file.txt'), 'Text destination failure');
    $reject(static fn() => QRimage::png([], $output . '/invalid.png'), 'Empty raw frame');
    $reject(static fn() => QRimage::png(['01', '1'], $output . '/invalid.png'), 'Non-square raw frame');
    $reject(static fn() => QRimage::png(['named' => '0'], $output . '/invalid.png'), 'Non-list raw frame');
    $invalidRenderer = new QRencode();
    $invalidRenderer->margin = -10.5;
    $reject(static fn() => $invalidRenderer->encodePNG('x'), 'Invalid manually configured renderer');
    $reject(static fn() => QRimage::png(['0'], $output . '/invalid.png', PHP_INT_MAX), 'Oversized raw frame');
    file_put_contents($output . '/manifest.json', json_encode(['checks' => $checks, 'php' => PHP_VERSION, 'images' => $images], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    echo "OK {$checks} Qrcode checks on PHP " . PHP_VERSION . "\n";
} finally {
    if (!$keepOutput) {
        foreach (glob($output . '/*') as $file) { unlink($file); }
        rmdir($output);
    }
}
