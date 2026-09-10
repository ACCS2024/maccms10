<?php
/** Exercise the real CSV download and import boundary with ordinary text values. */
declare(strict_types=1);
require dirname(__DIR__) . '/application/common/util/BulkTableIo.php';
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;

function csvRoundtripRows(): array
{
    $values = ['', '0', '普通标题', 'emoji 😀', ' leading and trailing ', 'one,two',
        "first\nsecond", "first\r\nsecond", '"double quotes"', 'C:\\', 'dir name\\',
        'quote\\"inside', '\\', 'ordinary'];
    foreach (range(1, 4) as $length) {
        $slashes = str_repeat('\\', $length);
        foreach ([$slashes, '"' . $slashes, $slashes . '"', 'a,' . $slashes . '"z',
            "line\n" . $slashes] as $value) {
            $values[] = $value;
        }
    }
    return array_map(static fn($value) => ['name' => $value, 'next' => 'tail'], $values);
}

if (($argv[1] ?? '') === '--download') {
    BulkTableIo::exportCsvDownload('ordinary', ['name', 'next'], csvRoundtripRows());
    exit;
}

$temporary = audit_temp_dir('csv-roundtrip');
try {
    $path = $temporary . '/download.csv';
    $process = proc_open([PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=stderr',
        __FILE__, '--download'], [0 => ['file', '/dev/null', 'r'],
        1 => ['file', $path, 'w'], 2 => ['pipe', 'w']], $pipes);
    check(is_resource($process), 'The real CSV download process must start');
    $errors = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    check(proc_close($process) === 0 && $errors === '', 'CSV download must finish without PHP diagnostics');
    $download = file_get_contents($path);
    check(str_starts_with($download, "\xEF\xBB\xBF"), 'CSV download keeps its UTF-8 BOM');
    $result = BulkTableIo::parseFile($path, 'csv');
    check($result['headers'] === ['name', 'next'], 'Actual import keeps header order');
    check(count($result['rows']) === count(csvRoundtripRows()), 'Backslashes must not merge exported records');
    foreach (csvRoundtripRows() as $index => $row) {
        check($result['rows'][$index] === $row, 'Every ordinary cell must survive export/import byte for byte');
    }
    // Independently supplied CSV uses doubled quotes and literal backslashes.
    $standard = "name,next\r\n\"C:\\\",tail\r\n\"a\"\"b\",tail\r\n\"line1\nline2\",tail\r\n";
    file_put_contents($path, $standard);
    check(BulkTableIo::parseFile($path, 'txt')['rows'] === [
        ['name' => 'C:\\', 'next' => 'tail'], ['name' => 'a"b', 'next' => 'tail'],
        ['name' => "line1\nline2", 'next' => 'tail'],
    ], 'Standard external CSV must keep literal backslashes, doubled quotes and multiline cells');
    echo 'CSV download/import roundtrip: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . "\n";
} finally {
    audit_remove_temp($temporary);
}
