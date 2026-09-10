<?php
/** Exercise real CSV export/import under E_ALL without database or application bootstrap. */
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/application/common/util/BulkTableIo.php';
use app\common\util\BulkTableIo;
$rows = [
    ['name' => '标题, "引号"', 'note' => "line one\nline two"],
    ['name' => 'plain', 'note' => 'C:\folder\file'],
];
ob_start();
BulkTableIo::exportCsvDownload('audit', ['name', 'note'], $rows);
$csv = ob_get_clean();
$file = tempnam(sys_get_temp_dir(), 'audit-csv-');
try {
    check(str_starts_with($csv, "\xEF\xBB\xBF"), 'CSV export must preserve its UTF-8 BOM');
    file_put_contents($file, $csv);
    check(BulkTableIo::parseCsv($file) === ['headers' => ['name', 'note'], 'rows' => $rows], 'CSV round trip lost quotes, backslashes or multiline data');
    file_put_contents($file, '');
    check(BulkTableIo::parseCsv($file) === ['headers' => [], 'rows' => []], 'Empty CSV must parse without diagnostics');
    echo 'CSV regressions: ' . $checks . " assertions passed\n";
} finally { unlink($file); }
