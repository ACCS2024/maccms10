<?php
/** Shared assertions and temporary-file cleanup; no application initialization. */
error_reporting(E_ALL);
set_error_handler(static function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) { return false; }
    throw new ErrorException($message, 0, $severity, $file, $line);
});
$checks = 0;
function check($ok, string $message): void
{
    $GLOBALS['checks']++;
    if (!$ok) { throw new RuntimeException($message); }
}
function audit_temp_dir(string $scope): string
{
    $path = sys_get_temp_dir() . '/maccms-audit-' . $scope . '-' . bin2hex(random_bytes(8));
    mkdir($path, 0700);
    return $path;
}
function audit_remove_temp(string $path): void
{
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $file) {
        if ($file->isDir() && !$file->isLink()) { rmdir($file->getPathname()); }
        else { unlink($file->getPathname()); }
    }
    rmdir($path);
}
