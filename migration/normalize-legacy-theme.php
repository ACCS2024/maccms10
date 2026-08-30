<?php

declare(strict_types=1);

/**
 * Normalize a legacy (TP5-era) MacCMS theme so it compiles under ThinkPHP 8.
 *
 * Background — the `|date=...,###` trap
 * -------------------------------------
 * think-template v3 (shipped with TP8) grew a dedicated `date` branch in
 * Template::parseVarFunction() that runs *before* the generic `###` placeholder
 * substitution:
 *
 *     case 'date':
 *         $name = 'date(' . $args[1] . ',!is_numeric(' . $name . ')? strtotime(' . $name . ') : ' . $name . ')';
 *
 * For the classic MacCMS idiom `{$vo.vod_time|date='Y-m-d',###}` the argument
 * string is `'Y-m-d',###`, so the compiler emits
 *
 *     date('Y-m-d',###,!is_numeric($vo['vod_time'])? ... )
 *
 * and the literal `###` never gets replaced — the compiled template is a PHP
 * parse error and every page using it returns 500. Under TP5 there was no
 * `date` special case, so the generic branch replaced `###` and it worked.
 *
 * Dropping the now-redundant `,###` produces byte-identical output, because the
 * `date` branch already substitutes the variable itself.
 *
 * Only `date` is affected. Other filters (`str_replace`, `explode`, …) still go
 * through the generic branch, where `###` is substituted correctly — those are
 * left untouched on purpose.
 *
 * Usage:
 *   php migration/normalize-legacy-theme.php --theme-dir=/path/to/template/xxx [--dry-run] [--backup-dir=...]
 */

const TEMPLATE_EXTENSIONS = ['html', 'htm', 'tpl'];

function fail(string $message): never
{
    fwrite(STDERR, "[fail] {$message}\n");
    exit(1);
}

function logLine(string $message): void
{
    fwrite(STDOUT, "[theme] {$message}\n");
}

/**
 * Rewrite `|date=<quoted format>,###` to `|date=<quoted format>`.
 *
 * The `###` is only stripped when it is the final argument of a `date` filter,
 * so `{$x|date='Y-m-d',###|foo}` keeps its trailing pipe segment intact.
 */
function normalizeContent(string $content, int &$hits): string
{
    $pattern = '/(\|\s*date\s*=\s*(?:\'[^\']*\'|"[^"]*"))\s*,\s*###/i';

    return preg_replace_callback($pattern, static function (array $m) use (&$hits): string {
        $hits++;
        return $m[1];
    }, $content) ?? $content;
}

$options = getopt('', ['theme-dir:', 'backup-dir::', 'dry-run']);
$themeDir = rtrim($options['theme-dir'] ?? '', '/');
$backupDir = rtrim($options['backup-dir'] ?? '', '/');
$dryRun = array_key_exists('dry-run', $options);

if ($themeDir === '') {
    fail('usage: php normalize-legacy-theme.php --theme-dir=... [--backup-dir=...] [--dry-run]');
}
if (!is_dir($themeDir)) {
    fail("theme directory does not exist: {$themeDir}");
}

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($themeDir, FilesystemIterator::SKIP_DOTS)
);

$changed = [];
$totalHits = 0;
$scanned = 0;

foreach ($iterator as $file) {
    if (!$file->isFile()) {
        continue;
    }
    if (!in_array(strtolower($file->getExtension()), TEMPLATE_EXTENSIONS, true)) {
        continue;
    }

    $scanned++;
    $path = $file->getPathname();
    $original = (string) file_get_contents($path);

    $hits = 0;
    $normalized = normalizeContent($original, $hits);
    if ($hits === 0 || $normalized === $original) {
        continue;
    }

    $totalHits += $hits;
    $changed[$path] = $hits;
}

logLine(sprintf('scanned %d template files, %d files need %d rewrites', $scanned, count($changed), $totalHits));

if ($changed === []) {
    logLine('nothing to do');
    exit(0);
}

foreach ($changed as $path => $hits) {
    logLine(sprintf('  %-4d %s', $hits, substr($path, strlen($themeDir) + 1)));
}

if ($dryRun) {
    logLine('dry-run: no files written');
    exit(0);
}

if ($backupDir !== '') {
    if (!is_dir($backupDir) && !mkdir($backupDir, 0750, true) && !is_dir($backupDir)) {
        fail("cannot create backup directory: {$backupDir}");
    }
}

foreach (array_keys($changed) as $path) {
    $original = (string) file_get_contents($path);

    if ($backupDir !== '') {
        $relative = substr($path, strlen($themeDir) + 1);
        $target = $backupDir . '/' . $relative;
        $targetDir = dirname($target);
        if (!is_dir($targetDir) && !mkdir($targetDir, 0750, true) && !is_dir($targetDir)) {
            fail("cannot create backup directory: {$targetDir}");
        }
        if (file_put_contents($target, $original) === false) {
            fail("cannot write backup: {$target}");
        }
    }

    $hits = 0;
    $normalized = normalizeContent($original, $hits);

    $perms = fileperms($path);
    $owner = fileowner($path);
    $group = filegroup($path);

    if (file_put_contents($path, $normalized) === false) {
        fail("cannot write: {$path}");
    }
    if ($perms !== false) {
        @chmod($path, $perms & 0777);
    }
    if ($owner !== false) {
        @chown($path, $owner);
    }
    if ($group !== false) {
        @chgrp($path, $group);
    }
}

logLine(sprintf('rewrote %d occurrences across %d files', $totalHits, count($changed)));
if ($backupDir !== '') {
    logLine("originals backed up to {$backupDir}");
}
