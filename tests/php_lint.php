<?php
/** Compile maintained PHP sources without loading the application or php.ini.
 * Usage: php tests/php_lint.php [--all] [--json=/path/report.json]
 * --all also inventories vendor, generated files and archived framework copies.
 */
$root = dirname(__DIR__);
$all = in_array('--all', $argv, true);
$reportPath = null;
foreach (array_slice($argv, 1) as $arg) {
    if (str_starts_with($arg, '--json=')) {
        $reportPath = substr($arg, 7);
    } elseif ($arg !== '--all') {
        fwrite(STDERR, "Unknown argument: {$arg}\n");
        exit(2);
    }
}
$skipped = [];
$files = [];
$walk = function (string $dir) use (&$walk, &$files, &$skipped, $root, $all): void {
    foreach (new DirectoryIterator($dir) as $item) {
        if ($item->isDot()) {
            continue;
        }
        $path = $item->getPathname();
        $relative = substr($path, strlen($root) + 1);
        if ($item->isLink()) {
            $skipped[$relative] = 'symbolic link; target is not followed';
            continue;
        }
        if ($item->isDir()) {
            if ($relative === '.git' || $item->getFilename() === 'node_modules') {
                $skipped[$relative] = 'repository metadata or JavaScript dependencies';
                continue;
            }
            if (!$all && (in_array($relative, ['vendor', 'runtime', 'upload'], true)
                || str_starts_with($relative, 'thinkphp_legacy_'))) {
                $skipped[$relative] = 'runtime/dependency/archive; included by --all';
                continue;
            }
            $walk($path);
        } elseif ($item->isFile()) {
            $extension = strtolower($item->getExtension());
            if (in_array($extension, ['php', 'phtml', 'php5', 'inc'], true)) {
                $files[] = $relative;
            } elseif ($extension === '') {
                $handle = fopen($path, 'rb');
                if ($handle === false) {
                    throw new RuntimeException('Cannot read ' . $relative);
                }
                $prefix = fread($handle, 160);
                fclose($handle);
                if (str_starts_with($prefix, '<?php') || preg_match('/^#![^\r\n]*\bphp\b/', $prefix)) {
                    $files[] = $relative;
                }
            }
        }
    }
};
try {
    $walk($root);
    sort($files);
    $results = [];
    $failed = 0;
    foreach ($files as $relative) {
        $pipes = [];
        $process = proc_open(
            [PHP_BINARY, '-n', '-d', 'error_reporting=-1', '-d', 'display_errors=1', '-l', $root . '/' . $relative],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
            $pipes
        );
        if (!is_resource($process)) {
            throw new RuntimeException('Cannot start PHP lint for ' . $relative);
        }
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $exit = proc_close($process);
        $diagnostic = trim(preg_replace('/^No syntax errors detected in .*$/m', '', $output));
        $ok = $exit === 0 && $diagnostic === '';
        $results[] = ['file' => $relative, 'passed' => $ok, 'exit' => $exit,
            'diagnostic' => str_replace($root . '/', '', $diagnostic)];
        if (!$ok) {
            ++$failed;
            fwrite(STDERR, $relative . ': ' . $diagnostic . "\n");
        }
    }
    $report = ['php' => PHP_VERSION, 'scope' => $all ? 'workspace' : 'maintained',
        'checked' => count($files), 'failed' => $failed, 'skipped' => $skipped, 'results' => $results];
    if ($reportPath !== null && file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
        throw new RuntimeException('Cannot write lint report');
    }
    printf("PHP %s: %d files checked, %d failures/diagnostics (%s).\n", PHP_VERSION, count($files), $failed, $report['scope']);
    exit($failed > 0 || count($files) === 0 ? 1 : 0);
} catch (Throwable $error) {
    fwrite(STDERR, "Lint incomplete: " . $error->getMessage() . "\n");
    exit(2);
}
