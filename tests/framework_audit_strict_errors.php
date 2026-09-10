<?php
/** Boot only a disposable minimal app with the real common.php/MacApp/config/app.php. */
declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/vendor/topthink/framework/src/helper.php';

$strict = ($argv[1] ?? 'strict') === 'strict';
$root = sys_get_temp_dir() . '/maccms-framework-errors-' . bin2hex(random_bytes(8)) . '/';
mkdir($root . 'application', 0700, true);
mkdir($root . 'config', 0700, true);
mkdir($root . 'runtime', 0700, true);
copy(dirname(__DIR__) . '/application/common.php', $root . 'application/common.php');
copy(dirname(__DIR__) . '/application/provider.php', $root . 'application/provider.php');
copy(dirname(__DIR__) . '/config/app.php', $root . 'config/app.php');
file_put_contents($root . 'config/cache.php', "<?php return ['default'=>'file','stores'=>['file'=>['type'=>'file']]];");
if ($strict) {
    file_put_contents($root . '.env', "APP_STRICT_PHP_ERRORS = true\n");
}
class AuditDiagnosticLog extends Psr\Log\AbstractLogger {
    public array $messages = [];
    public function log($level, string|Stringable $message, array $context = []): void {
        $this->messages[] = (string)$message;
    }
}
try {
    $app = new app\MacApp($root);
    $app->setAppPath($root . 'application/');
    $app->initialize();
    $logger = new AuditDiagnosticLog();
    $app->instance('log', $logger);
    if ((bool)$app->config->get('app.strict_php_errors') !== $strict) {
        throw new RuntimeException('Strict error setting did not load from the app config/environment');
    }
    if (error_reporting() !== E_ALL || !defined('IS_CLI')) {
        throw new RuntimeException('Real application/common.php must load without disabling diagnostics');
    }
    $caught = 0;
    foreach ([E_USER_WARNING, E_USER_DEPRECATED] as $level) {
        try { trigger_error('audit diagnostic ' . $level, $level); }
        catch (think\exception\ErrorException | ErrorException $e) { ++$caught; }
    }
    if ($strict && $caught !== 2) {
        throw new RuntimeException('Strict mode failed to reject warning/deprecation negative cases');
    }
    if (!$strict && ($caught !== 0 || count($logger->messages) !== 1)) {
        // Production compatibility mode deduplicates diagnostics by source file and line.
        throw new RuntimeException('Compatibility mode must retain diagnostics without throwing');
    }
    echo 'framework_audit_strict_errors: ' . ($strict ? 'strict negatives' : 'default logging') . ' passed on PHP ' . PHP_VERSION . "\n";
} catch (Throwable $e) {
    fwrite(STDERR, get_class($e) . ': ' . $e->getMessage() . PHP_EOL . $e->getTraceAsString() . PHP_EOL);
    $failed = true;
} finally {
    restore_error_handler();
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) {
        if ($file->isDir()) { rmdir($file->getPathname()); } else { unlink($file->getPathname()); }
    }
    rmdir($root);
}

exit(empty($failed) ? 0 : 1);
