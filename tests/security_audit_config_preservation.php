<?php
/** Request-time review must preserve configuration, custom files and prior quarantine evidence. */
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/application/middleware/Begin.php';
$temporary = audit_temp_dir('config-preservation');
define('APP_PATH', $temporary . '/application/');
define('RUNTIME_PATH', $temporary . '/runtime/');
mkdir(APP_PATH . 'extra', 0700, true);
mkdir(RUNTIME_PATH, 0700);
$files = [
    'custom-plugin.php' => '<?php return ["custom" => true];',
    'addons.php' => '<?php return ["hooks" => ["base64_decode_label" => "' . str_repeat('plugin-data', 300) . '"]];',
    'addons.php.quarantine.previous' => 'preserved audit evidence',
    'maccms.php' => '<?php return ["fixture" => true];',
    "odd\nentry.txt" => 'custom filename',
];
try {
    foreach ($files as $file => $content) { file_put_contents(APP_PATH . 'extra/' . $file, $content); }
    $called = 0;
    $next = static function ($request) use (&$called) { $called++; return $request; };
    $request = new stdClass();
    $middleware = new app\middleware\Begin();
    check($middleware->handle($request, $next) === $request && $called === 1, 'Review disrupted the request');
    foreach ($files as $file => $content) {
        check(is_file(APP_PATH . 'extra/' . $file) && file_get_contents(APP_PATH . 'extra/' . $file) === $content,
            'Request deleted or overwrote a configuration/evidence file');
    }
    $log = file_get_contents(RUNTIME_PATH . 'security_alert.log');
    check(str_contains($log, 'custom-plugin.php') && str_contains($log, 'addons.php requires inspection'), 'Review signals were lost');
    check(str_contains($log, 'odd\\nentry.txt') && !str_contains($log, "odd\nentry"), 'Filename injected an unstructured log line');
    unlink(RUNTIME_PATH . 'security_alert.log');
    rmdir(RUNTIME_PATH); // Logging failure must not restore destructive fallback behavior.
    check($middleware->handle($request, $next) === $request && $called === 2, 'Unavailable log directory disrupted the request');
    foreach ($files as $file => $content) {
        check(file_get_contents(APP_PATH . 'extra/' . $file) === $content, 'Log failure changed source files');
    }
    echo "Config preservation: {$checks} assertions passed on PHP " . PHP_VERSION . "\n";
} finally { audit_remove_temp($temporary); }
