<?php
/** Configuration files, including recovery shadows, must remain data rather than execute PHP. */
declare(strict_types=1);
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/application/common/util/DataConfig.php';

use app\common\util\DataConfig;

function rejectsData(callable $operation, string $message): void
{
    try { $operation(); } catch (RuntimeException $error) { check(true, $message); return; }
    check(false, $message);
}

$temporary = audit_temp_dir('data-config');
$repository = dirname(__DIR__);
try {
    $values = [
        [], ['autoload' => false, 'hooks' => ['view_filter' => ['aicontent']], 'route' => []],
        ['url' => 'https://example.invalid/?a=1&b=2', 'secret' => "quote' slash\\ line\n NUL\0 end"],
        ['nested' => [0, -1, PHP_INT_MIN, PHP_INT_MAX, 1.25, 1.0e-100, true, false, null]],
        ['text' => 'base64_decode; eval; file_put_contents are ordinary labels in data', '中文' => '中文'],
    ];
    for ($i = 0; $i < 64; $i++) { $values[] = ['bytes' => random_bytes(32), 'id' => $i]; }
    foreach ($values as $expected) {
        check(DataConfig::parse("<?php\nreturn " . var_export($expected, true) . ";\n") === $expected,
            'Legacy var_export configuration changed meaning');
    }
    check(DataConfig::parse('<?php /* comment */ return ["escaped" => "a\\nb\\t\\x41\\101\\$", "unknown" => "a\\qb"]; ?>' . "\n")
        === ['escaped' => "a\nb\tAA$", 'unknown' => 'a\qb'], 'String escape or close tag compatibility failed');
    check(DataConfig::parse('<?php return [0o77, -0o77, 077, 0xff, 0b110, 1_000, 00.5, 01e2];')
        === [0o77, -0o77, 077, 0xff, 0b110, 1_000, 00.5, 01e2], 'Numeric literal meaning changed');
    check(DataConfig::parse('<?php return ["\\u{4e2d}\\u{6587}\\u{1f600}"];') === ['中文😀'], 'Unicode literal escapes changed meaning');
    $marker = $temporary . '/executed';
    $call = 'file_put_contents(' . var_export($marker, true) . ', "executed")';
    $bad = [
        '<?php ' . $call . '; return [];',
        '<?php return []; ' . $call . ';',
        '<?php return [' . $call . '];',
        '<?php return ["key" => (' . $call . ')];',
        '<?php return [fn() => ' . $call . '];',
        '<?php return [new stdClass];',
        '<?php return [$_SERVER];',
        '<?php return ["${' . $call . '}"];',
        '<?php return ["a" . ' . $call . '];',
        '<?php return include "payload.php";',
        '<?php return [base64_decode("YQ==")];',
        '<?php think\\Hook::add("view_filter", "attacker"); return [];',
        '<?php return []; ?> <script>attacker()</script>',
        '<?php return ["a" => 1 + 2];',
        '<?php return [UNKNOWN_CONSTANT];',
        '<?php return [NAN];',
        '<?php return [1e10000];',
        '<?php return [0xFFFFFFFFFFFFFFFF];',
        '<?php return 1;',
        '<?php return [;',
        'not PHP',
    ];
    foreach ($bad as $source) {
        rejectsData(fn () => DataConfig::parse($source), 'Executable or malformed configuration was accepted');
        check(!file_exists($marker), 'Configuration payload executed while being inspected');
    }
    rejectsData(fn () => DataConfig::parse('<?php return ' . str_repeat('[', 70) . '0' . str_repeat(']', 70) . ';'), 'Unbounded nesting accepted');
    rejectsData(fn () => DataConfig::parse('<?php return ["' . str_repeat('a', 8388608) . '"];'), 'Unbounded source accepted');
    check(DataConfig::read($temporary . '/absent.php') === [], 'Optional absent configuration must be empty');
    rejectsData(fn () => DataConfig::read('data://text/plain,' . rawurlencode('<?php return [];')), 'PHP stream wrapper accepted');
    rejectsData(fn () => DataConfig::read($temporary), 'Directory accepted as configuration');
    file_put_contents($temporary . '/safe.php', '<?php return ["safe" => true];');
    symlink($temporary . '/safe.php', $temporary . '/linked.php');
    rejectsData(fn () => DataConfig::read($temporary . '/linked.php'), 'Symlink configuration accepted');

    // Exercise the shipped loader stubs in a disposable application, with actual malicious files.
    foreach (['config', 'application/extra', 'application/data/config', 'runtime/config-shadow'] as $dir) {
        mkdir($temporary . '/' . $dir, 0700, true);
    }
    $stubs = ['addons', 'bind', 'blacks', 'cache', 'captcha', 'domain', 'maccms', 'mctheme', 'quickmenu', 'session', 'timming', 'version', 'voddowner', 'vodplayer', 'vodserver'];
    foreach ($stubs as $name) { copy($repository . '/config/' . $name . '.php', $temporary . '/config/' . $name . '.php'); }
    $load = static fn ($name) => include $temporary . '/config/' . $name . '.php';
    foreach ($stubs as $name) {
        $file = $temporary . '/application/extra/' . (in_array($name, ['cache', 'session'], true) ? 'maccms' : $name) . '.php';
        file_put_contents($file, '<?php ' . $call . '; return [];');
        rejectsData(fn () => $load($name), 'A shipped configuration loader executed PHP: ' . $name);
        check(!file_exists($marker), 'Loader side effect escaped');
        unlink($file);
    }

    $live = $temporary . '/application/extra/maccms.php';
    $shadow = $temporary . '/runtime/config-shadow/maccms.php';
    $example = $temporary . '/application/data/config/maccms.example.php';
    file_put_contents($shadow, '<?php ' . $call . '; return ["old" => true];');
    file_put_contents($example, '<?php return ["example" => true];');
    rejectsData(fn () => $load('maccms'), 'Compromised shadow must not silently recover');
    check(!file_exists($live) && !file_exists($marker), 'Recovery propagated or executed compromised shadow');
    $original = file_get_contents($shadow);
    file_put_contents($live, '<?php ' . $call . '; return ["live" => true];');
    rejectsData(fn () => $load('maccms'), 'Compromised live file must fail closed');
    check(file_get_contents($shadow) === $original, 'Invalid live configuration polluted its recovery shadow');
    unlink($live);
    file_put_contents($shadow, '<?php /* do not propagate raw bytes */ return ["private" => "kept"];');
    check($load('maccms') === ['private' => 'kept'] && DataConfig::read($live) === ['private' => 'kept'], 'Valid site shadow did not recover');
    check(!str_contains(file_get_contents($live), 'do not propagate'), 'Recovery copied raw PHP instead of serializing data');
    unlink($live); unlink($shadow);
    check($load('maccms') === ['example' => true], 'Fresh install defaults did not seed');
    check(DataConfig::read($shadow) === ['example' => true], 'Safe shadow was not generated');

    foreach (array_merge(glob($repository . '/application/extra/*.php'), glob($repository . '/addons/*/config.php')) as $file) {
        check(is_array(DataConfig::read($file)), 'Shipped configuration is incompatible: ' . basename($file));
    }
    echo "Data configuration: {$checks} assertions passed on PHP " . PHP_VERSION . "\n";
} finally { audit_remove_temp($temporary); }
