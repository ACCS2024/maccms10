<?php
// Per-site configuration remains private to the deployment. Recovery and backups
// serialize parsed data only: a compromised live/shadow file must never execute or spread.
$_live = __DIR__ . '/../application/extra/maccms.php';
$_shadow = __DIR__ . '/../runtime/config-shadow/maccms.php';
$_example = __DIR__ . '/../application/data/config/maccms.example.php';
$_writeData = static function (array $data, string $path): bool {
    if (is_link($path)) { return false; }
    $directory = dirname($path);
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
        return false;
    }
    $temporary = @tempnam($directory, '.config-');
    if ($temporary === false) { return false; }
    try {
        $source = "<?php\nreturn " . var_export($data, true) . ";\n";
        if (@file_put_contents($temporary, $source, LOCK_EX) !== strlen($source)) { return false; }
        @chmod($temporary, 0600);
        return @rename($temporary, $path);
    } finally {
        if (is_file($temporary)) { @unlink($temporary); }
    }
};

if (file_exists($_live) || is_link($_live)) {
    $_config = \app\common\util\DataConfig::read($_live);
} else {
    $_source = file_exists($_shadow) || is_link($_shadow) ? $_shadow : $_example;
    $_config = \app\common\util\DataConfig::read($_source);
    $_writeData($_config, $_live);
}

if (!is_file($_shadow) || (is_file($_live) && @filemtime($_shadow) < @filemtime($_live))) {
    $_writeData($_config, $_shadow);
}
return $_config;
