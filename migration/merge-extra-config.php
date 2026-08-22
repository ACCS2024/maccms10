<?php

declare(strict_types=1);

/**
 * Merge data-only MacCMS configuration exported as JSON into a clean code tree.
 *
 * The source host should evaluate its own trusted array config and export JSON.
 * This tool never includes PHP copied from the source host.
 */

const CONFIG_ALLOWLIST = [
    'maccms',
    'vodplayer',
    'voddowner',
    'vodserver',
    'domain',
    'bind',
    'blacks',
    'captcha',
    'timming',
    'quickmenu',
    'queue',
    'type_synonyms',
];

function fail(string $message): never
{
    fwrite(STDERR, "[fail] {$message}\n");
    exit(1);
}

function logLine(string $message): void
{
    fwrite(STDOUT, "[config] {$message}\n");
}

function readArrayConfig(string $path): array
{
    if (!is_file($path) || !is_readable($path)) {
        fail("target config is not readable: {$path}");
    }

    $value = (static function (string $file): mixed {
        return require $file;
    })($path);

    if (!is_array($value)) {
        fail("target config did not return an array: {$path}");
    }

    return $value;
}

function nestedValue(array $data, array $path, bool &$exists): mixed
{
    $cursor = $data;
    foreach ($path as $key) {
        if (!is_array($cursor) || !array_key_exists($key, $cursor)) {
            $exists = false;
            return null;
        }
        $cursor = $cursor[$key];
    }
    $exists = true;
    return $cursor;
}

function setNestedValue(array &$data, array $path, mixed $value): void
{
    $cursor = &$data;
    $last = array_pop($path);
    foreach ($path as $key) {
        if (!isset($cursor[$key]) || !is_array($cursor[$key])) {
            $cursor[$key] = [];
        }
        $cursor = &$cursor[$key];
    }
    $cursor[$last] = $value;
}

function preservePaths(array $target, array &$merged, array $paths): void
{
    foreach ($paths as $path) {
        $exists = false;
        $value = nestedValue($target, $path, $exists);
        if ($exists) {
            setNestedValue($merged, $path, $value);
        }
    }
}

function parseEnvFile(string $path): array
{
    if (!is_file($path) || !is_readable($path)) {
        fail("environment file is not readable: {$path}");
    }

    $result = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $result[trim($key)] = trim($value, " \t\n\r\0\x0B\"'");
    }
    return $result;
}

function writeConfigAtomically(string $path, array $config): void
{
    $stat = stat($path);
    if ($stat === false) {
        fail("cannot stat target config: {$path}");
    }

    $body = "<?php\nreturn " . var_export($config, true) . ";\n";
    $tmp = tempnam(dirname($path), '.merge-');
    if ($tmp === false) {
        fail("cannot create temporary file beside {$path}");
    }

    try {
        if (file_put_contents($tmp, $body, LOCK_EX) === false) {
            fail("cannot write temporary config: {$tmp}");
        }
        chmod($tmp, $stat['mode'] & 0777);
        chown($tmp, $stat['uid']);
        chgrp($tmp, $stat['gid']);

        $output = [];
        $code = 0;
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $output, $code);
        if ($code !== 0) {
            fail("generated config failed php -l: " . implode("\n", $output));
        }

        if (!rename($tmp, $path)) {
            fail("cannot replace target config: {$path}");
        }
    } finally {
        if (is_file($tmp)) {
            unlink($tmp);
        }
    }
}

$options = getopt('', [
    'source-json:',
    'target-dir:',
    'backup-dir:',
    'dragonfly-password-file::',
    'meili-env::',
    'meili-index-uid::',
    'dry-run',
]);

$sourcePath = $options['source-json'] ?? '';
$targetDir = rtrim($options['target-dir'] ?? '', '/');
$backupDir = rtrim($options['backup-dir'] ?? '', '/');
$dryRun = array_key_exists('dry-run', $options);

if ($sourcePath === '' || $targetDir === '' || $backupDir === '') {
    fail('usage: php merge-extra-config.php --source-json=... --target-dir=... --backup-dir=... [--dragonfly-password-file=...] [--meili-env=...] [--meili-index-uid=...] [--dry-run]');
}
if (!is_file($sourcePath) || !is_readable($sourcePath)) {
    fail("source JSON is not readable: {$sourcePath}");
}
if (!is_dir($targetDir)) {
    fail("target directory does not exist: {$targetDir}");
}

try {
    $source = json_decode((string) file_get_contents($sourcePath), true, 512, JSON_THROW_ON_ERROR);
} catch (JsonException $e) {
    fail('invalid source JSON: ' . $e->getMessage());
}
if (!is_array($source)) {
    fail('source JSON must be an object of config-name => array');
}

$prepared = [];
foreach (CONFIG_ALLOWLIST as $name) {
    if (!array_key_exists($name, $source)) {
        continue;
    }
    if (!is_array($source[$name])) {
        fail("source config {$name} is not an array");
    }

    $targetPath = "{$targetDir}/{$name}.php";
    if (!is_file($targetPath)) {
        logLine("skip {$name}.php: clean tree has no matching config");
        continue;
    }

    $target = readArrayConfig($targetPath);
    $merged = array_replace_recursive($target, $source[$name]);

    if ($name === 'maccms') {
        preservePaths($target, $merged, [
            ['db'],
            // The clean code tree owns its themes. Importing a legacy theme selector
            // without importing legacy PHP/templates makes the new site return 500.
            ['site', 'template_dir'],
            ['site', 'html_dir'],
            ['site', 'mob_template_dir'],
            ['site', 'mob_html_dir'],
            ['site', 'ads_dir'],
            ['site', 'mob_ads_dir'],
            ['site', 'new_version'],
            ['app', 'cache_flag'],
            ['app', 'api_jwt_secret'],
            ['app', 'admin_audit_crypto_secret'],
        ]);

        $dragonflyFile = $options['dragonfly-password-file'] ?? '';
        if ($dragonflyFile !== '') {
            $dragonflyPassword = trim((string) file_get_contents($dragonflyFile));
            if ($dragonflyPassword === '') {
                fail("Dragonfly password file is empty: {$dragonflyFile}");
            }
            $merged['app']['cache_type'] = 'redis';
            $merged['app']['cache_host'] = '127.0.0.1';
            $merged['app']['cache_port'] = '6379';
            $merged['app']['cache_username'] = '';
            $merged['app']['cache_password'] = $dragonflyPassword;
            $merged['app']['cache_db'] = '0';
            $merged['app']['session_type'] = 'redis';
        }

        $meiliEnvFile = $options['meili-env'] ?? '';
        if ($meiliEnvFile !== '') {
            $meili = parseEnvFile($meiliEnvFile);
            $masterKey = $meili['MEILI_MASTER_KEY'] ?? '';
            if ($masterKey === '') {
                fail("MEILI_MASTER_KEY is missing from {$meiliEnvFile}");
            }
            $merged['meilisearch']['enabled'] = '1';
            $merged['meilisearch']['host'] = 'http://127.0.0.1:7700';
            $merged['meilisearch']['api_key'] = $masterKey;
            $indexUid = trim((string) ($options['meili-index-uid'] ?? ''));
            if ($indexUid !== '') {
                if (!preg_match('/^[A-Za-z0-9_-]+$/', $indexUid)) {
                    fail('Meilisearch index UID may only contain letters, numbers, underscores, and hyphens');
                }
                $merged['meilisearch']['index_uid'] = $indexUid;
            } else {
                $merged['meilisearch']['index_uid'] = $merged['meilisearch']['index_uid'] ?? 'maccms_contents';
            }
            $merged['meilisearch']['ssl_verify'] = '0';
        }
    }

    $prepared[$name] = ['path' => $targetPath, 'config' => $merged];
}

if ($prepared === []) {
    fail('no allowlisted source configs matched the clean target tree');
}

if ($dryRun) {
    logLine('dry-run: would merge ' . implode(', ', array_keys($prepared)));
    logLine('dry-run: database config and fresh security secrets remain unchanged');
    exit(0);
}

if (file_exists($backupDir)) {
    fail("backup directory already exists: {$backupDir}");
}
if (!mkdir($backupDir, 0700, true) && !is_dir($backupDir)) {
    fail("cannot create backup directory: {$backupDir}");
}
chmod($backupDir, 0700);

foreach ($prepared as $name => $item) {
    $backupPath = "{$backupDir}/{$name}.php";
    if (!copy($item['path'], $backupPath)) {
        fail("cannot back up {$item['path']}");
    }
    chmod($backupPath, 0600);
}

foreach ($prepared as $name => $item) {
    writeConfigAtomically($item['path'], $item['config']);
    logLine("merged {$name}.php");
}

logLine("backup={$backupDir}");
logLine('database config and fresh security secrets preserved');
logLine('secret values were not printed');
