<?php
/** Configure a fresh disposable checkout after loading the dedicated HTTP fixture database. */
declare(strict_types=1);
$root = dirname(__DIR__);
if (getenv('MAC_AUDIT_FIXTURE') !== '1' || (getenv('DB_NAME') ?: '') !== 'maccms_audit_http') {
    throw new RuntimeException('Explicit MAC_AUDIT_FIXTURE=1 and DB_NAME=maccms_audit_http are required');
}
foreach (['.env', 'application/extra/maccms.php', 'application/data/install/install.lock'] as $file) {
    if (file_exists($root . '/' . $file)) { throw new RuntimeException('Fixture requires a fresh checkout: ' . $file); }
}
$values = ['DB_HOST' => getenv('DB_HOST') ?: '127.0.0.1', 'DB_NAME' => 'maccms_audit_http',
    'DB_USER' => getenv('DB_USER') ?: 'root', 'DB_PASS' => getenv('DB_PASS') ?: 'audit-fixture'];
$env = "APP_DEBUG = false\nAPP_STRICT_PHP_ERRORS = true\n";
foreach ($values as $name => $value) {
    if (!preg_match('/\A[A-Za-z0-9_.:-]+\z/D', $value)) { throw new RuntimeException('Use simple fixture-only credentials'); }
    $env .= $name . ' = ' . $value . "\n";
}
$config = include $root . '/application/data/config/maccms.example.php';
$config['site']['site_name'] = 'AuditFixture';
$config['site']['site_url'] = '127.0.0.1';
$config['site']['site_status'] = '1';
$config['site']['install_dir'] = '/';
$config['site']['template_dir'] = 'default';
$config['site']['html_dir'] = 'html';
$config['app']['admin_login_verify'] = '0';
$config['app']['search_verify'] = '0';
$config['user']['login_verify'] = '0';
$config['user']['reg_verify'] = '0';
foreach ($config['api'] as &$section) {
    if (is_array($section)) { $section['status'] = '1'; $section['charge'] = '0'; $section['typefilter'] = ''; }
}
unset($section);
$files = ['.env' => $env, 'application/extra/maccms.php' => '<?php return ' . var_export($config, true) . ';',
    'application/data/install/install.lock' => "disposable audit fixture\n"];
foreach ($files as $file => $content) {
    $path = $root . '/' . $file;
    if (!is_dir(dirname($path)) && !mkdir(dirname($path), 0755, true)) { throw new RuntimeException('Cannot create fixture directory'); }
    if (file_put_contents($path, $content, LOCK_EX) !== strlen($content)) { throw new RuntimeException('Cannot write fixture: ' . $file); }
}
echo "Configured the disposable HTTP fixture with strict PHP diagnostics.\n";
