<?php
/** Runs inside a disposable Apache container whose document root contains only artificial fixtures. */
declare(strict_types=1);
if (!str_contains((string)@file_get_contents('/var/www/html/.env'), 'PRIVATE_FIXTURE_SENTINEL')) {
    throw new RuntimeException('Only the fake document root is allowed');
}
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message, 0, $level, $file, $line);
});
$checks = 0;
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
};
$request = static function (string $path, ?array $post = null, bool $head = false): array {
    $headers = [];
    $curl = curl_init('http://127.0.0.1' . $path);
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROXY => '', CURLOPT_TIMEOUT => 5, CURLOPT_PATH_AS_IS => true,
        CURLOPT_HTTPHEADER => ['Authorization: Bearer fixture-token'],
        CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$headers): int {
            if (str_contains($line, ':')) { [$name, $value] = explode(':', $line, 2); $headers[strtolower($name)] = trim($value); }
            return strlen($line);
        }]);
    if ($post !== null) { curl_setopt_array($curl, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => http_build_query($post)]); }
    if ($head) { curl_setopt($curl, CURLOPT_NOBODY, true); }
    $body = curl_exec($curl);
    $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);
    if ($body === false) { throw new RuntimeException('Loopback request failed: ' . $path); }
    return [$status, $body, $headers];
};
if (($argv[1] ?? '') === 'baseline') {
    foreach (['/.env', '/.git/config', '/composer.lock', '/application/fixture.txt', '/runtime/session/example'] as $path) {
        [$status, $body] = $request($path);
        $check($status === 200 && $body === 'PRIVATE_FIXTURE_SENTINEL', 'Baseline exposes only the fake private fixture: ' . $path);
    }
    foreach (['/upload/payload.php', '/upload/override/masquerade.jpg'] as $path) {
        [$status, $body] = $request($path);
        $check($status === 200 && $body === 'UPLOAD_EXECUTED', 'Baseline executes only the harmless uploaded sentinel: ' . $path);
    }
    $check($request('/pretty/route')[0] === 404, 'Baseline lacks application route rewriting');
    echo "OK {$checks} original Apache boundary reproductions on PHP " . PHP_VERSION . "\n";
    exit;
}
foreach (['/.env', '/%2eenv', '/.env.backup', '/.git/config', '/.git/HEAD', '/.%67it/config', '/composer.lock',
    '/composer.json', '/composer.phar', '/README.md', '/think', '/security_check.php', '/security_check.php/path',
    '/backup.zip', '/backup/config.txt', '/application/extra/example.php', '/application/fixture.txt',
    '/%61pplication/fixture.txt', '/APPLICATION/fixture.txt', '/runtime/session/example', '/vendor/package/source.css',
    '/config/example.txt', '/extend/example.js', '/migration/example.txt', '/docker/example.txt', '/tests/example.txt',
    '/tools/example.txt', '/route/example.txt', '/docs/example.txt', '/deploy/example.txt', '/thinkphp_legacy_20260618/example.txt',
    '/template/audit/settings.php', '/template/audit/settings.json', '/template/audit/html/view.html',
    '/addons/audit/config.php', '/addons/audit/info.ini', '/addons/audit/view/private.html', '/static_new/app.js.bak',
    '/upload/leak.sql', '/upload/shell.php.jpg', '/upload/payload.php', '/upload/payload.PHP', '/upload/payload.php8',
    '/upload/payload.phtml', '/upload/payload.phar', '/upload/payload.phps', '/upload/payload.cgi', '/upload/payload.shtml',
    '/upload/payload.php/anything.jpg', '/upload/payload.php%2fanything.jpg', '/upload/../application/fixture.txt',
    '/upload/%2e%2e/application/fixture.txt', '/upload/linked-env.jpg', '/static_new/linked-internal/fixture.txt',
    '/upload/override/.htaccess', '/static_new/empty/', '/template/audit/assets/source.php.css', '/template/audit/assets/source.sql.css', '/upload/secret.ini.txt',
    '/template/audit/asset/language/private.properties', '/template/audit/asset/language/strings_zh.properties.bak',
    '/template/audit/asset/language/strings_zh.properties.php', '/template/audit/settings.properties', '/upload/strings_zh.properties',
    '/template/linked/asset/language/strings_zh.properties', '/template/audit/asset/language/strings_zh.properties/path'] as $path) {
    [$status, $body] = $request($path);
    $check(in_array($status, [403, 404], true), 'Private/source path must be rejected: ' . $path . ' status=' . $status . ' body=' . substr($body, 0, 500));
    $check(!str_contains($body, 'PRIVATE_FIXTURE_SENTINEL') && !str_contains($body, 'UPLOAD_EXECUTED'),
        'Denied response must not contain private data or execute an uploaded script: ' . $path);
}
[$status, $body] = $request('/upload/override/masquerade.jpg');
$check($status === 200 && str_contains($body, '<?php') && !str_contains($body, 'UPLOAD_EXECUTED'),
    'An uploaded .htaccess cannot turn an allowed image extension into executable PHP');
$check(!is_file('/tmp/apache-audit-executed'), 'No uploaded execution sentinel was created');

foreach ([
    ['/template/audit/asset/language/strings_zh.properties', 'PUBLIC_LANGUAGE_FIXTURE'],
    ['/template/audit/asset/language/strings_en.properties', 'PUBLIC_LANGUAGE_FIXTURE'],
    ['/static_new/js/app.js', 'PUBLIC_SCRIPT_FIXTURE'], ['/static/addons/aicontent/js/aicontent.js', 'PUBLIC_SCRIPT_FIXTURE'],
    ['/template/audit/asset/js/theme.js', 'PUBLIC_SCRIPT_FIXTURE'], ['/template/audit/vendor/jquery/jquery.js', 'PUBLIC_SCRIPT_FIXTURE'],
    ['/addons/audit/assets/plugin.js', 'PUBLIC_SCRIPT_FIXTURE'], ['/template/audit/asset/css/theme.css', 'PUBLIC_STYLE_FIXTURE'],
    ['/addons/audit/assets/plugin.css', 'PUBLIC_STYLE_FIXTURE'], ['/static_new/style.css', 'PUBLIC_STYLE_FIXTURE'],
    ['/static/ueditor/config.json', '{"fixture":"public"}'], ['/template/audit/asset/lottie/logo.json', '{"fixture":"public"}'],
    ['/static_new/ueditor/dialogs/preview/preview.html', '<p>PUBLIC_HTML_FIXTURE</p>'], ['/static/player/index.html', '<p>PUBLIC_HTML_FIXTURE</p>'],
    ['/vod/detail/1.html', '<p>PUBLIC_HTML_FIXTURE</p>'], ['/template/audit/help/help.html', '<p>PUBLIC_HTML_FIXTURE</p>'], ['/addons/audit/assets/dialog.html', '<p>PUBLIC_HTML_FIXTURE</p>'], ['/404.html', '<p>PUBLIC_HTML_FIXTURE</p>'],
    ['/robots.txt', 'PUBLIC_TEXT_FIXTURE'], ['/sitemap.xml', 'PUBLIC_TEXT_FIXTURE'], ['/baidu_audit_verify.txt', 'PUBLIC_TEXT_FIXTURE'],
    ['/.well-known/acme-challenge/audit-token', 'PUBLIC_TEXT_FIXTURE'], ['/upload/help/mac10.zip', 'PUBLIC_DOWNLOAD_FIXTURE'],
    ['/upload/docs/manual.pdf', 'PUBLIC_DOWNLOAD_FIXTURE'], ['/upload/docs/sheet.xlsx', 'PUBLIC_DOWNLOAD_FIXTURE'], ['/upload/video/movie.mkv', 'PUBLIC_DOWNLOAD_FIXTURE'],
] as [$path, $expected]) {
    [$status, $body] = $request($path . '?v=fixture');
    $check($status === 200 && $body === $expected, 'Public asset keeps its existing URL/body: ' . $path . ' status=' . $status);
}
foreach (['/upload/vod/picture.png', '/upload/user/avatar.webp', '/template/audit/images/logo.png', '/addons/audit/logo.png'] as $path) {
    [$status, $body, $headers] = $request($path);
    $check($status === 200 && str_starts_with($body, "\x89PNG\r\n\x1a\n") && str_starts_with($headers['content-type'] ?? '', 'image/'),
        'Public image remains readable as an image: ' . $path);
}
foreach ([['/', 'index.php', ''], ['/index.php', 'index.php', ''],
    ['/index.php/vod/detail/id/3.html', 'index.php', 'vod/detail/id/3.html'],
    ['/admin_audit_renamed.php/index/login', 'admin_audit_renamed.php', 'index/login'],
    ['/api.php/v1/vod/list', 'api.php', 'v1/vod/list'], ['/install.php/index/index', 'install.php', 'index/index'],
    ['/vod/detail/id/3.html', 'index.php', 'vod/detail/id/3.html'],
    ['/addons/audit/api/generate', 'index.php', 'addons/audit/api/generate'],
    ['/search/%E4%B8%AD%E6%96%87%20test.html', 'index.php', 'search/中文 test.html']
] as [$path, $entry, $route]) {
    [$status, $body] = $request($path . '?q=one%26two' . (!str_contains($path, '.php') && $path !== '/' ? '&s=override-attempt' : ''), ['text' => '正文', 'id' => '7']);
    $check($status === 200, 'Front controller remains reachable: ' . $path . ' status=' . $status);
    $result = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    $check($result['entry'] === $entry && $result['route'] === $route, 'Real ThinkPHP Request receives the intended entry/PATH_INFO: ' . $path . ' actual=' . json_encode($result, JSON_UNESCAPED_UNICODE));
    $check($result['query']['q'] === 'one&two' && $result['post'] === ['text' => '正文', 'id' => '7'] && $result['method'] === 'POST',
        'Rewrites preserve query, POST body and method: ' . $path);
    $check($result['authorization'] === 'Bearer fixture-token', 'API authorization header survives Apache handling');
}
[$status, $body] = $request('/.env', null, true);
$check($status === 403 && $body === '', 'HEAD also rejects private files without a body');
echo "OK {$checks} Apache boundary checks on PHP " . PHP_VERSION . "\n";
