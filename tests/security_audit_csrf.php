<?php
/** Explicit CSRF token regressions, including the middleware HTTP branch. */
require __DIR__ . "/fixtures/security_audit_controller_stubs.php";
require dirname(__DIR__) . '/application/middleware/CsrfGuard.php';
if (PHP_SAPI === 'cli-server') {
    define('ENTRANCE', 'admin');
    $GLOBALS['config'] = ['app' => ['security_csrf_admin' => 1]];
    $GLOBALS['audit_session'] = ['__csrf_token__' => 'audit-header-token'];
    $request = new AuditRequest($_GET['route'] ?? '', $_SERVER['REQUEST_METHOD'] === 'POST');
    try {
        $result = (new \app\middleware\CsrfGuard())->handle($request, static fn() => json(['allowed' => true]));
    } catch (\think\exception\HttpResponseException $e) {
        $result = $e->response;
    }
    http_response_code($result['status']);
    echo json_encode($result['data']);
    return;
}

require dirname(__DIR__) . '/application/admin/controller/Base.php';
require dirname(__DIR__) . '/application/admin/controller/Upload.php';
require dirname(__DIR__) . '/application/common/util/UeditorAiCsrf.php';
$temp = audit_temp_dir('csrf');
$server = null;
try {
$GLOBALS['audit_session'] = ['ueditor_ai_csrf_token' => 'audit-session-token'];
$_COOKIE['ueditor_ai_csrf'] = 'audit-session-token';
foreach (['', 'incorrect', [], null] as $submitted) {
    check(!\app\common\util\UeditorAiCsrf::validate($submitted), 'Automatic cookie bypassed submitted token');
}
check(\app\common\util\UeditorAiCsrf::validate('audit-session-token'), 'Valid explicit token rejected');
$upload = (new \ReflectionClass(\app\admin\controller\Upload::class))->newInstanceWithoutConstructor();
foreach (['{}', '{"_csrf_token":"incorrect"}', '{"_csrf_token":[]}'] as $body) {
    $upload->request = new AuditRequest('upload/ueditorai', true, $body);
    check($upload->ueditorAi()['data']['msg'] === 'admin/ueditor_ai/invalid_token', 'Controller accepted cookie-only request');
}

// Exercise the middleware's real HTTP branch; CLI intentionally bypasses it.
$socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
if ($socket === false) { throw new \RuntimeException('Could not reserve HTTP test port'); }
$address = stream_socket_get_name($socket, false);
fclose($socket);
$server = proc_open([PHP_BINARY, '-S', $address, __FILE__],
    [0 => ['file', '/dev/null', 'r'], 1 => ['file', $temp . '/server.log', 'a'], 2 => ['file', $temp . '/server.log', 'a']], $pipes, $temp);
if (!is_resource($server)) { throw new \RuntimeException('HTTP fixture failed to start'); }
for ($i = 0; $i < 100; $i++) {
    $probe = @stream_socket_client('tcp://' . $address, $errno, $error, 0.05);
    if ($probe !== false) { fclose($probe); break; }
    usleep(20000);
}
foreach ([['assistant/chat', '', 403], ['assistant/chat', 'wrong', 403],
    ['assistant/chat', 'audit-header-token', 200], ['system/config', '', 403],
    ['system/config', 'audit-header-token', 200]] as [$route, $token, $status]) {
    $context = stream_context_create(['http' => ['method' => 'POST', 'ignore_errors' => true, 'timeout' => 5,
        'header' => "Content-Type: application/json\r\nX-CSRF-Token: " . $token . "\r\n", 'content' => '{}']]);
    $body = file_get_contents('http://' . $address . '/?route=' . urlencode($route), false, $context);
    check(str_contains($http_response_header[0], ' ' . $status . ' '), 'Unexpected HTTP CSRF result for ' . $route);
}
echo 'CSRF regressions: ' . $checks . " assertions passed\n";
} finally {
    if (is_resource($server)) { proc_terminate($server); proc_close($server); }
    audit_remove_temp($temp);
}
