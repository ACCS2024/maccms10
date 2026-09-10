<?php
/** URL push should handle empty input without submitting malformed provider requests. */
require __DIR__ . '/fixtures/security_audit_runtime_stubs.php';
require dirname(__DIR__) . '/application/admin/controller/Urlsend.php';
define('ENTRANCE', 'admin');
$controller = (new ReflectionClass(app\admin\controller\Urlsend::class))->newInstanceWithoutConstructor();
$GLOBALS['config'] = ['site' => ['site_url' => 'fixture.example']];
$GLOBALS['http_type'] = 'https://';
foreach ([[], ['mid' => 999], ['mid' => 1]] as $input) {
    $controller->_param = $input;
    check($controller->data() === null, 'Empty or unsupported source did not terminate cleanly');
}
foreach ([[], ['ac' => []], ['ac' => '../fixture']] as $input) {
    $controller->_param = $input;
    check($controller->push()['ok'] === false, 'Invalid provider name accepted');
}
$controller->_param = ['ac' => 'fixture', 'mid' => 1];
check($controller->push() === null && empty($GLOBALS['runtime_submissions']), 'Empty content was sent to a provider');
foreach ([1 => 'vod', 2 => 'art', 3 => 'topic', 8 => 'actor', 9 => 'role', 11 => 'website', 12 => 'manga'] as $mid => $kind) {
    $GLOBALS['runtime_lists'][$kind] = [[$kind . '_id' => 9, $kind . '_name' => 'fixture']];
    $controller->_param = ['mid' => $mid, 'limit' => 99999];
    $result = $controller->data();
    check(count($result['urls']) === 1 && str_starts_with($result['urls'][9], 'https://fixture.example/'), 'Valid provider URL building failed');
    check($GLOBALS['runtime_queries'][$kind][array_key_last($GLOBALS['runtime_queries'][$kind])]['limit'] === 1000, 'Batch limit was not bounded');
}
$controller->_param = ['ac' => 'fixture', 'mid' => 1];
check($controller->push() === null && count($GLOBALS['runtime_submissions']) === 1, 'Valid source was not submitted once');
echo 'URL push regressions: ' . $checks . " assertions passed\n";
