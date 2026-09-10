<?php
/** Real Think Log facade must preserve success and error paths on PHP 8. */
require __DIR__ . '/fixtures/security_audit_runtime_stubs.php';
require dirname(__DIR__) . '/application/common/util/AiSearch.php';
require dirname(__DIR__) . '/application/common/util/VodAiCover.php';
require dirname(__DIR__) . '/application/admin/controller/Upload.php';
use think\facade\Db;

$debug = new ReflectionMethod(app\common\util\AiSearch::class, 'debugLog');
$debug->invoke(null, ['debug_log' => 0], 'disabled');
check($logger->events === [], 'Disabled AI diagnostics emitted a log');
$debug->invoke(null, ['debug_log' => 1], 'fixture');
check($logger->events === [['notice', '[ai_search] fixture']], 'AI diagnostics did not reach the real Log facade');

$upload = (new ReflectionClass(app\admin\controller\Upload::class))->newInstanceWithoutConstructor();
$upload->_admin = ['admin_id' => 2];
$upload->request = new class {
    public function isGet(): bool { return false; }
    public function isPost(): bool { return true; }
    public function getContent(): string { return '{"_csrf_token":"fixture-csrf","user_prompt":"fixture"}'; }
};
$GLOBALS['runtime_config']['maccms'] = ['ai_seo' => ['enabled' => 1, 'api_key' => 'fixture-key', 'provider' => 'fixture']];
$GLOBALS['runtime_proxy_mode'] = 'throw';
$logger->events = [];
$response = $upload->ueditorAi();
check($response['data']['code'] === 1 && $response['data']['msg'] === 'admin/ueditor_ai/upstream_fail', 'Upstream exception escaped through logging');
check(count($logger->events) === 1 && $logger->events[0][0] === 'error', 'Upstream exception was not logged');
$GLOBALS['runtime_proxy_mode'] = '';
$GLOBALS['runtime_proxy_reply'] = ['ok' => false, 'error' => 'fixture rejection', 'log_detail' => 'fixture detail'];
$logger->events = [];
$response = $upload->ueditorAi();
check($response['data']['code'] === 1 && $response['data']['msg'] === 'fixture rejection', 'Rejected upstream response was lost while logging');
check(count($logger->events) === 1 && str_contains($logger->events[0][1], 'fixture detail'), 'Rejected upstream detail was not logged');
$GLOBALS['runtime_proxy_reply'] = ['ok' => true, 'text' => 'fixture answer'];
$logger->events = [];
$response = $upload->ueditorAi();
check($response['data']['code'] === 0 && $response['data']['data']['text'] === 'fixture answer', 'Successful upstream response failed during logging');
check(count($logger->events) === 1 && $logger->events[0][0] === 'log', 'Successful upstream response did not reach Log::write');

Db::execute('CREATE TABLE audit_vod (vod_id INTEGER PRIMARY KEY, vod_pic TEXT, vod_pic_original TEXT, vod_pic_thumb TEXT)');
$vod = ['vod_id' => 1, 'vod_pic' => 'original.jpg', 'vod_pic_original' => '', 'vod_pic_thumb' => ''];
Db::name('vod')->insert($vod);
$GLOBALS['runtime_config']['maccms.upload'] = ['watermark' => 1, 'thumb' => 1, 'mode' => 'fixture'];
$logger->events = [];
$finish = new ReflectionMethod(app\common\util\VodAiCover::class, 'finalizeAndUpdateVod');
$response = $finish->invoke(null, $vod, 'upload/vod/fixture.jpg');
check($response['code'] === 1, 'Recoverable image-processing failures escaped through logging');
check(count($logger->events) === 3 && array_column($logger->events, 0) === ['error', 'error', 'error'], 'Watermark, thumbnail and storage failures were not all logged');
$stored = Db::name('vod')->find(1);
check($stored['vod_pic'] === 'upload/vod/fixture.jpg' && $stored['vod_pic_original'] === 'original.jpg', 'Logging interrupted the cover update or original backup');
echo 'Log facade regressions: ' . $checks . " assertions passed\n";
