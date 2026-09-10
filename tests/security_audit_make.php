<?php
/** Article generation must reset page counts between multi-page and empty records. */
require __DIR__ . '/fixtures/security_audit_runtime_stubs.php';
require dirname(__DIR__) . '/application/admin/controller/Make.php';
use think\facade\Db;
define('ENTRANCE', 'admin');
class RuntimeAuditMake extends app\admin\controller\Make
{
    protected function buildHtml($htmlfile = '', $htmlpath = '', $templateFile = '') {
        $GLOBALS['runtime_rendered'][] = [$_REQUEST['id'], $_REQUEST['page'], $htmlfile];
        return true;
    }
    protected function echoLink($des, $url = '', $color = '', $wrap = 1) {}
}
Db::execute('CREATE TABLE audit_art (art_id INTEGER PRIMARY KEY, art_time_make INTEGER)');
foreach ([1, 2, 3] as $id) { Db::name('art')->insert(['art_id' => $id, 'art_time_make' => 0]); }
$GLOBALS['runtime_lists']['art'] = [];
foreach ([1 => 'one$$$two', 2 => '', 3 => 'three'] as $id => $content) {
    $GLOBALS['runtime_lists']['art'][] = ['art_id' => $id, 'art_name' => 'article', 'art_title' => '', 'art_note' => '',
        'art_content' => $content, 'type_id' => 1, 'type' => ['type_pid' => 0]];
}
$GLOBALS['config'] = ['app' => ['makesize' => 20], 'view' => ['art_detail' => 2]];
$controller = (new ReflectionClass(RuntimeAuditMake::class))->newInstanceWithoutConstructor();
$controller->_param = ['tab' => 'art', 'ids' => [1, 2, 3], 'arttype' => [], 'num' => 0, 'start' => 1,
    'page_count' => 1, 'data_count' => 3, 'page_size' => 20, 'ac2' => '', 'ref' => 0];
ob_start();
try { $controller->info(); } finally { ob_end_clean(); }
check($GLOBALS['runtime_rendered'] === [[1, 1, '/art/1/1'], [1, 2, '/art/1/2'], [3, 1, '/art/3/1']], 'Article page count leaked across records');
check($controller->_param['start'] === 2, 'Generation did not advance the batch');
check(Db::name('art')->where('art_time_make', '>', 0)->count() === 3, 'Generation did not retain existing make-time update behavior');
echo 'Static generation regressions: ' . $checks . " assertions passed\n";
