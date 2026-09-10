<?php
/** Security cleanup must detect contamination in any text column using real ORM/SQLite queries. */
require __DIR__ . '/fixtures/security_audit_runtime_stubs.php';
require dirname(__DIR__) . '/application/admin/controller/Safety.php';
use think\facade\Db;
Db::execute('CREATE TABLE audit_vod (vod_id INTEGER PRIMARY KEY, vod_name TEXT, vod_content TEXT)');
Db::name('vod')->insertAll([
    ['vod_id' => 1, 'vod_name' => '<script>bad()</script>first', 'vod_content' => 'clean body'],
    ['vod_id' => 2, 'vod_name' => 'second', 'vod_content' => '<iframe src="x"></iframe>clean body'],
    ['vod_id' => 3, 'vod_name' => 'third', 'vod_content' => 'unchanged'],
    ['vod_id' => 4, 'vod_name' => '<script>bad()</script>fourth', 'vod_content' => '{php}bad(){/php}clean body'],
]);
$GLOBALS['runtime_schema'] = [
    ['TABLE_NAME' => 'audit_vod', 'COLUMN_NAME' => 'vod_id', 'DATA_TYPE' => 'int'],
    ['TABLE_NAME' => 'audit_vod', 'COLUMN_NAME' => 'vod_name', 'DATA_TYPE' => 'varchar'],
    ['TABLE_NAME' => 'audit_vod', 'COLUMN_NAME' => 'vod_content', 'DATA_TYPE' => 'text'],
];
think\facade\Request::$input = ['ck' => 1, 'tbi' => 6];
$safety = (new ReflectionClass(app\admin\controller\Safety::class))->newInstanceWithoutConstructor();
// The controller ends its streaming action with exit; assertions still run in shutdown.
register_shutdown_function(static function () {
    $rows = Db::name('vod')->order('vod_id')->select()->toArray();
    check(count($rows) === 4, 'Cleanup deleted records');
    check($rows[0]['vod_name'] === 'first', 'Name-only contamination was missed by AND grouping');
    check($rows[1]['vod_content'] === 'clean body', 'Body-only contamination was missed by AND grouping');
    check($rows[2]['vod_name'] === 'third' && $rows[2]['vod_content'] === 'unchanged', 'Clean record changed');
    check($rows[3]['vod_name'] === 'fourth' && $rows[3]['vod_content'] === 'clean body', 'Multi-column contamination not removed');
    check(count($GLOBALS['runtime_redirects'] ?? []) === 1, 'Cleanup did not advance to the next table');
    echo 'Safety query regressions: ' . $GLOBALS['checks'] . " assertions passed\n";
});
$safety->data();
