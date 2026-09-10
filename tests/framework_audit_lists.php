<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\Base;

$frameworkAuditTables = ['rows', 'type', 'group', 'annex', 'comment', 'manga', 'msg', 'visit'];
require __DIR__ . '/fixtures/framework_audit_db.php';

class FrameworkAuditRows extends Base {
    protected $name = 'rows';
    protected $primaryId = 'row_id';
    public function transformRow($row, $extends = []) {
        $row['label'] = $extends['prefix'] . $row['label'];
        return $row;
    }
}

Db::name('rows')->insertAll([
    ['row_id'=>1, 'label'=>'one'],
    ['row_id'=>2, 'label'=>'two'],
    ['row_id'=>3, 'label'=>'three'],
]);
$rows = new FrameworkAuditRows();
expect(array_column($rows->getListByCond(0, 2, []), 'row_id') === [3, 2], 'Nonempty model collections must become plain rows in descending primary-key order');
expect($rows->getListByCond(0, 20, ['row_id'=>99]) === [], 'Empty model collections must remain an empty list');
expect($rows->getListByCond(1, 1, [], 'row_id ASC', '*', ['prefix'=>'row:']) === [['row_id'=>2, 'label'=>'row:two']], 'Pagination and row transformation must operate on array rows');

foreach (['Annex', 'Comment', 'Manga', 'Msg', 'Visit'] as $name) {
    $class = 'app\\common\\model\\' . $name;
    $result = (new $class())->listData([], '', 1, 20, 0, '*', 0, 0);
    expect($result['total'] === 0 && $result['list'] === [], $name . ': disabling total calculation must still return a defined zero total');
}

finishFrameworkAudit('framework_audit_lists');
