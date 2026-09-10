<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;
use app\common\model\Cj;

$frameworkAuditTables = ['cj_node'];
require __DIR__ . '/fixtures/framework_audit_db.php';

$collector = new Cj();
expect($collector->saveData(['name'=>'node','__token__'=>'form-only'])['code'] === 1, 'Collection node insert must not call a missing inherited helper');
$nodeId = (int)Db::name('cj_node')->value('nodeid');
expect($collector->saveData(['nodeid'=>$nodeId,'name'=>'changed','__token__'=>'form-only'])['code'] === 1, 'Collection node update must filter form-only fields');
expect(Db::name('cj_node')->where('nodeid', $nodeId)->value('name') === 'changed', 'Collection node update must persist');


finishFrameworkAudit('framework_audit_collection_nodes');
