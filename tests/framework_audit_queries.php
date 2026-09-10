<?php
/** Isolated real-ORM regression group; no application bootstrap or production database. */
declare(strict_types=1);
use think\facade\Db;

$frameworkAuditTables = ['actor', 'website', 'query_vod'];
require __DIR__ . '/fixtures/framework_audit_db.php';

class FrameworkAuditActor extends app\common\model\Actor {
    public function listData($where,$order,$page=1,$limit=20,$start=0,$field='*',$addition=1,$totalshow=1) {
        return ['list'=>Db::name('actor')->where($where)->order('actor_id')->select()->toArray()];
    }
}
class FrameworkAuditWebsite extends app\common\model\Website {
    public function listData($where,$order,$page=1,$limit=20,$start=0,$field='*',$addition=1,$totalshow=1) {
        return ['list'=>Db::name('website')->where($where)->order('website_id')->select()->toArray()];
    }
}
$GLOBALS['audit_url_params'] = ['tid'=>7];
foreach (['actor'=>FrameworkAuditActor::class, 'website'=>FrameworkAuditWebsite::class] as $table => $class) {
    Db::name($table)->insertAll([
        [$table.'_id'=>1,$table.'_status'=>1,'type_id'=>7,'type_id_1'=>0],
        [$table.'_id'=>2,$table.'_status'=>1,'type_id'=>8,'type_id_1'=>7],
        [$table.'_id'=>3,$table.'_status'=>1,'type_id'=>9,'type_id_1'=>0],
    ]);
    $res = (new $class())->listCacheData(['paging'=>'yes','pageurl'=>'test-route']);
    expect(array_column($res['list'], $table.'_id') === [1,2], $table . ': tid must filter direct or parent category');
}

Db::name('query_vod')->insertAll([
    ['vod_id'=>1,'vod_status'=>1,'vod_name'=>'movie','vod_actor'=>'Alice','vod_director'=>'Bob','vod_tag'=>'red'],
    ['vod_id'=>2,'vod_status'=>1,'vod_name'=>'movie','vod_actor'=>'Carol','vod_director'=>'Alice','vod_tag'=>'blue'],
    ['vod_id'=>3,'vod_status'=>1,'vod_name'=>'other','vod_actor'=>'Alice','vod_director'=>'Alice','vod_tag'=>'red'],
    ['vod_id'=>4,'vod_status'=>0,'vod_name'=>'movie','vod_actor'=>'Alice','vod_director'=>'Alice','vod_tag'=>'red'],
    ['vod_id'=>5,'vod_status'=>1,'vod_name'=>'movie','vod_actor'=>'David','vod_director'=>'Eve','vod_tag'=>'red'],
]);
$searchCondition = new ReflectionMethod(app\common\model\Vod::class, 'appendCachedSearchCondition');
$searchWhere = ['vod_status'=>1];
$searchCondition->invokeArgs(null, [&$searchWhere, ['vod_actor','like','%Alice%'], [1,3,4], 10]);
expect(Db::name('query_vod')->where($searchWhere)->order('vod_id')->column('vod_id') === [1,3], 'Cached IDs must preserve the outside status predicate');
$sql = Db::name('query_vod')->where($searchWhere)->fetchSql()->select();
expect(!str_contains(strtoupper($sql), 'LIKE'), 'A cached filter must replace its LIKE condition');
$searchCondition->invokeArgs(null, [&$searchWhere, ['vod_name','like','%movie%'], [1,2,4,5], 10]);
expect(Db::name('query_vod')->where($searchWhere)->column('vod_id') === [1], 'Separate cached search facets must intersect, not union');
$searchCondition->invokeArgs(null, [&$searchWhere, ['vod_tag','like','%missing%'], [], 10]);
expect(Db::name('query_vod')->where($searchWhere)->count() === 0, 'Empty cached match set must never broaden results');
$searchWhere = ['vod_status'=>1];
$searchCondition->invokeArgs(null, [&$searchWhere, ['vod_actor|vod_director','like','%Alice%'], [1,2,3,4], 1]);
expect(Db::name('query_vod')->where($searchWhere)->order('vod_id')->column('vod_id') === [1,2,3], 'Oversized cached match set must retain multi-field LIKE fallback');
$alternatives = new ReflectionMethod(app\common\model\Collect::class, 'alternativeConditions');
$group = $alternatives->invoke(null, [['vod_director','like',['%Alice%'],'OR'], ['vod_actor','like',['%Alice%'],'OR']]);
expect(Db::name('query_vod')->where(['vod_status'=>1,'vod_name'=>'movie'])->where($group)->order('vod_id')->column('vod_id') === [1,2], 'Collector actor/director alternatives must stay grouped under name and status');
$group = $alternatives->invoke(null, [['vod_director','=','Alice'], ['vod_id','in',[1,3,4]]]);
expect(Db::name('query_vod')->where(['vod_status'=>1,'vod_name'=>'movie'])->where($group)->order('vod_id')->column('vod_id') === [1,2], 'Cached actor IDs must preserve director alternative and outer constraints');


finishFrameworkAudit('framework_audit_queries');
