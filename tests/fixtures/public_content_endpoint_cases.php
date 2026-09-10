<?php
// Included only by the disposable real-MySQL public media fixture.
use think\facade\Db;
use app\common\util\PublicContentQuery;
foreach(['vod','art','manga'] as $kind){
    $listed=visibilityCall($kind,'get_list');visibleRows($kind,$listed,[20,10]);
    check(($listed['info']['total']??$listed['total'])===2,'Public '.$kind.' pagination counts the same published active rows');
    foreach(['get_hot','get_latest'] as $action){
        if($kind==='vod' && $action==='get_latest')continue;
        visibleRows($kind,visibilityCall($kind,$action),[20,10]);
        visibleRows($kind,visibilityCall($kind,$action,['start'=>1,'num'=>1]),[10]);
        visibleRows($kind,visibilityCall($kind,$action,['start'=>100]),[]);
    }
    $key=$kind==='manga'?'id':$kind.'_id';
    foreach([30,40,50,60,999] as $id){check(visibilityCall($kind,'get_detail',[$key=>$id])['code']!==1,'Public '.$kind.' detail excludes every nonpublic state');}
    check(visibilityCall($kind,'get_detail',[$key=>20])['code']===1,'Published '.$kind.' metadata detail remains available');
    $model=model($kind);
    $res=$model->listData([$kind.'_status'=>0,'_recycle'=>'all'],$kind.'_id desc',1,10);
    check(array_column($res['list'],$kind.'_id')===[60,30],'Explicit administrative '.$kind.' state queries keep their original model contract');
    $res=$model->listData([$kind.'_status'=>1,'_recycle'=>'recycle'],$kind.'_id desc',1,10);
    check(array_column($res['list'],$kind.'_id')===[40],'Explicit administrative '.$kind.' recycle queries remain possible');
}
$related=visibilityCall('topic','get_detail',['topic_id'=>1]);
check($related['code']===1 && $related['info']['topic_name']==='Public topic','Topic metadata remains available when some child media are hidden');
foreach(['vod','art'] as $kind){
    check(array_column($related['info']['topic_rel_'.$kind],$kind.'_id')===[20,10],'Topic child '.$kind.' list preserves configured order while omitting every hidden state');
}
$roles=visibilityCall('role','get_list');
check(array_column($roles['info']['rows'],'role_id')===[6,5,4,3,2,1],'Role list keeps its own rows and ordering');
check(array_column($roles['info']['rows'],'vod_name')===['Fixture-20','','','','','Fixture-10'],'Role titles expose only visible associated videos without removing the role');
foreach([1=>10,2=>null,3=>null,4=>null,5=>null,6=>20] as $role=>$vod){
    $r=visibilityCall('role','get_detail',['role_id'=>$role]);
    check($r['code']===1 && ($r['info']['vod_info']['vod_id']??null)===$vod,'Role detail keeps an explicit null for unavailable related videos');
}
check(visibilityCall('art','get_list',['status'=>2])['code']===1001,'Public article lists reject explicitly requested unpublished status');
visibleRows('art',visibilityCall('art','get_list',['status'=>1,'type_id'=>1]),[20,10]);
visibleRows('vod',visibilityCall('vod','get_list',['type_id'=>1]),[20,10]);
foreach(['vod','art'] as $kind){
    visibleRows($kind,visibilityCall($kind,'get_list',['offset'=>1]),[10]);
    visibleRows($kind,visibilityCall($kind,'get_list',['offset'=>100]),[]);
    $sql=[];visibleRows($kind,visibilityCall($kind,'get_list',['orderby'=>'hits','offset'=>1]),[10]);
    check((bool)array_filter($sql,fn($query)=>preg_match('/ORDER BY.*'.$kind.'_hits.*'.$kind.'_id/i',$query)),'Equal primary sort values preserve the original ID-descending pagination tie breaker');
    $params=$kind==='vod'?['vod_name'=>'Fixture']:['name'=>'Fixture'];
    visibleRows($kind,visibilityCall($kind,'get_list',$params),[20,10]);
}
visibleRows('manga',visibilityCall('manga','get_list',['wd'=>'Fixture']),[20,10]);
// Keep the deployed count TTL, but namespace its key with the actual public predicates.
$GLOBALS['config']['app']['count_cache_sec']=60;
foreach(['vod','art'] as $kind){
    $cache->data=[];$class='app\\common\\model\\'.ucfirst($kind);
    $cache->data['visibility_fixture_cnt_'.md5($class.'|'.serialize([$kind.'_status'=>1]))]=999;
    check(visibilityCall($kind,'get_list')['info']['total']===2,'Old counts without visibility guards cannot contaminate the new count cache');
    Db::name($kind)->where($kind.'_id',20)->update([$kind.'_status'=>0]);$sql=[];
    $result=visibilityCall($kind,'get_list');visibleRows($kind,$result,[10]);
    check($result['info']['total']===2 && !array_filter($sql,fn($query)=>str_contains($query,'COUNT(')),'Short-lived cached totals may lag while fresh rows already hide newly disabled content');
    Db::name($kind)->where($kind.'_id',20)->update([$kind.'_status'=>1]);
}
$GLOBALS['config']['app']['count_cache_sec']=0;$cache->data=[];
// Stale external search hits are filtered through the actual bridge and fresh MySQL rows.
$GLOBALS['config']['meilisearch']=['enabled'=>'1','host'=>'https://fixture.invalid','index_uid'=>'visibility-fixture'];
foreach(['vod','art','manga'] as $kind){
    $method='applyFor'.ucfirst($kind);
    $args=[$kind.'_status'=>1];
    $bridge=$kind==='vod'
        ? \app\common\util\MeilisearchListBridge::$method($args,'fixture-'.$kind,'','','','','',1,10,0,$kind.'_time desc')
        : \app\common\util\MeilisearchListBridge::$method($args,'fixture-'.$kind,'','','',1,10,0,$kind.'_time desc');
    check(is_array($bridge) && $bridge['where'][$kind.'_id']===[20,10],'Actual search bridge excludes stale unpublished, recycled and missing '.$kind.' IDs');
    check(PublicContentQuery::query($kind)->where($bridge['where'])->order($bridge['order'])->column($kind.'_id')===[20,10],'Final public SQL retains search order and public state');
}
visibleRows('vod',visibilityCall('vod','get_list',['vod_name'=>'Fixture']),[20,10]);
check(count(\app\common\util\MeilisearchHttp::$calls)>=4,'Search tests exercise the real service through the isolated transport');
unset($GLOBALS['config']['meilisearch']);
// Already-correct Ajax model paths must remain covered instead of applying a global model filter.
foreach(['vod'=>1,'art'=>2] as $kind=>$mid){visibleRows($kind,visibilityAjax('data',['mid'=>$mid,'limit'=>10,'page'=>1,'tid'=>0]),[20,10]);}
foreach(['art','manga'] as $kind){
    $r=visibilityAjax('guess_'.$kind,['num'=>20]);check(array_column($r['list'],$kind.'_id')===[20,10],'Ajax recommendations exclude drafts/recycle for '.$kind);
}
foreach([2=>'vod',6=>'manga',7=>'art'] as $tab=>$kind){
    $r=visibilityAjax('home_hot_tab',['tab'=>$tab]);
    check($r['code']===1 && $r['data']['content_type']===$kind,'Ajax home tab keeps its media envelope');
    $links=array_column($r['data']['img_list'],'link');
    check($links===['/'.$kind.'/20','/'.$kind.'/10'],'Ajax home tab contains only visible '.$kind.' rows');
}
foreach(['get_banner'=>[],'get_hot'=>[],'get_latest_by_type'=>['type_id'=>1],'get_rank'=>[]] as $action=>$parameters){
    visibleRows('vod',visibilityCall('vod',$action,$parameters),[20,10]);
}
// Cache hits must observe depublication/recycling before exposing a formerly visible title.
$GLOBALS['config']['app']['cache_core']=1;$cache->data=[];
visibleRows('vod',visibilityCall('vod','get_latest_by_type',['type_id'=>1]),[20,10]);
$sql=[];visibleRows('vod',visibilityCall('vod','get_latest_by_type',['type_id'=>1]),[20,10]);
check((bool)array_filter($sql,fn($query)=>str_contains($query,'COUNT(')),'Reused latest cache revalidates actual IDs against MySQL');
Db::name('vod')->where('vod_id',20)->update(['vod_status'=>0]);
visibleRows('vod',visibilityCall('vod','get_latest_by_type',['type_id'=>1]),[10]);
Db::name('vod')->where('vod_id',10)->update(['vod_recycle_time'=>time()]);
visibleRows('vod',visibilityCall('vod','get_latest_by_type',['type_id'=>1]),[]);
Db::name('vod')->where('vod_id',20)->update(['vod_status'=>1]);Db::name('vod')->where('vod_id',10)->update(['vod_recycle_time'=>0]);
$GLOBALS['config']['app']['cache_core']=0;$cache->data=[];
// Facet values carry no source IDs, so old metadata caches cannot establish their visibility.
foreach(['get_year'=>'year','get_class'=>'class','get_area'=>'area'] as $action=>$field){
    check(visibilityCall('vod',$action,['type_id_1'=>0])['info']['rows']===[$field==='year'?'2010':$field.'-10'],'Facet excludes a recycled source with a distinct private value');
    $cache->data['vod_meta_'.$field.'_1']=['stale-private-'.$field];
    $r=visibilityCall('vod',$action,['type_id_1'=>1]);
    check($r['info']['rows']===[$field==='year'?'2020':$field.'-20'],'Facet excludes recycled and unpublished source rows and ignores unverifiable old cache');
    Db::name('vod')->where('vod_id',20)->update(['vod_status'=>0]);
    check(visibilityCall('vod',$action,['type_id_1'=>1])['info']['rows']===[],'Facet does not retain a value after its final public source is disabled');
    Db::name('vod')->where('vod_id',20)->update(['vod_status'=>1]);
}
// Preserve the existing bounded SQL/result sizes on populated metadata endpoints.
for($id=1000;$id<1510;$id++){
    Db::name('vod')->insert(['vod_id'=>$id,'vod_name'=>'Facet-'.$id,'vod_status'=>1,'type_id'=>2,'type_id_1'=>1,'vod_year'=>(string)$id,'vod_class'=>'class-'.$id,'vod_area'=>'area-'.$id]+$rowDefaults['vod']);
}
foreach(['get_year'=>200,'get_class'=>500,'get_area'=>200] as $action=>$maximum){
    $sql=[];$r=visibilityCall('vod',$action,['type_id_1'=>1]);
    check($r['info']['total']===$maximum && count($r['info']['rows'])===$maximum,'Facet preserves its existing maximum result size');
    check((bool)array_filter($sql,fn($query)=>preg_match('/SELECT\s+DISTINCT\b/i',$query)&&preg_match('/LIMIT\s+(?:0\s*,\s*)?'.$maximum.'\b/i',$query)),'Facet keeps a bounded DISTINCT SQL query');
}
Db::name('vod')->where('vod_id','>=',1000)->delete();
