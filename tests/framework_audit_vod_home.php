<?php
/** Real ORM collections and API home-list transforms; URL and taxonomy helpers are fixture boundaries. */
declare(strict_types=1);
namespace { require dirname(__DIR__).'/vendor/autoload.php'; }
namespace app\common\controller { class All {} }
namespace {
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use think\facade\Db;
function lang($key,$vars=[]) { return $key; }
function json($data) { return \think\Response::create($data,'json'); }
function config($key,$default=null) { return \think\facade\Config::get($key,$default); }
function mac_url_img($image) { return '/fixture/'.$image; }
function mac_url_vod_detail($row) { return '/fixture/vod/'.$row['vod_id']; }
function mac_vod_type_filter_ids_for_list($id) { return $id === 10 ? [10,11] : [$id]; }
// Preserve the real helper's array-by-reference contract; taxonomy lookup is outside this test.
function mac_append_type_is_vip_exclusive_for_rows(array &$rows) {
    foreach ($rows as &$row) { $row['type_is_vip_exclusive'] = (int)$row['type_id'] === 11 ? 1 : 0; }
}
$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$temp = audit_temp_dir('vod-home');
$app = new \think\App($temp);
$configuration=['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>[
    'type'=>$mysql?'mysql':'sqlite','database'=>$mysql?'maccms_audit_models':':memory:',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1','username'=>'root',
    'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD')?:'','prefix'=>'audit_home_',
    'charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false,
]]];
$app->config->set($configuration,'database');
$manager=new \think\DbManager();$manager->setConfig($configuration);$app->instance('think\\DbManager',$manager);
$GLOBALS['user']=['user_id'=>0];$GLOBALS['config']=['app'=>['cache_core'=>0,'cache_flag'=>'fixture','cache_time'=>0]];
$columns=['vod_id INTEGER PRIMARY KEY'];
foreach (['vod_name','vod_sub','vod_pic','vod_pic_slide','vod_actor','vod_director','vod_content','vod_blurb','vod_remarks','vod_year','vod_area','vod_class'] as $column) {
    $columns[]=$column." VARCHAR(255) NOT NULL DEFAULT ''";
}
foreach (['vod_recycle_time','vod_status','vod_level','vod_score','vod_points_play','type_id','type_id_1','vod_time','vod_time_add','vod_hits','vod_hits_day','vod_hits_week','vod_hits_month','vod_isend'] as $column) {
    $columns[]=$column.' INTEGER NOT NULL DEFAULT 0';
}
function homeCall(string $action,array $parameters=[]): array {
    global $app;
    $request=(new \think\Request())->withGet($parameters);$app->instance('request',$request);
    $controller=(new \ReflectionClass(\app\api\controller\Vod::class))->newInstanceWithoutConstructor();
    return $controller->$action($request)->getData();
}
try {
    Db::execute('DROP TABLE IF EXISTS audit_home_vod');Db::execute('DROP TABLE IF EXISTS audit_home_ulog');
    Db::execute('CREATE TABLE audit_home_vod ('.implode(',',$columns).')');
    Db::execute('CREATE TABLE audit_home_ulog (ulog_id INTEGER PRIMARY KEY,user_id INTEGER,ulog_rid INTEGER,ulog_mid INTEGER,ulog_type INTEGER)');
    $now=time();
    foreach ([1=>[11,10,1],2=>[10,0,1],3=>[10,0,0]] as $id=>[$type,$parent,$status]) {
        Db::name('Vod')->insert(['vod_id'=>$id,'vod_name'=>'Fixture '.$id,'vod_pic'=>'cover'.$id.'.jpg','vod_pic_slide'=>'slide.jpg',
            'vod_content'=>'<b>Fixture description</b>','vod_status'=>$status,'vod_level'=>9,'vod_score'=>10-$id,
            'type_id'=>$type,'type_id_1'=>$parent,'vod_time'=>$now-$id,'vod_time_add'=>$now,
            'vod_hits_month'=>100-$id]);
    }
    Db::name('Vod')->insert(['vod_id'=>90,'vod_status'=>1,'vod_level'=>9,'type_id'=>10,'vod_recycle_time'=>time(), 'vod_time'=>$now,'vod_time_add'=>$now,'vod_hits_month'=>999]);
    foreach (['get_banner'=>[],'get_hot'=>[],'get_latest_by_type'=>['type_id'=>10],'get_rank'=>[]] as $action=>$parameters) {
        $result=homeCall($action,$parameters);$rows=$result['info']['rows'];
        check($result['code']===1 && is_array($rows) && array_column($rows,'vod_id')===[1,2],$action.' must return real visible rows from the configured prefix');
        check($rows[0]['vod_pic']==='/fixture/cover1.jpg' && $rows[0]['vod_link']==='/fixture/vod/1',$action.' must persist row transformations');
        check(array_column($rows,'type_is_vip_exclusive')===[1,0],$action.' must pass a mutable array to the taxonomy helper');
        $page=homeCall($action,$parameters+['num'=>1,'start'=>1]);
        check($page['info']['total']===1 && array_column($page['info']['rows'],'vod_id')===[2],$action.' must keep pagination');
        $empty=homeCall($action,$parameters+['start'=>99]);
        check($empty['info']['total']===0 && $empty['info']['rows']===[],$action.' must preserve empty JSON lists');
    }
    check(homeCall('get_banner')['info']['rows'][0]['vod_content']==='Fixture description','Banner text transform must persist');
    check(homeCall('get_hot',['type_id'=>10])['info']['total']===2,'Hot list must include parent/child category rows');
    check(homeCall('get_rank')['info']['rows'][1]['rank']===2,'Ranking transforms must survive serialization');
    check(homeCall('get_latest_by_type',['type_id'=>10])['info']['today_new_count']===2,'Today count must use the same prefix and visible category scope');
    $GLOBALS['user']['user_id']=4;
    Db::name('Ulog')->insertAll([
        ['ulog_id'=>7,'user_id'=>4,'ulog_rid'=>1,'ulog_mid'=>1,'ulog_type'=>2],
        ['ulog_id'=>8,'user_id'=>5,'ulog_rid'=>2,'ulog_mid'=>1,'ulog_type'=>2],
        ['ulog_id'=>9,'user_id'=>4,'ulog_rid'=>2,'ulog_mid'=>2,'ulog_type'=>2],
    ]);
    $rows=homeCall('get_banner')['info']['rows'];
    check([$rows[0]['is_fav'],$rows[0]['fav_uid'],$rows[1]['is_fav']]===[1,7,0],'Banner must keep current-user favorites with real query rows');
    foreach (['get_banner'=>[],'get_hot'=>[],'get_latest_by_type'=>['type_id'=>10],'get_rank'=>[]] as $action=>$defaults) {
        foreach (['num','start','type_id','level','by'] as $field) {
            foreach ([[],null,true,1.5] as $value) {
                check(homeCall($action,[$field=>$value]+$defaults)['code']===1001,$action.' must reject structured/nontext '.$field);
            }
        }
        foreach ([['num'=>0],['num'=>-1],['num'=>'1x'],['start'=>-1],['start'=>100001],['type_id'=>'4294967296'],['level'=>'1,'],['level'=>'10']] as $bad) {
            check(homeCall($action,$bad+$defaults)['code']===1001,$action.' must reject invalid filter ranges');
        }
        check(homeCall($action,['num'=>'999','start'=>'0']+$defaults)['code']===1,$action.' must cap a valid large count');
        check(homeCall($action,['by'=>'unsupported']+$defaults)['code']===1,$action.' must preserve the safe sorting fallback');
    }
    Db::name('Vod')->where('vod_id',2)->update(['vod_level'=>8]);
    check(array_column(homeCall('get_banner',['level'=>' 8,9,8 '])['info']['rows'],'vod_id')===[1,2],'Banner comma-separated levels must be an IN filter');
    check(array_column(homeCall('get_hot',['level'=>'8'])['info']['rows'],'vod_id')===[2],'Hot level filter must select the requested level');
    check(homeCall('get_latest_by_type',[])['code']===1001,'Latest lists require a positive type ID');
    for ($id=4; $id<=75; $id++) {
        Db::name('Vod')->insert(['vod_id'=>$id,'vod_status'=>1,'vod_level'=>9,'type_id'=>10]);
    }
    foreach (['get_banner'=>[],'get_hot'=>[],'get_latest_by_type'=>['type_id'=>10],'get_rank'=>[]] as $action=>$defaults) {
        check(homeCall($action,['num'=>999]+$defaults)['info']['total']===60,$action.' must enforce the 60-row cap on a populated result');
    }
    Db::name('Vod')->where('vod_id',90)->delete();
    Db::execute('ALTER TABLE audit_home_vod DROP COLUMN vod_recycle_time');
    Db::connect()->getSchemaInfo('audit_home_vod',true);
    foreach (['get_banner'=>[],'get_hot'=>[],'get_latest_by_type'=>['type_id'=>10],'get_rank'=>[]] as $action=>$defaults) {
        check(homeCall($action,$defaults)['code']===1,$action.' must also read old schemas without a recycle column');
    }
    echo 'framework_audit_vod_home: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite').PHP_EOL;
} finally {
    Db::execute('DROP TABLE IF EXISTS audit_home_ulog');Db::execute('DROP TABLE IF EXISTS audit_home_vod');audit_remove_temp($temp);
}
}
