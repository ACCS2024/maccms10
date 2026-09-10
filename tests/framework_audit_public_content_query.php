<?php
/** Actual Request, API/Ajax methods and MySQL; synthetic configuration and local presentation boundaries. */
declare(strict_types=1);
namespace app\common\controller { class All {} }
namespace app\common\util {
    /** Replace only the external transport; search service, bridge, primary-ID checks and ORM are real. */
    class MeilisearchHttp {
        public static array $calls=[];
        public static function requestParallel($host,$jobs,...$arguments):array {
            if($host!=='https://fixture.invalid')throw new \RuntimeException('Unexpected external search destination');
            $responses=[];
            foreach($jobs as $job){
                self::$calls[]=$job;preg_match('/kind = "(vod|art|manga)"/',$job['body']['filter'],$match);
                if(!isset($match[1]))throw new \RuntimeException('Unexpected search fixture filter');
                $hits=array_map(fn($id)=>['id'=>$match[1].'_'.$id],[40,20,30,10,50,999]);
                $responses[]=['ok'=>true,'status'=>200,'data'=>['hits'=>$hits,'estimatedTotalHits'=>66]];
            }
            return $responses;
        }
    }
}
namespace app\api\controller {
    function mac_url_img($value){return $value === '' ? '' : '/fixture/'.$value;}
    function mac_url_vod_detail($row){return '/vod/'.$row['vod_id'];}
    function mac_url_art_detail($row){return '/art/'.$row['art_id'];}
    function mac_url_manga_detail($row){return '/manga/'.$row['manga_id'];}
    function mac_url_role_detail($row){return '/role/'.$row['role_id'];}
    function mac_tpl_vod_playlink_on(){return false;}
    function mac_vod_type_filter_ids_for_list($id){return $id === 1 ? [1,2] : [$id];}
}
namespace app\index\controller {
    function mac_url_img($value){return $value === '' ? '' : '/fixture/'.$value;}
    function mac_url_vod_detail($row){return '/vod/'.$row['vod_id'];}
    function mac_url_art_detail($row){return '/art/'.$row['art_id'];}
    function mac_url_manga_detail($row){return '/manga/'.$row['manga_id'];}
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use think\facade\Db;
use app\common\util\PublicContentQuery;
function json($value){return \think\Response::create($value,'json');}
function config($key,$default=null){return \think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function cookie($name,...$args){return null;}
function model($name){$class='app\\common\\model\\'.ucfirst($name);return new $class();}
class VisibilityCache {
    public array $data=[];
    public function get($key){
        if(str_ends_with($key,'vip_exclusive_type_ids'))return [2];
        if(str_ends_with($key,'type_list'))return [
            1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>1,'type_name'=>'Parent','type_en'=>'parent','childids'=>'1,2'],
            2=>['type_id'=>2,'type_pid'=>1,'type_mid'=>1,'type_name'=>'Child','type_en'=>'child','childids'=>'2'],
        ];
        if(str_ends_with($key,'group_list'))return [];
        return $this->data[$key]??null;
    }
    public function set($key,$value,...$rest){$this->data[$key]=$value;}
    public function delete($key){unset($this->data[$key]);}
}
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new \RuntimeException('Dedicated MySQL fixture required');
$app=new \think\App(sys_get_temp_dir().'/public-query-fixture');
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_visible_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new \think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);$cache=new VisibilityCache();$app->instance('cache',$cache);
$GLOBALS['config']=['app'=>['cache_flag'=>'visibility_fixture','cache_core'=>0,'cache_time'=>600,'count_cache_sec'=>0],'upload'=>['protocol'=>'https'],'user'=>['art_points_type'=>'0','manga_points_type'=>'0']];
$GLOBALS['mctheme']=['theme'=>['hotvod'=>['tabs'=>[['id'=>'1','name'=>'Public videos']]]]];
$GLOBALS['user']=['user_id'=>0];$sql=[];Db::listen(static function($statement)use(&$sql){$sql[]=$statement;});
function visibilityCall(string $kind,string $action,array $parameters=[]): array {
    global $app;
    $request=(new \think\Request())->withGet($parameters)->setController(ucfirst($kind))->setAction($action);$app->instance('request',$request);
    $controller=(new \ReflectionClass('app\\api\\controller\\'.ucfirst($kind)))->newInstanceWithoutConstructor();
    return json_decode($controller->$action($request)->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function visibilityAjax(string $action,array $parameters=[]):array {
    global $app;
    $request=(new \think\Request())->withGet($parameters)->setController('Ajax')->setAction($action);$app->instance('request',$request);
    $controller=(new \ReflectionClass(\app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$controller->_param=$parameters;
    return json_decode($controller->$action()->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function visibleRows(string $kind,array $result,array $expected):void {
    check($result['code']===1,'Public list keeps a successful JSON envelope');
    $rows=$result['info']['rows']??$result['list'];
    check(array_map('intval',array_column($rows,$kind.'_id'))===$expected,$kind.' list must contain only expected published active rows: '.json_encode(array_column($rows,$kind.'_id')));
    foreach($rows as $row){check($row[$kind.'_pic']==='/fixture/cover.png','Real list transforms survive JSON');}
}
$tables=['vod','art','manga','type','group','ulog','role','topic'];
try {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach($tables as $table){preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$m);Db::execute(str_replace('`mac_'.$table.'`','`audit_visible_'.$table.'`',$m[0]));}
    foreach(['vod','art','manga'] as $kind){
        $rowDefaults[$kind]=[];
        foreach(Db::query('SHOW COLUMNS FROM audit_visible_'.$kind) as $column){
            if($column['Null']==='NO' && $column['Default']===null && !str_contains($column['Extra'],'auto_increment'))$rowDefaults[$kind][$column['Field']]='';
        }
        foreach([10=>[1,0,1],20=>[1,0,2],30=>[0,0,2],40=>[1,time(),1],50=>[2,0,2],60=>[0,time(),1]] as $id=>[$status,$recycle,$type]){
            $row=[$kind.'_id'=>$id,$kind.'_name'=>'Fixture-'.$id,$kind.'_status'=>$status,$kind.'_recycle_time'=>$recycle,$kind.'_pic'=>'cover.png',$kind.'_time'=>time()+$id,$kind.'_time_add'=>time(),$kind.'_level'=>9,$kind.'_hits_month'=>$id,'type_id'=>$type,'type_id_1'=>$type===2?1:0];
            if($kind==='vod')$row+=['vod_year'=>(string)(2000+$id),'vod_area'=>'area-'.$id,'vod_class'=>'class-'.$id];
            Db::name($kind)->insert($row+$rowDefaults[$kind]);
        }
    }
    foreach(['role','topic'] as $kind){
        $rowDefaults[$kind]=[];
        foreach(Db::query('SHOW COLUMNS FROM audit_visible_'.$kind) as $column){
            if($column['Null']==='NO' && $column['Default']===null && !str_contains($column['Extra'],'auto_increment'))$rowDefaults[$kind][$column['Field']]='';
        }
    }
    Db::name('topic')->insert(['topic_id'=>1,'topic_name'=>'Public topic','topic_status'=>1,'topic_rel_vod'=>'40,20,30,10,50,999','topic_rel_art'=>'40,20,30,10,50,999']+$rowDefaults['topic']);
    foreach([1=>10,2=>30,3=>40,4=>50,5=>999,6=>20] as $id=>$rid){Db::name('role')->insert(['role_id'=>$id,'role_rid'=>$rid,'role_name'=>'Role-'.$id,'role_status'=>1,'role_time'=>$id]+$rowDefaults['role']);}
    // Policy is deliberately separate from shared models: chained filters cannot replace its guards.
    foreach(['vod','art','manga'] as $kind){
        check(PublicContentQuery::query($kind)->order($kind.'_id')->column($kind.'_id')===[10,20],'Public policy applies both state predicates');
        check(PublicContentQuery::query($kind)->where([$kind.'_status'=>0])->count()===0,'A later status filter cannot override public publication state');
        check(PublicContentQuery::query($kind)->where([[$kind.'_recycle_time','>',0]])->count()===0,'A later recycle filter cannot override active-only state');
        check(PublicContentQuery::cachedRowsVisible($kind,[[$kind.'_id'=>10],[$kind.'_id'=>'20']],2),'Current public IDs can reuse their list cache');
        foreach([[[$kind.'_id'=>30]],[[$kind.'_id'=>40]],[[$kind.'_id'=>999]],[[$kind.'_id'=>[]]],[[$kind.'_id'=>1.0]],[[$kind.'_id'=>'4294967296']],[[$kind.'_id'=>10],[$kind.'_id'=>10]],null] as $rows){check(!PublicContentQuery::cachedRowsVisible($kind,$rows),'Invisible or malformed cached IDs cannot be reused');}
        check(!PublicContentQuery::cachedRowsVisible($kind,[[$kind.'_id'=>10]],0),'Cache verification has a bounded row budget');
        check(PublicContentQuery::cachedRowsVisible($kind,[]),'An empty public list remains a valid cache entry');
    }
    $caught=false;try{PublicContentQuery::query('actor');}catch(\InvalidArgumentException $error){$caught=true;}check($caught,'Actor status semantics are outside this media policy');
    if(getenv('PUBLIC_CONTENT_REPRO')==='1'){
        check(in_array(30,array_column(visibilityCall('art','get_list')['info']['rows'],'art_id')),'Reproduce omitted article publication filter');
        check(visibilityCall('art','get_list',['status'=>2])['info']['rows'][0]['art_id']===50,'Reproduce public explicit nonpublished status');
        foreach(['vod','art','manga'] as $kind){$action=$kind==='vod'?'get_list':'get_hot';check(in_array(40,array_column(visibilityCall($kind,$action)['info']['rows'],$kind.'_id')),'Reproduce direct '.$kind.' query bypassing recycle filtering');}
        check(visibilityCall('vod','get_detail',['vod_id'=>30])['code']===1,'Reproduce unpublished video metadata detail');
        foreach(['get_year'=>'year','get_class'=>'class','get_area'=>'area'] as $action=>$field){
            $r=visibilityCall('vod',$action,['type_id_1'=>0]);check(in_array($field==='year'?'2040':$field.'-40',$r['info']['rows']),'Reproduce recycled source facet '.$field);
        }
        $GLOBALS['config']['app']['cache_core']=1;visibilityCall('vod','get_latest_by_type',['type_id'=>1]);Db::name('vod')->where('vod_id',20)->update(['vod_status'=>0]);
        check(in_array(20,array_column(visibilityCall('vod','get_latest_by_type',['type_id'=>1])['info']['rows'],'vod_id')),'Reproduce a newly disabled title surviving in a populated home cache');
        Db::name('vod')->where('vod_id',20)->update(['vod_status'=>1]);$GLOBALS['config']['app']['cache_core']=0;$cache->data=[];
        $related=visibilityCall('topic','get_detail',['topic_id'=>1]);
        foreach(['vod','art'] as $kind){check(in_array(40,array_column($related['info']['topic_rel_'.$kind],$kind.'_id')),'Reproduce hidden '.$kind.' metadata in a topic child list');}
        check(in_array('Fixture-30',array_column(visibilityCall('role','get_list')['info']['rows'],'vod_name')),'Reproduce hidden video names in role lists');
        check(visibilityCall('role','get_detail',['role_id'=>2])['info']['vod_info']['vod_id']===30,'Reproduce hidden video metadata in role details');
        echo 'public_content_repro: 14 confirmed production boundary failures on PHP '.PHP_VERSION.PHP_EOL;
    } elseif(getenv('PUBLIC_CONTENT_POLICY_ONLY')!=='1') {
        require __DIR__.'/fixtures/public_content_endpoint_cases.php';
    }
    // Schema detection must remain read-only for pre-recycle legacy tables, with no fail-open SQL catch.
    foreach(['vod','art','manga'] as $kind){
        Db::name($kind)->where($kind.'_recycle_time','>',0)->delete();
        Db::execute('ALTER TABLE audit_visible_'.$kind.' DROP COLUMN '.$kind.'_recycle_time');
        Db::connect()->getSchemaInfo('audit_visible_'.$kind,true);$sql=[];
        check(PublicContentQuery::query($kind)->order($kind.'_id')->column($kind.'_id')===[10,20],'Legacy schema keeps published-only reads without requiring a migration');
        check(!array_filter($sql,fn($statement)=>preg_match('/^(ALTER|CREATE|INSERT|UPDATE|DELETE)\b/i',$statement)),'Public schema detection never writes or migrates a table');
    }
    echo 'framework_audit_public_content_query: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL'.PHP_EOL;
}finally{foreach($tables as $table)Db::execute('DROP TABLE IF EXISTS audit_visible_'.$table);}
}
