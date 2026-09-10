<?php
/** Real Request, search service/bridge/models and installation DDL; only external HTTP/presentation isolated. */
declare(strict_types=1);
namespace app\common\controller { class All {} }
namespace app\common\util {
    class MeilisearchHttp {
        public static string $mode='ok';public static array $calls=[];
        public static function requestParallel($host,$jobs,...$arguments):array {
            if($host!=='https://fixture.invalid')throw new \RuntimeException('Unexpected external search destination');
            $out=[];foreach($jobs as $job){
                self::$calls[]=$job;preg_match('/kind = "(vod|art|manga|topic|actor|role|website)"/',$job['body']['filter'],$match);
                if(!isset($match[1]))throw new \RuntimeException('Unexpected fixture search kind');
                if(self::$mode==='fail'){$out[]=['ok'=>false,'status'=>503,'error'=>'Fixture search unavailable'];continue;}
                $hits=self::$mode==='empty'?[]:array_map(fn($id)=>['id'=>$match[1].'_'.$id],[40,10,30,20,50,999]);
                $out[]=['ok'=>true,'status'=>200,'data'=>['hits'=>$hits,'estimatedTotalHits'=>66]];
            }return $out;
        }
    }
    function mac_url_img($value){return $value===''?'':'/fixture/'.$value;}
    function mac_url_vod_detail($row){return '/vod/'.$row['vod_id'];}
    function mac_url_art_detail($row){return '/art/'.$row['art_id'];}
    function mac_url_manga_detail($row){return '/manga/'.$row['manga_id'];}
    function mac_url_actor_detail($row){return '/actor/'.$row['actor_id'];}
    function mac_url_topic_detail($row){return '/topic/'.$row['topic_id'];}
    function mac_url_role_detail($row){return '/role/'.$row['role_id'];}
    function mac_url_website_detail($row){return '/website/'.$row['website_id'];}
}
namespace app\api\controller { function mac_url_search($param,$kind){return '/search/'.$kind.'?wd='.rawurlencode($param['wd']);} }
namespace app\index\controller { function mac_url_search($param,$kind){return '/search/'.$kind.'?wd='.rawurlencode($param['wd']);} }
namespace {
require dirname(__DIR__).'/vendor/autoload.php';require dirname(__DIR__).'/application/common.php';require __DIR__.'/fixtures/security_audit_test_helpers.php';
use think\facade\Db;
use app\common\util\ApiMeilisearchSuggest as Suggest;
use app\common\util\MeilisearchHttp as Transport;
function json($value){return \think\Response::create($value,'json');}
function config($key,$default=null){return \think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function model($name){$class='app\\common\\model\\'.ucfirst($name);return new $class();}
function request(){return \think\Container::getInstance()->make('request');}
class SuggestCache {
    public array $data=[];
    public function get($key){
        if(str_ends_with($key,'vip_exclusive_type_ids'))return [];
        if(str_ends_with($key,'type_list'))return [1=>['type_id'=>1,'type_pid'=>0,'type_name'=>'Public category','type_en'=>'fixture']];
        if(str_ends_with($key,'group_list'))return [];
        return $this->data[$key]??null;
    }
    public function set($key,$value,...$rest){$this->data[$key]=$value;}
    public function delete($key){unset($this->data[$key]);}
}
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new \RuntimeException('Dedicated MySQL fixture required');
$temp=audit_temp_dir('search-suggest');$app=new \think\App($temp);
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_suggest_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new \think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);$cache=new SuggestCache();$app->instance('cache',$cache);
$GLOBALS['config']=['app'=>['cache_flag'=>'suggest_fixture','cache_core'=>0,'count_cache_sec'=>0,'search'=>'1','search_len'=>64,'search_suggest_rate_ip'=>0],
    'upload'=>['protocol'=>'https'],'meilisearch'=>['enabled'=>'1','host'=>'https://fixture.invalid','index_uid'=>'suggest-fixture']];
$GLOBALS['user']=['user_id'=>0];$GLOBALS['mctheme']=['theme'=>[]];
$sql=[];$queryFault=false;Db::listen(static function($statement)use(&$sql,&$queryFault){
    $sql[]=$statement;
    if($queryFault && str_contains($statement,'vod_recycle_time') && preg_match('/^SELECT\b/i',$statement)){$queryFault=false;throw new \RuntimeException('Injected trace failure after a real guarded SQL query');}
});
function resetSuggestSearch(string $mode='ok',bool $enabled=true):void {
    $GLOBALS['config']['meilisearch']['enabled']=$enabled?'1':'0';Transport::$mode=$mode;Transport::$calls=[];
    (new \ReflectionProperty(\app\common\util\MeilisearchService::class,'searchMemo'))->setValue(null,[]);
}
function suggestApi(string $kind,string $keyword='match',int $limit=10):array {
    global $app;
    $request=(new \think\Request())->withGet(['wd'=>$keyword,'limit'=>$limit])->setController(ucfirst($kind))->setAction('suggest');$app->instance('request',$request);
    $controller=(new \ReflectionClass('app\\api\\controller\\'.ucfirst($kind)))->newInstanceWithoutConstructor();
    return json_decode($controller->suggest($request)->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function suggestAjax(int $mid,string $keyword='match',int $limit=10):array {
    global $app;
    $params=['mid'=>$mid,'wd'=>$keyword,'limit'=>$limit];
    $request=(new \think\Request())->withGet($params)->withServer(['REMOTE_ADDR'=>'127.0.0.1','REQUEST_METHOD'=>'GET'])->setController('Ajax')->setAction('suggest');$app->instance('request',$request);
    $controller=(new \ReflectionClass(\app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$controller->_param=$params;
    return json_decode($controller->suggest()->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function assertSuggestions(string $kind,array $result,array $ids,bool $ajax=false):void {
    check($result['code']===1 && array_is_list($result['list']),'Suggestions retain a successful JSON array');
    check(array_map('intval',array_column($result['list'],'id'))===$ids,'Suggestion ordering and visible IDs for '.$kind.' differ: '.json_encode(array_column($result['list'],'id')));
    foreach($result['list'] as $item){
        check(array_keys($item)===($ajax?['id','name','en','pic']:['id','name','en','pic',$kind.'_link']),'Only the documented suggestion fields are returned');
        check($item['name']==='match '.$item['id'] && $item['pic']==='/fixture/cover.png','Suggestion names and pictures remain usable');
        if(!$ajax)check($item[$kind.'_link']==='/'.$kind.'/'.$item['id'],'Suggestion links retain the selected source ID');
    }
    check(!str_contains(json_encode($result),'PRIVATE-'),'No unselected source fields escape suggestion projection');
}
$kinds=['vod','art','manga','actor','topic','role','website'];$tables=array_merge($kinds,['type','group']);
try {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach($tables as $table){preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$m);Db::execute(str_replace('`mac_'.$table.'`','`audit_suggest_'.$table.'`',$m[0]));}
    foreach($kinds as $kind){
        $defaults=[];$columns=[];
        foreach(Db::query('SHOW COLUMNS FROM audit_suggest_'.$kind) as $column){$columns[]=$column['Field'];if($column['Null']==='NO' && $column['Default']===null && !str_contains($column['Extra'],'auto_increment'))$defaults[$column['Field']]='';}
        foreach([10=>1,20=>1,30=>0,40=>1,50=>2] as $id=>$status){
            $row=[$kind.'_id'=>$id,$kind.'_name'=>'match '.$id,$kind.'_en'=>'match-'.$id,$kind.'_status'=>$status,$kind.'_pic'=>'cover.png',$kind.'_content'=>'PRIVATE-BODY-'.$kind,$kind.'_time'=>$id,$kind.'_hits_month'=>$id];
            if(in_array('type_id',$columns,true))$row['type_id']=1;
            if(in_array($kind.'_recycle_time',$columns,true))$row[$kind.'_recycle_time']=$id===40?time():0;
            elseif($id===40)$row[$kind.'_status']=0;
            Db::name($kind)->insert($row+$defaults);
        }
    }
    if(getenv('SEARCH_SUGGEST_REPRO')==='1'){
        check(Suggest::orderedDbRowsByIds('vod',[20,10])===[],'Reproduce valid SQL Collection discarded by the array check');
        resetSuggestSearch();check(array_column(suggestApi('vod')['list'],'id')===[20,10],'Reproduce Meili ordering lost through unnecessary MySQL fallback');
        $failed=false;try{resetSuggestSearch('empty',false);suggestApi('role');}catch(\think\db\exception\PDOException $error){$failed=str_contains($error->getMessage(),'type_id');}check($failed,'Reproduce role suggestions selecting a column missing from the installation schema');
        resetSuggestSearch('empty',false);$cache->data=[];$r=suggestAjax(3);check(!isset($r['list'][10]['id']) && str_contains(json_encode($r),'PRIVATE-BODY-topic'),'Reproduce raw topic rows instead of the declared Ajax fields');
        $sql=[];$queryFault=true;Suggest::orderedDbRowsByIds('vod',[40]);check((bool)array_filter($sql,fn($query)=>preg_match('/^SELECT\b/i',$query)&&str_contains($query,'audit_suggest_vod')&&!str_contains($query,'vod_recycle_time')),'Reproduce a broad exception retry dropping the recycle predicate');
        echo 'search_suggest_repro: 5 production compatibility/boundary failures confirmed on PHP '.PHP_VERSION.PHP_EOL;
    } else {require __DIR__.'/fixtures/search_suggest_cases.php';}
    echo 'framework_audit_search_suggest: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL'.PHP_EOL;
}finally{foreach($tables as $table)Db::execute('DROP TABLE IF EXISTS audit_suggest_'.$table);audit_remove_temp($temp);}
}
