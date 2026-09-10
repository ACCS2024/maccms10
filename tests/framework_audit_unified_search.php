<?php
/** Actual installed MySQL DDL, Request, ORM, Search and Meili service. External HTTP and page decoration are isolated. */
declare(strict_types=1);
namespace app\api\controller {
    class Base {public function __construct(){}}
    function mac_url_img($value){return $value===''?'':'/fixture/'.$value;}
    function mac_url_vod_detail($row){return '/vod/'.$row['vod_id'];}
    function mac_url_art_detail($row){return '/art/'.$row['art_id'];}
    function mac_url_manga_detail($row){return '/manga/'.$row['manga_id'];}
}
namespace app\common\util {
    class MeilisearchHttp {
        public static string $mode='ok';public static array $calls=[];public static array $hits=[];public static bool $ignoreLimit=false;
        public static function requestParallel($host,$jobs,...$arguments):array {
            if($host!=='https://fixture.invalid')throw new \RuntimeException('Unexpected external search destination');
            $out=[];foreach($jobs as $job){
                self::$calls[]=$job;preg_match('/kind = "(vod|art|manga)"/',$job['body']['filter'],$match);
                if(!isset($match[1]))throw new \RuntimeException('Unexpected search kind');
                if(self::$mode==='fail'){$out[]=['ok'=>false,'status'=>503,'error'=>'Fixture search unavailable'];continue;}
                if(self::$mode==='throw')throw new \RuntimeException('Fixture transport threw');
                $kind=$match[1];$hits=self::$mode==='empty'?[]:(self::$hits[$kind]??array_map(fn($id)=>['id'=>$kind.'_'.$id],[10,20,40,30,50,999]));
                if(!self::$ignoreLimit)$hits=array_slice($hits,$job['body']['offset'],$job['body']['limit']);
                $out[]=['ok'=>true,'status'=>200,'data'=>['hits'=>$hits,'estimatedTotalHits'=>66]];
            }return $out;
        }
    }
    function mac_url_img($value){return $value===''?'':'/fixture/'.$value;}
    function mac_url_vod_detail($row){return '/vod/'.$row['vod_id'];}
    function mac_url_art_detail($row){return '/art/'.$row['art_id'];}
    function mac_url_manga_detail($row){return '/manga/'.$row['manga_id'];}
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';require dirname(__DIR__).'/application/common.php';require __DIR__.'/fixtures/security_audit_test_helpers.php';
use think\facade\Db;
use app\common\util\MeilisearchHttp as Transport;
function json($value){return \think\Response::create($value,'json');}
function config($key,$default=null){return \think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function request(){return \think\Container::getInstance()->make('request');}
function app($name){return \think\Container::getInstance()->make($name);}
final class UnifiedSearchCache {
    public array $data=[];public array $ttl=[];public string $fault='';
    public function get($key,$default=null){
        if($this->fault==='get'&&str_starts_with($key,'api_search_'))throw new \RuntimeException('Fixture cache unavailable');
        if(str_ends_with($key,'vip_exclusive_type_ids'))return [];
        if(str_ends_with($key,'type_list'))return [1=>['type_id'=>1,'type_pid'=>0,'type_name'=>'Public category','type_en'=>'fixture']];
        return $this->data[$key]??$default;
    }
    public function set($key,$value,$ttl=null){if($this->fault==='set'&&str_starts_with($key,'api_search_'))throw new \RuntimeException('Fixture cache write unavailable');$this->data[$key]=$value;$this->ttl[$key]=$ttl;return true;}
    public function delete($key){unset($this->data[$key],$this->ttl[$key]);}
    public function store(){return $this;}public function handler(){return new \stdClass();}
}
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new \RuntimeException('Dedicated MySQL fixture required');
$temp=audit_temp_dir('unified-search');$app=new \think\App($temp);$logs=[];
$app->instance('log',new class($logs){public function __construct(private array &$lines){}public function record($message,...$args){$this->lines[]=$message;}public function error($message){$this->lines[]=$message;}});
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_unified_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new \think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);$cache=new UnifiedSearchCache();$app->instance('cache',$cache);
$GLOBALS['config']=['app'=>['cache_flag'=>'unified_fixture','cache_core'=>0,'count_cache_sec'=>0,'search'=>'1'],
    'api'=>['publicapi'=>['status'=>1,'charge'=>0]],'upload'=>['protocol'=>'https'],
    'meilisearch'=>['enabled'=>'0','host'=>'https://fixture.invalid','index_uid'=>'unified-fixture']];
$GLOBALS['user']=['user_id'=>0];$GLOBALS['mctheme']=['theme'=>[]];
$sql=[];$queryFault='';Db::listen(static function($statement)use(&$sql,&$queryFault){
    $sql[]=$statement;
    if($queryFault==='recycle'&&str_contains($statement,'audit_unified_vod')&&str_contains($statement,'vod_recycle_time')&&preg_match('/^SELECT\b/i',$statement)){$queryFault='';throw new \RuntimeException('Injected guarded query failure, private fixture detail');}
    if($queryFault==='schema'&&str_contains(strtolower($statement),'information_schema.columns')){$queryFault='';throw new \RuntimeException('Injected schema failure, private fixture detail');}
});
function unifiedRequest(string $endpoint,array $parameters=[],bool $enabled=false,string $mode='ok'):array {
    global $app;
    $GLOBALS['config']['meilisearch']['enabled']=$enabled?'1':'0';Transport::$mode=$mode;Transport::$calls=[];
    (new \ReflectionProperty(\app\common\util\MeilisearchService::class,'searchMemo'))->setValue(null,[]);
    $request=(new \think\Request())->withGet($parameters)->withServer(['REMOTE_ADDR'=>'127.0.0.1','REQUEST_METHOD'=>'GET'])->setController('Search')->setAction($endpoint);$app->instance('request',$request);
    $controller=new \app\api\controller\Search();
    return json_decode($controller->$endpoint($request)->getContent(),true,512,JSON_THROW_ON_ERROR);
}
$kinds=['vod','art','manga'];$tables=array_merge($kinds,['type']);
try {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach($tables as $table){preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$m);Db::execute(str_replace('`mac_'.$table.'`','`audit_unified_'.$table.'`',$m[0]));}
    foreach($kinds as $kind){
        $defaults=[];foreach(Db::query('SHOW COLUMNS FROM audit_unified_'.$kind) as $column){if($column['Null']==='NO'&&$column['Default']===null&&!str_contains($column['Extra'],'auto_increment'))$defaults[$column['Field']]='';}
        foreach([10=>1,20=>1,30=>0,40=>1,50=>2] as $id=>$status){
            $row=[$kind.'_id'=>$id,$kind.'_name'=>'match '.$id,$kind.'_en'=>'match-'.$id,$kind.'_status'=>$status,$kind.'_pic'=>'cover.png',
                $kind.'_content'=>'PRIVATE-BODY-'.$kind,$kind.'_time'=>$id,$kind.'_recycle_time'=>$id===40?time():0,'type_id'=>1];
            Db::name($kind)->insert($row+$defaults);
        }
    }
    if(getenv('SEARCH_UNIFIED_REPRO')==='1') {
        $r=unifiedRequest('index',['wd'=>'match','module'=>'vod']);check($r['info']['vod']['total']===2&&$r['info']['vod']['list']===[],'SQL Collection silent-empty failure changed');
        $cache->data=[];$r=unifiedRequest('index',['wd'=>'match','module'=>'vod'],true);check($r['info']['vod']['total']===66&&$r['info']['vod']['list']===[],'Meili Collection silent-empty failure changed');
        $failed=false;try{unifiedRequest('index',['wd'=>[]]);}catch(\TypeError $e){$failed=true;}check($failed,'Array keyword TypeError changed');
        $cache->data=[];$sql=[];$queryFault='recycle';unifiedRequest('index',['wd'=>'match','module'=>'vod']);check((bool)array_filter($sql,fn($q)=>preg_match('/^SELECT\b/i',$q)&&str_contains($q,'audit_unified_vod')&&!str_contains($q,'vod_recycle_time')),'Broad catch guard-removal retry changed');
        $cache->data=[];$before=unifiedRequest('suggest',['wd'=>'match']);Db::name('vod')->where('vod_id',20)->update(['vod_status'=>0]);$after=unifiedRequest('suggest',['wd'=>'match']);check($before===$after&&in_array(20,array_column(array_filter($after['info']['list'],fn($r)=>$r['module']==='vod'),'id'),true),'Hidden cached suggestion replay changed');
        echo 'Unified Search original: '.$checks.' regressions reproduced on PHP '.PHP_VERSION."\n";
    } else {require __DIR__.'/fixtures/unified_search_cases.php';echo 'Unified Search: '.$checks.' checks passed on PHP '.PHP_VERSION." / MySQL\n";}
} finally {foreach($tables as $table)Db::execute('DROP TABLE IF EXISTS audit_unified_'.$table);audit_remove_temp($temp);}
}
