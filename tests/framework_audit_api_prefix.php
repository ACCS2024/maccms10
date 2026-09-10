<?php
/** Real Request/controllers/ORM with two different data sets; no site bootstrap or external services. */
declare(strict_types=1);
namespace app\common\controller { class All {} }
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function($severity,$message,$file,$line){throw new \ErrorException($message,0,$severity,$file,$line);});
function json($data){return \think\Response::create($data,'json');}
function config($key,$default=null){return \think\facade\Config::get($key,$default);}
function lang($key){return $key;}
function mac_url_img($value){return '/fixture/'.$value;}
function prefixLink(string $kind,array $row): string {global $rendered;$rendered[$kind][]=$row;return '/'.$kind.'/'.$row[$kind.'_id'];}
function mac_url_vod_detail($row){return prefixLink('vod',$row);}
function mac_url_art_detail($row){return prefixLink('art',$row);}
function mac_url_manga_detail($row){return prefixLink('manga',$row);}
function mac_url_actor_detail($row){return prefixLink('actor',$row);}
function mac_url_topic_detail($row){return prefixLink('topic',$row);}
function mac_url_role_detail($row){return prefixLink('role',$row);}
function mac_url_website_detail($row){return prefixLink('website',$row);}
function mac_url_type($row){return '/type/'.$row['type_id'];}
function mac_user_fav_state(...$args){return ['is_fav'=>false,'fav_ulog_id'=>0];}
function mac_user_has_digg(...$args){return false;}
function mac_get_vip_exclusive_type_ids(){return [];}
// Keep the production array-by-reference contract. A later Collection group fixes the existing callers.
function mac_append_type_is_vip_exclusive_for_rows(array &$rows){foreach($rows as &$row){$row['type_is_vip_exclusive']=0;}}
class PrefixFixtureCache {
    public array $data=[];
    function get($key){return str_ends_with($key,'type_list')?[1=>['type_id'=>1,'type_pid'=>0,'type_en'=>'fixture']]:($this->data[$key]??null);}
    function set($key,$value,...$args){$this->data[$key]=$value;}
}
use think\facade\Db;
$checks=0;$rendered=[];$sql=[];$knownCollectionFailures=0;
function prefixCheck(bool $condition,string $message): void {global $checks;++$checks;if(!$condition)throw new \RuntimeException($message);}
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if(!is_string($socket)||$socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database)){
    fwrite(STDERR,"Only the disposable MySQL runner is supported.\n");exit(2);
}
$app=new \think\App(sys_get_temp_dir().'/maccms-api-prefix-fixture');
$configuration=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','database'=>$database,'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),
    'dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','charset'=>'utf8mb4',
    'prefix'=>'audit_api_','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($configuration,'database');$manager=new \think\DbManager();$manager->setConfig($configuration);
$app->instance('think\\DbManager',$manager);$cache=new PrefixFixtureCache();$app->instance('cache',$cache);
Db::listen(static function($statement,...$rest){global $sql;$sql[]=$statement;});
$GLOBALS['config']=['app'=>['cache_flag'=>'prefix_fixture','cache_core'=>0,'count_cache_sec'=>0],'upload'=>['protocol'=>'https']];
$GLOBALS['user']=['user_id'=>0];
$kinds=['vod','art','manga','actor','role','topic','website'];
function prefixCall(string $kind,string $action,array $params=[]): array {
    global $app,$cache,$sql,$rendered,$knownCollectionFailures;
    $cache->data=[];$sql=[];$rendered=[];
    $request=(new \think\Request())->withGet($params)->setController(ucfirst($kind))->setAction($action);
    $app->instance('request',$request);
    $controller=(new \ReflectionClass('app\\api\\controller\\'.ucfirst($kind)))->newInstanceWithoutConstructor();
    try {$response=$controller->$action($request);$result=json_decode($response->getContent(),true,512,JSON_THROW_ON_ERROR);}
    catch(\TypeError $error){
        // Do not widen the helper's signature just to turn a known 500 into a green prefix test.
        if(!in_array($kind,['art','manga'],true)||$action!=='get_latest'||!str_contains($error->getMessage(),'mac_append_type_is_vip_exclusive_for_rows()')||!str_contains($error->getMessage(),'think\\Collection given'))throw $error;
        ++$knownCollectionFailures;$result=['known_collection_failure'=>true];
    }
    foreach($sql as $statement){prefixCheck(!preg_match('/\b(?:FROM|JOIN)\s+`?mac_/i',$statement),$kind.'::'.$action.' queried the other table prefix');}
    foreach($rendered as $rowKind=>$rows){foreach($rows as $row){
        if(isset($row[$rowKind.'_name']))prefixCheck(str_starts_with($row[$rowKind.'_name'],'configured-'),$kind.'::'.$action.' rendered foreign '.$rowKind.' data');
    }}
    return $result;
}
function prefixRows(string $kind,array $result,array $expected): void {
    prefixCheck(($result['code']??null)===1 && isset($result['info']['rows']),$kind.' list keeps its JSON envelope');
    prefixCheck(array_map('intval',array_column($result['info']['rows'],$kind.'_id'))===$expected,$kind.' list returns configured rows in the expected order');
    foreach($result['info']['rows'] as $row)prefixCheck(str_starts_with($row[$kind.'_name'],'configured-'),$kind.' list contains another prefix');
}
try {
    foreach($kinds as $kind){
        $columns=[$kind.'_id INTEGER PRIMARY KEY','type_id INTEGER NOT NULL DEFAULT 1','type_id_1 INTEGER NOT NULL DEFAULT 1','group_id INTEGER NOT NULL DEFAULT 0'];
        foreach(['name','en','sub','alias','author','actor','director','sex','area','class','year','pic','pic_thumb','pic_slide','logo','content','blurb','remarks','rel_vod','rel_art'] as $field)$columns[]=$kind.'_'.$field." VARCHAR(255) NOT NULL DEFAULT ''";
        foreach(['status','time','hits','hits_day','hits_week','hits_month','score','points','level','rid','recycle_time'] as $field)$columns[]=$kind.'_'.$field.' INTEGER NOT NULL DEFAULT 0';
        foreach(['mac_','audit_api_'] as $prefix){
            Db::execute('DROP TABLE IF EXISTS '.$prefix.$kind);Db::execute('CREATE TABLE '.$prefix.$kind.' ('.implode(',',$columns).')');
            foreach($prefix==='mac_'?[10,20,30,99]:[10,20,30,40] as $id){
                $marker=$prefix==='mac_'?'foreign-':'configured-';
                $row=[$kind.'_id'=>$id,$kind.'_name'=>$marker.$kind.$id,$kind.'_pic'=>$marker.'cover.png',$kind.'_status'=>1,$kind.'_time'=>$id,$kind.'_hits_month'=>$id];
                if($kind==='vod')$row+=['vod_year'=>$marker.'year'.$id,'vod_class'=>$marker.'class'.$id,'vod_area'=>$marker.'area'.$id];
                if($kind==='topic')$row+=['topic_rel_vod'=>'20,10','topic_rel_art'=>'20,10'];
                if($kind==='role')$row+=['role_rid'=>20];
                Db::table($prefix.$kind)->insert($row);
            }
        }
    }
    // Type construction reads schema even when getCache() is backed by the isolated cache.
    Db::execute('CREATE TABLE audit_api_type (type_id INTEGER PRIMARY KEY)');
    foreach([false,true] as $removeForeign){
        if($removeForeign)foreach($kinds as $kind)Db::execute('DROP TABLE mac_'.$kind);
        foreach(['actor','role','vod','website'] as $kind){
            $result=prefixCall($kind,'get_detail',[$kind.'_id'=>20]);
            prefixCheck($result['code']===1 && $result['info'][$kind.'_name']==='configured-'.$kind.'20',$kind.' detail selects the configured prefix');
            prefixCheck($result['info'][$kind.'_pic']==='/fixture/configured-cover.png',$kind.' detail keeps image formatting');
            if($kind==='role')prefixCheck($result['info']['vod_info']['vod_name']==='configured-vod20','Role and its related video use one prefix');
            prefixCheck(prefixCall($kind,'get_detail',[$kind.'_id'=>99])['code']===1001,$kind.' detail cannot fall back to an ID existing only in another prefix');
        }
        $result=prefixCall('art','get_detail',['art_id'=>20]);
        prefixCheck($result['info']['art_name']==='configured-art20','Article body uses configured prefix');
        prefixCheck($result['info']['art_prev']['art_name']==='configured-art10' && $result['info']['art_next']['art_name']==='configured-art30','Both article neighbors use the same configured prefix');
        $result=prefixCall('topic','get_detail',['topic_id'=>20]);
        prefixCheck($result['info']['topic_name']==='configured-topic20','Topic detail uses configured prefix');
        foreach(['vod','art'] as $kind){
            prefixCheck(array_column($result['info']['topic_rel_'.$kind],$kind.'_name')===['configured-'.$kind.'20','configured-'.$kind.'10'],'Topic '.$kind.' relations keep order and configured data');
        }
        $missing=prefixCall('topic','get_detail',['topic_id'=>99]);
        prefixCheck($missing['code']===1 && empty($missing['info']),'Topic keeps its existing empty-detail JSON contract without cross-prefix fallback');
        foreach(['actor'=>'get_recommend','art'=>'get_hot','manga'=>'get_hot','topic'=>'get_recommend'] as $kind=>$action){
            prefixRows($kind,prefixCall($kind,$action,['num'=>2,'start'=>1]),[30,20]);
            prefixRows($kind,prefixCall($kind,$action,['num'=>2,'start'=>99]),[]);
        }
        $result=prefixCall('topic','get_recommend',['ids'=>'30,0,99,10','num'=>4]);
        prefixCheck(array_column($result['info']['rows'],'topic_id')===[30,0,0,10],'Explicit topic IDs preserve ordering and missing/zero placeholders');
        prefixCheck($result['info']['rows'][0]['topic_name']==='configured-topic30' && $result['info']['rows'][3]['topic_name']==='configured-topic10','Explicit topic IDs select configured content');
        foreach(['art','manga'] as $kind){
            foreach([1=>[30,20],99=>[]] as $start=>$ids){
                $result=prefixCall($kind,'get_latest',['num'=>2,'start'=>$start]);
                if(isset($result['known_collection_failure'])){
                    prefixCheck(array_map('intval',array_column($rendered[$kind]??[],$kind.'_id'))===$ids,$kind.' latest query selects configured pagination before the independently tracked Collection failure');
                    prefixCheck((bool)array_filter($sql,static fn($statement)=>str_contains($statement,'`audit_api_'.$kind.'`')&&str_starts_with($statement,'SELECT')),$kind.' latest executes the configured query even for an empty result');
                }else{prefixRows($kind,$result,$ids);}
            }
        }
        foreach(['get_year'=>'year','get_class'=>'class','get_area'=>'area'] as $action=>$field){
            $result=prefixCall('vod',$action,['type_id_1'=>1]);$rows=$result['info']['rows'];sort($rows);
            prefixCheck($rows===['configured-'.$field.'10','configured-'.$field.'20','configured-'.$field.'30','configured-'.$field.'40'],$action.' queries configured metadata');
            prefixCheck($result['info']['total']===4,$action.' keeps metadata cardinality');
            prefixCheck(prefixCall('vod',$action,['type_id_1'=>999])['info']['rows']===[],$action.' keeps empty metadata arrays');
        }
    }
    echo 'framework_audit_api_prefix: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL; '.$knownCollectionFailures.' known latest-list Collection failures observed (not fixed in this group)'.PHP_EOL;
} finally {
    foreach($kinds as $kind)foreach(['mac_','audit_api_'] as $prefix)Db::execute('DROP TABLE IF EXISTS '.$prefix.$kind);
    Db::execute('DROP TABLE IF EXISTS audit_api_type');
}
}
