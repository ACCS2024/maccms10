<?php
/** Actual content/user/permission models and installation DDL; only presentation helpers are isolated. */
declare(strict_types=1);
namespace app\common\model { class HelpCfg {public static function get($key,$default=null){return $default;}} class SeoAiResult { public function getByObject(...$args){return [];} } }
namespace app\common\controller {
    function mac_url_art_detail($row,$p=[]){return '/art/'.$row['art_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
    function mac_user_fav_state(...$args){return ['is_fav'=>0,'fav_ulog_id'=>0];}
}
namespace app\api\controller {
    function mac_url_img($value){return '/fixture/'.$value;}
    function mac_url_art_detail($row,$p=[]){return '/art/'.$row['art_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\ContentResource;
use app\common\util\ContentPassword;
use app\common\util\JwtService;
use think\facade\Db;
function config($key,$default=null){return think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function model($name){$class='app\\common\\model\\'.ucfirst($name);return new $class();}
function input(){return request()->param();}
function request(){return think\Container::getInstance()->make('request');}
function url($model,$params=[]){return '/'.basename($model).'/'.($params['id']??1).'/'.($params['sid']??1).'/'.($params['nid']??1);}
function json($value){return think\Response::create($value,'json');}
function cookie($name,...$args){$c=think\Container::getInstance()->make('cookie');if($args===[])return $c->get($name);if($args[0]===null)return $c->delete($name);return $c->set($name,(string)$args[0],$args[1]??null);}
function session($name,...$args){$s=think\Container::getInstance()->make('session');if($args===[])return $s->get($name);if($args[0]===null)return $s->delete($name);return $s->set($name,$args[0]);}
class ArtAccessCache implements Psr\SimpleCache\CacheInterface {
    public array $data=[];
    public function get(string $key,mixed $default=null):mixed{return $this->data[$key]??$default;}
    public function set(string $key,mixed $value,null|int|DateInterval $ttl=null):bool{$this->data[$key]=$value;return true;}
    public function delete(string $key):bool{unset($this->data[$key]);return true;}
    public function clear():bool{$this->data=[];return true;}
    public function has(string $key):bool{return array_key_exists($key,$this->data);}
    public function getMultiple(iterable $keys,mixed $default=null):iterable{$out=[];foreach($keys as $key)$out[$key]=$this->get($key,$default);return $out;}
    public function setMultiple(iterable $values,null|int|DateInterval $ttl=null):bool{foreach($values as $key=>$value)$this->set($key,$value,$ttl);return true;}
    public function deleteMultiple(iterable $keys):bool{foreach($keys as $key)$this->delete($key);return true;}
}
class ArtPageProbe extends app\index\controller\Art {
    public array $assigned=[];
    public function __construct(){}
    protected function assign($name,$value=''):void{if(is_array($name))$this->assigned=array_merge($this->assigned,$name);else $this->assigned[$name]=$value;}
    protected function label_fetch($tpl,$loadcache=1,$type='html'){return $tpl;}
    protected function page_error($msg=''){throw new RuntimeException('Page denied: '.$msg);}
}
class ArtMakeProbe extends app\admin\controller\Make {
    public array $assigned=[];
    public $renderer;
    public function __construct(){}
    protected function assign($name,$value=''):void{if(is_array($name))$this->assigned=array_merge($this->assigned,$name);else $this->assigned[$name]=$value;}
    protected function label_maccms(){}
    protected function echoLink($description,$url='',$color='',$wrap=1){}
    protected function label_fetch($template,$loadcache=1,$type='html'){return ($this->renderer)($this->assigned);}
}
define('MAC_PAGE_SP','-');define('IN_FILE','api.php');define('ENTRANCE','api');define('MAC_PLAYER_SORT','1');define('MAC_PATH',getenv('ART_AUDIT_PREFIX') ?: '/');
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new RuntimeException('Dedicated MySQL fixture required');
$temp=audit_temp_dir('art-resource');mkdir($temp.'/site');define('ROOT_PATH',$temp.'/site/');define('APP_PATH',dirname(__DIR__).'/application/');$app=new think\App($temp.'/app');
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_resource_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);
$app->config->set(['type'=>'file','name'=>'resource_session','path'=>$temp.'/sessions','expire'=>3600],'session');
$cache=new ArtAccessCache();$app->instance('cache',$cache);
$GLOBALS['config']=['api'=>['publicapi'=>['status'=>1,'charge'=>0]],'site'=>['site_status'=>1],'upload'=>['protocol'=>'https','mode'=>'local','img_key'=>''],'app'=>['cache_flag'=>'resource_fixture','cache_core'=>0,'count_cache_sec'=>0,'encrypt'=>0,'copyright_status'=>0,'ajax_page'=>1,
    'api_jwt_enabled'=>'1','api_jwt_secret'=>str_repeat('synthetic-key-',4),'api_jwt_iss'=>'vod-resource-audit'],
    'user'=>['status'=>1,'vod_points_type'=>'0','art_points_type'=>'0','trysee'=>2],'rewrite'=>['vod_id'=>0,'art_id'=>0,'type_id'=>0,'status'=>1,'suffix_hide'=>0,'encode_len'=>6,'encode_key'=>'fixture-key']];
$cache->data['resource_fixture_type_list']=[1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>2,'type_name'=>'Articles','type_tpl_detail'=>'','type_tpl_play'=>'','type_tpl_down'=>'']];
$groups=[];foreach([1=>'Guest',2=>'Member',3=>'VIP',4=>'BlockedVIP',5=>'Extra'] as $id=>$name)$groups[$id]=['group_id'=>$id,'group_name'=>$name,'group_type'=>'1,','group_popedom'=>[1=>[2=>1,3=>$id!==4?1:0,4=>$id!==4?1:0,5=>1]]];
$cache->data['resource_fixture_group_list']=$groups;$cache->data['resource_fixture_vip_exclusive_type_ids']=[];
function artRequest(array $parameters=[],int $uid=0,array $state=[],string $action='get_read_page',?string $sessionId=null,array $cookies=[]):void {
    global $app;
    $_COOKIE=$cookies;$_REQUEST=[];
    $header=$uid>0?['authorization'=>'Bearer '.JwtService::encode($uid,md5('fixture-'.$uid))]:[];
    $r=think\Request::__make($app)->withGet($parameters)->withHeader($header)->withServer(['REQUEST_METHOD'=>'GET'])->setController('Art')->setAction($action);
    $s=new think\Session($app);if($sessionId!==null)$s->setId($sessionId);$s->init();foreach($state as $key=>$value)$s->set($key,$value);
    $r->withSession($s);$app->instance('request',$r);$app->instance('session',$s);$app->instance('cookie',new think\Cookie($r));
    $GLOBALS['user']=[];
    $identity=(new ReflectionClass(app\common\controller\All::class))->newInstanceWithoutConstructor();
    (new ReflectionMethod($identity,'label_user'))->invoke($identity);
}
function artApi(string $action,array $parameters,int $uid=0,array $state=[],?string $sessionId=null,array $cookies=[]):array {
    artRequest($parameters,$uid,$state,$action,$sessionId,$cookies);
    try { $controller=new app\api\controller\Art(); $response=$controller->$action(request()); }
    catch (think\exception\HttpResponseException $error) { $response=$error->getResponse(); }
    return json_decode($response->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function noArtSecrets($value,array $allowed=[]):void {
    $text=is_string($value)?$value:json_encode($value,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
    foreach(['PWD-ART','BODY-PAGE-1','BODY-PAGE-2','BODY-PAGE-3','BODY-OTHER'] as $marker){
        if(in_array($marker,$allowed,true))continue;
        check(!str_contains($text,$marker),'Unexpected article password or unauthorized chapter '.$marker);
    }
}
function purchase(int $uid,int $page,int $points,int $rid=1,int $mid=2,int $type=1):void {
    Db::name('ulog')->insert(['user_id'=>$uid,'ulog_mid'=>$mid,'ulog_type'=>$type,'ulog_rid'=>$rid,'ulog_sid'=>$page,'ulog_nid'=>0,'ulog_points'=>$points,'ulog_time'=>time()]);
}
$sqlTrace=[];Db::listen(function($sql)use(&$sqlTrace){$sqlTrace[]=$sql;});

$tables=['art','user','ulog','type','group'];
try {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach($tables as $table){preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$m);Db::execute(str_replace('`mac_'.$table.'`','`audit_resource_'.$table.'`',$m[0]));}
    foreach([1=>'2',2=>'3',3=>'4',4=>'2,5'] as $id=>$group)Db::name('user')->insert(['user_id'=>$id,'user_name'=>'member-'.$id,'user_random'=>md5('fixture-'.$id),'user_status'=>1,'group_id'=>$group,'user_points'=>100,'user_end_time'=>time()+3600]);
    $row=['art_id'=>1,'art_name'=>'Public article name','art_en'=>'rewritten-article','art_status'=>1,'type_id'=>1,'art_points'=>9,'art_points_detail'=>3,'art_pwd'=>'PWD-ART',
        'art_blurb'=>'Public introduction','art_title'=>'First$$$Second$$$Third','art_note'=>'One$$$Two$$$Three','art_content'=>'<p>BODY-PAGE-1</p>$$$<p>BODY-PAGE-2</p>$$$<p>BODY-PAGE-3</p>'];
    Db::name('art')->insert($row);
    require __DIR__.'/fixtures/art_resource_cases.php';
    require __DIR__.'/fixtures/art_resource_templates.php';
    echo 'framework_audit_art_access: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL (prefix '.MAC_PATH.')'.PHP_EOL;

}finally{foreach($tables as $table)Db::execute('DROP TABLE IF EXISTS audit_resource_'.$table);audit_remove_temp($temp);}
}
