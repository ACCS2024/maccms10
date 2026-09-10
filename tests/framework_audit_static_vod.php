<?php
/** Actual content/user/permission models and installation DDL; only presentation helpers are isolated. */
declare(strict_types=1);
namespace app\common\model { class HelpCfg {public static function get($key,$default=null){return $default;}} class SeoAiResult { public function getByObject(...$args){return [];} } }
namespace app\common\controller {
    function mac_url_vod_play($row,$p=[]){return '/play/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
    function mac_url_vod_down($row,$p=[]){return '/down/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
    function mac_user_fav_state(...$args){return ['is_fav'=>0,'fav_ulog_id'=>0];}
    function mac_vod_play_tagwall_payload(...$args){return ['enabled'=>false,'json'=>'[]'];}
}
namespace app\api\controller {
    function mac_url_img($value){return '/fixture/'.$value;}
    function mac_url_vod_play($row,$p=[]){return '/play/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
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
class VodAccessCache {
    public array $data=[];
    public function get($key,$default=null){return $this->data[$key]??$default;}
    public function set($key,$value,...$args){$this->data[$key]=$value;return true;}
    public function delete($key){unset($this->data[$key]);return true;}
}
class VodPageProbe extends app\index\controller\Vod {
    public array $assigned=[];
    public function __construct(){}
    protected function assign($name,$value=''):void{if(is_array($name))$this->assigned=array_merge($this->assigned,$name);else $this->assigned[$name]=$value;}
    protected function label_fetch($tpl,$loadcache=1,$type='html'){return $tpl;}
    protected function page_error($msg=''){throw new RuntimeException('Page denied: '.$msg);}
}
define('IN_FILE','api.php');define('ENTRANCE','api');define('MAC_PLAYER_SORT','1');define('MAC_PATH',getenv('STATIC_VOD_PREFIX') ?: '/');
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new RuntimeException('Dedicated MySQL fixture required');
$temp=audit_temp_dir('static-vod');mkdir($temp.'/site');define('ROOT_PATH',$temp.'/site/');define('APP_PATH',dirname(__DIR__).'/application/');$app=new think\App($temp.'/app');
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_resource_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);
$app->config->set(['type'=>'file','name'=>'resource_session','path'=>$temp.'/sessions','expire'=>3600],'session');
$cache=new VodAccessCache();$app->instance('cache',$cache);
$GLOBALS['config']=['api'=>['publicapi'=>['status'=>1,'charge'=>0]],'site'=>['site_status'=>1],'app'=>['cache_flag'=>'resource_fixture','cache_core'=>0,'count_cache_sec'=>0,'encrypt'=>0,'copyright_status'=>0,'ajax_page'=>1,
    'api_jwt_enabled'=>'1','api_jwt_secret'=>str_repeat('synthetic-key-',4),'api_jwt_iss'=>'vod-resource-audit'],
    'user'=>['status'=>1,'vod_points_type'=>'0','trysee'=>2],'rewrite'=>['vod_id'=>0,'status'=>1,'suffix_hide'=>0,'encode_len'=>6,'encode_key'=>'fixture-key']];
$cache->data['resource_fixture_type_list']=[1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>1,'type_name'=>'Videos','type_tpl_detail'=>'','type_tpl_play'=>'','type_tpl_down'=>'']];
$groups=[];foreach([1=>'Guest',2=>'Member',3=>'VIP',4=>'BlockedVIP',5=>'Extra'] as $id=>$name)$groups[$id]=['group_id'=>$id,'group_name'=>$name,'group_type'=>'1,','group_popedom'=>[1=>[2=>1,3=>$id!==4?1:0,4=>$id!==4?1:0,5=>1]]];
$cache->data['resource_fixture_group_list']=$groups;$cache->data['resource_fixture_vip_exclusive_type_ids']=[];
$players=['source'=>['show'=>'线路一','from'=>'source','sort'=>2,'status'=>1,'private'=>'PRIVATE-CONFIG'],
    'backup'=>['show'=>'线路二','from'=>'backup','sort'=>1,'status'=>1,'private'=>'PRIVATE-CONFIG']];
$app->config->set($players,'vodplayer');$app->config->set($players,'voddowner');$app->config->set(['server'=>['url'=>'https://PRIVATE-SERVER.invalid']],'vodserver');$app->config->set(['comment'=>[],'player'=>$players],'maccms');
function vodRequest(array $parameters=[],int $uid=0,array $state=[],string $action='get_play_info',?string $sessionId=null,array $cookies=[]):void {
    global $app;
    $_COOKIE=$cookies;$_REQUEST=[];
    $header=$uid>0?['authorization'=>'Bearer '.JwtService::encode($uid,'fixture-'.$uid)]:[];
    $r=think\Request::__make($app)->withGet($parameters)->withHeader($header)->withServer(['REQUEST_METHOD'=>'GET'])->setController('Vod')->setAction($action);
    $s=new think\Session($app);if($sessionId!==null)$s->setId($sessionId);$s->init();foreach($state as $key=>$value)$s->set($key,$value);
    $r->withSession($s);$app->instance('request',$r);$app->instance('session',$s);$app->instance('cookie',new think\Cookie($r));
    $GLOBALS['user']=[];
    $identity=(new ReflectionClass(app\common\controller\All::class))->newInstanceWithoutConstructor();
    (new ReflectionMethod($identity,'label_user'))->invoke($identity);
}
function vodApi(string $action,array $parameters,int $uid=0,array $state=[],?string $sessionId=null,array $cookies=[]):array {
    vodRequest($parameters,$uid,$state,$action,$sessionId,$cookies);
    $controller=new app\api\controller\Vod();
    return json_decode($controller->$action(request())->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function noVodSecrets($value,array $allowed=[]):void {
    $text=is_string($value)?$value:json_encode($value,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
    foreach(['PWD-DETAIL','PWD-PLAY','PWD-DOWN','PRIVATE-CONFIG','PRIVATE-SERVER',
        'MEDIA-PLAY-1','MEDIA-PLAY-2','MEDIA-PLAY-3','MEDIA-DOWN-1','MEDIA-DOWN-2','MEDIA-DOWN-3'] as $marker){
        if(in_array($marker,$allowed,true))continue;
        check(!str_contains($text,$marker),'Unexpected secret/unapproved resource '.$marker);
        check(!str_contains($text,base64_encode('https://fixture.invalid/'.$marker)),'Encoded unapproved resource escaped');
        check(!str_contains($text,base64_encode(mac_escape('https://fixture.invalid/'.$marker))),'Player-encoded unapproved resource escaped');
    }
}
function purchase(int $uid,int $type,int $sid,int $nid,int $points,int $rid=1):void {
    Db::name('ulog')->insert(['user_id'=>$uid,'ulog_mid'=>1,'ulog_type'=>$type,'ulog_rid'=>$rid,'ulog_sid'=>$sid,'ulog_nid'=>$nid,'ulog_points'=>$points,'ulog_time'=>time()]);
}
$sqlTrace=[];Db::listen(function($sql)use(&$sqlTrace){$sqlTrace[]=$sql;});

class StaticMakeProbe extends app\admin\controller\Make {
    public array $links=[];
    public function __construct(){}
    protected function label_maccms(){}
    protected function echoLink($description,$url='',$color='',$wrap=1){$this->links[]=[$description,$url];}
}
class StaticRouteProbe extends think\Route {
    public function inspect(think\Request $request): array {
        $this->request=$request;$this->host=$request->host(true);
        $url=str_replace($this->config['pathinfo_depr'],'|',$this->path());
        $dispatch=$this->check($url,(bool)$this->config['route_complete_match']);$dispatch=$dispatch?:$this->checkUrlDispatch($url);
        $dispatch->init($this->app);return [$request->controller(),$request->action(),$request->param()];
    }
}
function runStaticMake(string $operation,int $mode,?string $sessionId=null){
    global $sqlTrace;
    $GLOBALS['config']['view']=['vod_detail'=>1,'vod_play'=>1,'vod_down'=>1];$GLOBALS['config']['view']['vod_'.$operation]=$mode;
    vodRequest([],2,[],'info',$sessionId);request()->withServer(['HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest']);
    $make=new StaticMakeProbe();$make->_param=['tab'=>'vod','ids'=>'1','vodtype'=>[],'num'=>0,'start'=>1,'page_count'=>1,'data_count'=>0,'ac2'=>'','ref'=>0];
    $sqlTrace=[];ob_start();try{$result=$make->info();}finally{ob_end_clean();}return [$make,$result];
}
$tables=['vod','user','ulog','type','group'];$exports=[];
try {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach($tables as $table){preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$m);Db::execute(str_replace('`mac_'.$table.'`','`audit_resource_'.$table.'`',$m[0]));}
    Db::name('user')->insert(['user_id'=>2,'user_name'=>'member-2','user_random'=>'fixture-2','user_status'=>1,'group_id'=>'3','user_points'=>100,'user_end_time'=>time()+3600]);
    $row=['vod_id'=>1,'vod_name'=>'Secret title','vod_en'=>'rewritten-video','vod_status'=>1,'type_id'=>1,'vod_points'=>9,'vod_points_play'=>3,'vod_points_down'=>4,'vod_pwd'=>'PWD-DETAIL','vod_pwd_play'=>'PWD-PLAY','vod_pwd_down'=>'PWD-DOWN','vod_content'=>'','vod_plot_name'=>'','vod_plot_detail'=>''];
    foreach(['play','down'] as $operation){$row['vod_'.$operation.'_from']='backup$$$source$$$backup';$row['vod_'.$operation.'_url']='备用$https://fixture.invalid/MEDIA-'.strtoupper($operation).'-3$$$#第二集$https://fixture.invalid/MEDIA-'.strtoupper($operation).'-1##第四集$https://fixture.invalid/MEDIA-'.strtoupper($operation).'-2$$$';}
    Db::name('vod')->insert($row);
    $GLOBALS['config']['path']=['vod_play'=>'generated/play/{id}','vod_down'=>'generated/down/{id}','suffix'=>'html','page_sp'=>'-'];
    foreach(['play','down'] as $operation){foreach([2,3,4] as $mode){
        if(is_dir(ROOT_PATH.'generated'))audit_remove_temp(ROOT_PATH.'generated');
        Db::name('vod')->where('vod_id',1)->update(['vod_time_make'=>0]);
        $grant=vodApi('verify_pwd',['id'=>1,'type'=>$operation==='play'?4:5,'pwd'=>$operation==='play'?'PWD-PLAY':'PWD-DOWN'],2);check($grant['code']===1,'Generation fixture has a genuine authorized member password grant');$sessionId=$app->session->getId();$app->session->save();
        [$make,$result]=runStaticMake($operation,$mode,$sessionId);check($result===null,'Normal static generation completes');
        $files=[];$iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator(ROOT_PATH,FilesystemIterator::SKIP_DOTS));foreach($iterator as $file)if($file->isFile())$files[]=$file->getPathname();
        check(count($files)===([2=>1,3=>3,4=>2][$mode]),'Modes 2/3/4 produce one/per-episode/per-source artifact using actual nonempty keys');
        $fresh=(new app\common\model\Vod())->infoData(['vod_id'=>1],'*',0)['info'];$pages=app\common\util\StaticVideoRedirect::pages($fresh,$operation,$mode);
        check($pages[0]['sid']===2 && $pages[0]['nid']===2,'Default redirect uses the actual sorted source and first nonempty episode');
        foreach($pages as $page){$html=app\common\util\StaticVideoRedirect::render($page);noVodSecrets($html);check(!str_contains($html,'Secret title'),'Static transport contains no user-authorized display payload');$path=app\common\util\StaticVideoRedirect::write($page['url'],$html,ROOT_PATH);check(file_get_contents($path)===$html,'Real published artifact matches the safe redirect');$exports[]=$page+['html'=>$html,'prefix'=>MAC_PATH];}
        check((int)Db::name('vod')->where('vod_id',1)->value('vod_time_make')>0,'Progress advances only after all requested artifacts succeed');
        check(count(array_filter($sqlTrace,fn($sql)=>preg_match('/^(INSERT|UPDATE|DELETE).*audit_resource_(?:user|ulog)/',$sql)))===0,'Static generation does not read authorization as a payment or change member balances');
    }}
    // Real router verifies the fixed PHP entry despite dynamic/static and legacy route settings.
    foreach([0,1] as $legacy){$app->config->set(['app'=>['legacy_pathinfo_url'=>$legacy]],'maccms');$route=new StaticRouteProbe($app);$app->instance('route',$route);require dirname(__DIR__).'/application/index/route/web.php';
        $r=(new think\Request())->withServer(['REQUEST_METHOD'=>'GET','HTTP_HOST'=>'fixture.invalid','SCRIPT_NAME'=>MAC_PATH.'index.php'])->setPathinfo('vod/resource')->withGet(['id'=>'1','operation'=>'play','sid'=>'2','nid'=>'4']);$app->instance('request',$r);
        [$controller,$action,$param]=$route->inspect($r);check($controller==='Vod' && $action==='resource' && $param['id']==='1' && $param['sid']==='2' && $param['nid']==='4','Dynamic target dispatches to the guarded action with exact numeric coordinates in both route modes');
    }
    $app->config->set(['comment'=>[],'player'=>[]],'maccms');
    foreach([0,1,2] as $rewrite){$GLOBALS['config']['rewrite']['vod_id']=$rewrite;
        foreach(['play','down'] as $operation){vodRequest(['id'=>1,'operation'=>$operation,'sid'=>2,'nid'=>4],0,[],'resource');$page=new VodPageProbe();$template=$page->resource();check(str_ends_with($template,'_pwd'),'A fresh guest request to the static target must pass the corresponding password');noVodSecrets($page->assigned);
            $res=vodApi('verify_pwd',['id'=>1,'type'=>$operation==='play'?4:5,'pwd'=>$operation==='play'?'PWD-PLAY':'PWD-DOWN'],2);check($res['code']===1,'Actual scoped password grants work before the dynamic target');$sessionId=$app->session->getId();$app->session->save();
            vodRequest(['id'=>1,'operation'=>$operation,'sid'=>2,'nid'=>4],2,[],'resource',$sessionId);$page=new VodPageProbe();$page->resource();check($page->assigned['param']['id']===1 && $page->assigned['param']['sid']===2 && $page->assigned['param']['nid']===4,'The new dynamic action always resolves a numeric ID, independent of configured slug/encoded IDs');noVodSecrets($page->assigned,$operation==='play'?['MEDIA-PLAY-2']:['MEDIA-DOWN-1','MEDIA-DOWN-2','MEDIA-DOWN-3']);
        }
    }
    $GLOBALS['config']['rewrite']['vod_id']=0;
    foreach([['id'=>[]],['id'=>0],['operation'=>'unknown'],['sid'=>2,'nid'=>3]] as $bad){vodRequest(array_replace(['id'=>1,'operation'=>'play','sid'=>2,'nid'=>2],$bad),0,[],'resource');$page=new VodPageProbe();$denied=false;try{$page->resource();}catch(RuntimeException $e){$denied=str_starts_with($e->getMessage(),'Page denied:');}check($denied,'Malformed or missing dynamic resources are rejected');noVodSecrets($page->assigned);}

    // Paid/password checks are repeated for a fresh request even when an earlier visitor was authorized.
    vodRequest(['id'=>1,'operation'=>'play','sid'=>2,'nid'=>4],0,[],'resource');$page=new VodPageProbe();check($page->resource()==='vod/player_pwd','A following anonymous visitor never inherits the earlier member password grant');noVodSecrets($page->assigned);
    Db::name('vod')->where('vod_id',1)->update(['vod_pwd_play'=>'']);vodRequest(['id'=>1,'operation'=>'play','sid'=>2,'nid'=>4],0,[],'resource');$page=new VodPageProbe();$page->resource();check(!$page->assigned['popedom']['can_access'] && $page->assigned['player_data']==='','Password-free dynamic redirects still enforce paid resource permission');noVodSecrets($page->assigned);Db::name('vod')->where('vod_id',1)->update(['vod_pwd_play'=>'PWD-PLAY']);

    vodRequest(['id'=>1,'operation'=>'play','sid'=>2,'nid'=>4],0,[],'resource');check(!app\common\util\ContentCachePolicy::isPublicCatalog(request()),'The new dynamic entry is never an anonymous shared catalog page');$response=(new app\middleware\SecurityHeaders())->handle(request(),static fn()=>think\Response::create('DYNAMIC-AUTHORIZATION','html'));check($response->getHeader('Cache-Control')==='private, no-store','Even a guest dynamic redirect target receives private no-store transport headers');
    // Output boundaries and failed generation must preserve prior files and leave progress unchanged.
    $valid=app\common\util\StaticVideoRedirect::render($exports[0]);
    foreach(['/../escape.html','/application/test.html','/generated/test.php','/generated/%2e%2e/escape.html','https://outside.invalid/x.html'] as $bad){$denied=false;try{app\common\util\StaticVideoRedirect::write($bad,$valid,ROOT_PATH);}catch(RuntimeException $e){$denied=true;}check($denied,'Static writer rejects paths outside the HTML output contract');}
    mkdir($temp.'/outside');symlink($temp.'/outside',ROOT_PATH.'linked');$denied=false;try{app\common\util\StaticVideoRedirect::write(MAC_PATH.'linked/escape.html',$valid,ROOT_PATH);}catch(RuntimeException $e){$denied=true;}check($denied && !file_exists($temp.'/outside/escape.html'),'Static writer never follows a directory symlink outside the site');unlink(ROOT_PATH.'linked');

    $unicode=app\common\util\StaticVideoRedirect::write(MAC_PATH.'生成目录/影片.html',$valid,ROOT_PATH);check(file_get_contents($unicode)===$valid,'Valid UTF-8 static output paths remain supported');
    file_put_contents($temp.'/outside/existing.html','OUTSIDE-SENTINEL');symlink($temp.'/outside/existing.html',ROOT_PATH.'linked.html');$denied=false;try{app\common\util\StaticVideoRedirect::write(MAC_PATH.'linked.html',$valid,ROOT_PATH);}catch(RuntimeException $e){$denied=true;}check($denied && file_get_contents($temp.'/outside/existing.html')==='OUTSIDE-SENTINEL','An existing target symlink cannot overwrite outside content');unlink(ROOT_PATH.'linked.html');
    $previous=ROOT_PATH.'preserved.html';file_put_contents($previous,'OLD-PUBLIC-FILE');$GLOBALS['config']['path']['vod_play']='../bad/{id}';Db::name('vod')->where('vod_id',1)->update(['vod_time_make'=>0]);[$make,$result]=runStaticMake('play',3);check(json_decode($result->getContent(),true)['code']===0 && app\common\controller\All::$lastJumpCode===0,'Make reports a real output failure instead of success');check((int)Db::name('vod')->where('vod_id',1)->value('vod_time_make')===0 && file_get_contents($previous)==='OLD-PUBLIC-FILE','Failed output leaves progress and unrelated existing HTML untouched');
    // Actual filesystem conflicts exercise caught write failures, beyond path validation alone.
    mkdir(ROOT_PATH.'blocked');mkdir(ROOT_PATH.'blocked/1.html');$GLOBALS['config']['path']['vod_play']='blocked/{id}';
    [$make,$result]=runStaticMake('play',2);check(json_decode($result->getContent(),true)['code']===0 && is_dir(ROOT_PATH.'blocked/1.html'),'A directory at the real output filename reports failure and is preserved');
    check((int)Db::name('vod')->where('vod_id',1)->value('vod_time_make')===0,'A real filesystem publication failure cannot advance generation progress');
    file_put_contents(ROOT_PATH.'not-a-directory','EXISTING-FILE');$GLOBALS['config']['path']['vod_play']='not-a-directory/{id}';
    [$make,$result]=runStaticMake('play',2);check(json_decode($result->getContent(),true)['code']===0 && file_get_contents(ROOT_PATH.'not-a-directory')==='EXISTING-FILE','An output parent that is a regular file fails without overwriting it');
    check((int)Db::name('vod')->where('vod_id',1)->value('vod_time_make')===0,'Directory creation failure leaves progress unchanged');
    $GLOBALS['config']['path']['vod_play']='generated/play/{id}';Db::name('vod')->where('vod_id',1)->update(['vod_play_from'=>'','vod_play_url'=>'']);[$make,$result]=runStaticMake('play',3);check($result===null && count(array_filter($make->links,fn($link)=>str_contains($link[0],'无可用资源')))===1,'Empty sources are explicitly skipped without indexing nonexistent source or episode keys');
    file_put_contents('/audit/static-vod-redirects.json',json_encode($exports,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
    echo 'framework_audit_static_vod: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL (prefix '.MAC_PATH.')'.PHP_EOL;
}finally{foreach($tables as $table)Db::execute('DROP TABLE IF EXISTS audit_resource_'.$table);audit_remove_temp($temp);}
}
