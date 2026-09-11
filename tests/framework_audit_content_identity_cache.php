<?php
/** Real All/User/JWT/Request/Cookie/Session and disposable MySQL; no site bootstrap. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\JwtService;
use think\facade\Db;
function config($key,$default=null){return think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function request(){return think\Container::getInstance()->make('request');}
function cookie($name,...$args){
    $cookie=think\Container::getInstance()->make('cookie');
    if($args===[])return $cookie->get($name);
    if($args[0]===null)return $cookie->delete($name);
    return $cookie->set($name,(string)$args[0],$args[1]??null);
}
function session($name,...$args){
    $session=think\Container::getInstance()->make('session');
    if($args===[])return $session->get($name);
    return $session->set($name,$args[0]);
}
class IdentityCache {
    public array $data=[];
    public array $reads=[];
    public array $writes=[];
    public function get($key,$default=null){$this->reads[]=$key;return $this->data[$key]??$default;}
    public function set($key,$value,...$args){$this->writes[]=$key;$this->data[$key]=$value;return true;}
    public function add($key,$value,...$args){if(isset($this->data[$key]))return false;return $this->set($key,$value);}
    public function delete($key){unset($this->data[$key]);return true;}
    public function store(...$args){return $this;}
    public function handler(){return $this;}
}
class IdentityController extends app\common\controller\All {
    public array $assigned=[];
    public string $rendered='PUBLIC-CATALOG';
    public function __construct(){$this->request=request();}
    public function identify():array{$this->label_user();return $GLOBALS['user'];}
    protected function assign($name,$value=''):void{if(is_array($name))$this->assigned=array_merge($this->assigned,$name);else $this->assigned[$name]=$value;}
    protected function fetch(string $template='',array $vars=[]):string{return $this->rendered;}
    public function pageKey():string{return $this->page_cache_key('index/index');}
    public function renderPage():string{return $this->label_fetch('index/index');}
}
$entrance=$argv[1]??'';
if(!in_array($entrance,['index','api'],true))throw new RuntimeException('Choose index or api fixture entrance');
define('ENTRANCE',$entrance);define('MAC_MOB',0);
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new RuntimeException('Dedicated MySQL fixture required');
$temp=audit_temp_dir('content-identity');
define('ROOT_PATH',$temp.'/');define('MAC_PATH','/');
$app=new think\App($temp.'/app');
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_identity_','charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);
$app->config->set(['type'=>'file','name'=>'fixture_session','path'=>$temp.'/sessions','expire'=>3600,'var_session_id'=>'fixture_sid'],'session');
$cache=new IdentityCache();$app->instance('cache',$cache);
$groups=[];foreach([1=>'游客',2=>'会员',3=>'VIP',4=>'额外组'] as $id=>$name)$groups[$id]=['group_id'=>$id,'group_name'=>$name,'group_type'=>'1,','group_popedom'=>[1=>[2=>1,3=>1,4=>1]]];
$cache->data['identity_fixture_group_list']=$groups;
$GLOBALS['config']=['app'=>['cache_flag'=>'identity_fixture','cache_page'=>'1','cache_time_page'=>60,'compress'=>0,'security_csp'=>'0','api_jwt_enabled'=>'1','api_jwt_secret'=>str_repeat('synthetic-key-',4),'api_jwt_iss'=>'identity-cache-audit']];
$_SERVER['HTTP_HOST']='fixture.invalid';$_SERVER['REQUEST_METHOD']='GET';
function identityRequest(array $cookies=[],array $headers=[],string $controller='Index',string $action='index',array $state=[],string $method='GET',array $get=[]):IdentityController {
    global $app;
    $_GET=$get;$_POST=[];$_REQUEST=$get;$_COOKIE=$cookies;
    $r=think\Request::__make($app)->withHeader($headers)->withServer(['REQUEST_METHOD'=>$method])->setController($controller)->setAction($action);
    $s=new think\Session($app);if(is_string($cookies['fixture_session']??null))$s->setId($cookies['fixture_session']);
    $s->init();foreach($state as $key=>$value)$s->set($key,$value);
    $r->withSession($s);$app->instance('session',$s);$app->instance('request',$r);$app->instance('cookie',new think\Cookie($r));
    $GLOBALS['user']=[];unset($GLOBALS['_mac_page_cacheable']);
    return new IdentityController();
}
function privateResponse():void {
    $middleware=new app\middleware\SecurityHeaders();
    $response=$middleware->handle(request(),static function(){
        $GLOBALS['_mac_page_cacheable']=600;
        return think\Response::create('PRIVATE-RESOURCE')->header(['Cache-Control'=>'public, max-age=600']);
    });
    check($response->getHeader('Cache-Control')==='private, no-store','Sensitive response must override stale/public cache markers');
    check(!isset($GLOBALS['_mac_page_cacheable']),'Private response must clear its public-cache marker');
}
function noPrivatePageCache(IdentityController $controller):void {
    global $cache;
    $reads=count($cache->reads);$writes=count($cache->writes);$controller->rendered='PRIVATE-CURRENT-REQUEST';
    check($controller->renderPage()==='PRIVATE-CURRENT-REQUEST','Private page must render the current request');
    check(count($cache->reads)===$reads && count($cache->writes)===$writes,'Private page must neither read nor write shared cache');
}
try {
    Db::execute('CREATE TABLE audit_identity_group (group_id INTEGER PRIMARY KEY)');
    Db::execute('CREATE TABLE audit_identity_user (user_id INTEGER PRIMARY KEY,user_name VARCHAR(100),user_pwd VARCHAR(100),user_random VARCHAR(64),user_status INTEGER DEFAULT 1,group_id VARCHAR(20),user_end_time INTEGER,user_points INTEGER DEFAULT 20)');
    foreach([[1,'member','2'],[2,'vip','3'],[3,'multi','2,4'],[4,'expired','3']] as [$id,$name,$group])Db::name('user')->insert(['user_id'=>$id,'user_name'=>$name,'user_pwd'=>'PRIVATE-PASSWORD-HASH','user_random'=>md5('fixture-'.$id),'group_id'=>$group,'user_end_time'=>$id===4?time()-60:time()+3600]);
    $valid=['user_id'=>'1','user_name'=>'member','user_check'=>md5(md5('fixture-1').'-member-1-')];
    $token=JwtService::encode(2,md5('fixture-2'));
    // This is the original failure: real User accepts this token, while old label_user skipped it.
    $controller=identityRequest([],['authorization'=>'Bearer '.$token]);$user=$controller->identify();
    check($user['user_id']===2 && $user['vip_nav']===1,'Pure Bearer must reach actual verified VIP identity through label_user');
    check($user['user_points']===20 && $user['group']['group_name']==='VIP','Verified database fields and group are preserved');
    check(!isset($controller->assigned['user']['user_pwd'],$controller->assigned['user']['user_random']),'Template user must not include authentication secrets');
    check(isset($user['user_pwd'],$user['user_random']),'Server user compatibility is preserved');
    check(!mac_page_cache_eligible(),'Bearer identity must never enter shared page cache');privateResponse();noPrivatePageCache($controller);
    foreach([$valid,array_replace($valid,['user_id'=>1])] as $credentials){
        $controller=identityRequest($credentials);$user=$controller->identify();
        check($user['user_id']===1 && $user['vip_nav']===0,'Existing original parsed Cookie identity stays valid');
        check(!mac_page_cache_eligible(),'Cookie identity must not enter page cache');privateResponse();noPrivatePageCache($controller);
    }
    $controller=identityRequest(array_replace($valid,['user_id'=>'%31']));check($controller->identify()['user_id']===0,'Already parsed double-encoded Cookie id is not decoded again');privateResponse();
    $controller=identityRequest($valid,['authorization'=>'Bearer '.$token]);check($controller->identify()['user_id']===2,'Enabled valid Bearer takes precedence over other user Cookie');
    $controller=identityRequest($valid,['authorization'=>'Bearer '.$token.'x']);check($controller->identify()['user_id']===0,'Invalid enabled Bearer must not fall back to a valid Cookie');privateResponse();
    foreach(['user_id','user_name','user_check'] as $key){
        foreach([[],['nested'=>'bad'],false,1.25,''] as $bad){
            $controller=identityRequest(array_replace($valid,[$key=>$bad]));$user=$controller->identify();
            check($user['user_id']===0 && $user['user_points']===0,'Malformed Cookie becomes a complete guest without PHP diagnostics');
            check(!mac_page_cache_eligible(),'Rejected credentials cannot enter shared cache');
        }
    }
    $controller=identityRequest(['is_member'=>'1','group_id'=>'4']);$user=$controller->identify();check($user['user_id']===0 && $user['vip_nav']===0,'Client presentation/group cookies must not create a VIP badge');
    $controller=identityRequest([],['authorization'=>'Bearer '.JwtService::encode(3,md5('fixture-3'))]);$user=$controller->identify();check($user['group_id']==='2,4' && $user['vip_nav']===1 && count($user['groups'])===2,'Verified multiple groups survive label_user');
    $controller=identityRequest([],['authorization'=>'Bearer '.JwtService::encode(4,md5('fixture-4'))]);$user=$controller->identify();check($user['group_id']===2 && $user['vip_nav']===0,'Expired VIP uses the model downgrade contract');
    check((int)Db::name('user')->where('user_id',4)->value('group_id')===2,'Expired group is updated by the real User model');
    foreach([['user_status'=>0],['user_random'=>'rotated']] as $change){
        Db::name('user')->where('user_id',2)->update($change);$controller=identityRequest([],['authorization'=>'Bearer '.$token]);check($controller->identify()['user_id']===0,'Disabled/rotated user invalidates Bearer at label_user');
        Db::name('user')->where('user_id',2)->update(['user_status'=>1,'user_random'=>md5('fixture-2')]);
    }
    $GLOBALS['config']['app']['api_jwt_enabled']='0';$controller=identityRequest($valid,['authorization'=>'Bearer '.$token.'x']);check($controller->identify()['user_id']===1,'JWT-disabled deployments retain the model Cookie fallback');$GLOBALS['config']['app']['api_jwt_enabled']='1';
    $controller=identityRequest();$user=$controller->identify();check($user['user_id']===0 && $user['user_points']===0 && $user['group']['group_id']===1,'Absent credentials use the guest group');
    check($app->cookie->getCookie()===[],'Anonymous identity must not emit clearing login Cookies');
    check(mac_page_cache_eligible()===($entrance==='index'),'Only anonymous index catalogs use shared page cache');
    if($entrance==='index'){
        $oldKey='fixture.invalid_0_identity_fixture_index/index_'.http_build_query(mac_param_url());
        $cache->data[$oldKey]='PRIVATE-OLD-CACHE';check($controller->pageKey()!==$oldKey,'Shared page namespace must bypass old polluted cache');
        $before=count($cache->writes);$cache->reads=[];
        check($controller->renderPage()==='PUBLIC-CATALOG','Anonymous page must render without old sensitive cache content');
        check(!in_array($oldKey,$cache->reads,true) && count($cache->writes)>$before,'Safe anonymous page writes only the new cache namespace');
        foreach(['Index','Vod','Art','Manga','Actor','Topic','Role','Website'] as $name){
            $c=identityRequest([],[],$name,$name==='Index'?'index':'type');$c->identify();check(mac_page_cache_eligible(),'Anonymous public catalog remains cacheable: '.$name);
        }
        $c=identityRequest();$c->identify();$response=(new app\middleware\SecurityHeaders())->handle(request(),static function(){ $GLOBALS['_mac_page_cacheable']=60; return think\Response::create('PUBLIC-CATALOG'); });
        check($response->getHeader('Cache-Control')==='public, max-age=60','Eligible public response retains shared-cache headers');
    }
    $routes=$entrance==='index'?[
        ['Vod','play'],['Vod','player'],['Vod','down'],['Vod','downer'],['Vod','detail'],['Vod','ajax_detail'],['Vod','rss'],
        ['Art','detail'],['Art','read'],['Art','ajax_detail'],['Art','rss'],['Manga','detail'],['Manga','play'],['Ajax','pwd'],['User','index'],['User','login'],['Index','unknown'],
    ]:[['Vod','get_detail'],['Vod','get_play_info'],['Vod','get_down_info'],['Vod','verify_pwd'],['Art','get_detail'],['Art','get_read_page'],['Manga','get_detail'],['Manga','get_chapter'],['User','get_info']];
    foreach($routes as [$name,$action]){$c=identityRequest([],[],$name,$action);$c->identify();check(!mac_page_cache_eligible(),'Private route cannot use shared page cache: '.$name.'/'.$action);privateResponse();noPrivatePageCache($c);}
    foreach([
        [[],['authorization'=>'Basic synthetic'],[]],
        [[],['authorization'=>['bad']],[]],
        [['user_id'=>[]],[],[]],
        [['fixture_session'=>str_repeat('a',32)],[],[]],
        [[],[],['1-4-1'=>'1']],
        [[],[],['2-1-1'=>'1']],
        [[],[],['12-1-1'=>'1']],
        [[],[],['__token__'=>'session-specific']],
    ] as [$cookies,$headers,$state]){
        $c=identityRequest($cookies,$headers,'Index','index',$state);
        $c->identify();check(!mac_page_cache_eligible(),'Credentials or private session state cannot be publicly cached');privateResponse();noPrivatePageCache($c);
    }
    foreach(['POST','PUT','PATCH','DELETE','HEAD'] as $method){$c=identityRequest([],[],'Index','index',[],$method);$c->identify();check(!mac_page_cache_eligible(),'Only GET is eligible, using actual Request method');privateResponse();}
    $c=identityRequest([],[],'Index','index',[],'GET',['fixture_sid'=>str_repeat('b',32)]);$c->identify();check(!mac_page_cache_eligible(),'Configured session-ID transport must exclude shared caching');privateResponse();
    // Two sequential requests must not inherit old authentication/public-cache flags.
    $c=identityRequest([],['authorization'=>'Bearer '.$token]);$c->identify();$GLOBALS['_mac_page_cacheable']=999;
    $c=identityRequest();$c->identify();$GLOBALS['_mac_page_cacheable']=999;
    $response=(new app\middleware\SecurityHeaders())->handle(request(),static fn()=>think\Response::create('ANONYMOUS-NEW-REQUEST'));
    check($GLOBALS['user']['user_id']===0,'A later visitor cannot inherit the previous verified user');
    check($response->getHeader('Cache-Control')!=='public, max-age=999','A later request cannot inherit a public cache marker');
    check(!str_contains($response->getContent(),'PRIVATE-'),'A later response contains no prior private response body');
    // SecurityHeaders must wrap actual SessionInit so its outgoing Cookie queue is visible.
    $order=require dirname(__DIR__).'/application/middleware.php';
    check(array_search(app\middleware\SecurityHeaders::class,$order,true)<array_search(think\middleware\SessionInit::class,$order,true),'Security headers must execute outside SessionInit');
    foreach([[],['1-4-1'=>'1'],['__token__'=>'SYNTHETIC-CSRF-TOKEN']] as $state){
        $c=identityRequest();$s=$app->make('session');$sessionMiddleware=new think\middleware\SessionInit($app,$s);
        $response=(new app\middleware\SecurityHeaders())->handle(request(),static function($request)use($sessionMiddleware,$state,$c){
            return $sessionMiddleware->handle($request,static function()use($state,$c){
                foreach($state as $key=>$value)session($key,$value);
                $c->identify();$GLOBALS['_mac_page_cacheable']=60;
                return think\Response::create('SESSION-RESPONSE')->header(['Cache-Control'=>'public, max-age=60']);
            });
        });
        check(isset($app->cookie->getCookie()['fixture_session']),'Real SessionInit queues its outgoing session Cookie');
        check($response->getHeader('Cache-Control')==='private, no-store','A Set-Cookie response must never be marked public');
        $sessionMiddleware->end($response);$id=$s->getId();
        $c=identityRequest(['fixture_session'=>$id]);$c->identify();
        foreach($state as $key=>$value)check(request()->session($key)===$value,'SessionInit persistence and password/CSRF session state remain intact');
        check(!mac_page_cache_eligible(),'Restored visitor Session Cookie cannot use shared page cache');
        if(isset($state['__token__'])){
            identityRequest(['fixture_session'=>$id],[],'User','login',[],'POST');
            check(request()->checkToken('__token__',['__token__'=>$state['__token__']]),'Actual Request accepts the token restored through SessionInit');
            check(!request()->checkToken('__token__',['__token__'=>$state['__token__']]),'Actual Request rejects token reuse');
            identityRequest(['fixture_session'=>$id],[],'User','login',[],'POST');
            check(!request()->checkToken('__token__',['__token__'=>'wrong-token']),'Actual Request rejects an incorrect restored-session token');
        }
    }
    $c=identityRequest();$c->identify();
    $response=(new app\middleware\SecurityHeaders())->handle(request(),static function(){cookie('synthetic_login','issued');$GLOBALS['_mac_page_cacheable']=60;return think\Response::create('COOKIE-RESPONSE');});
    check($response->getHeader('Cache-Control')==='private, no-store','Other outgoing login Cookies also prohibit public caching');
    $c=identityRequest();$c->identify();
    $response=(new app\middleware\SecurityHeaders())->handle(request(),static function(){ $GLOBALS['_mac_page_cacheable']=60;return think\Response::create('EXPLICIT-PRIVATE')->header(['Cache-Control'=>'private, no-store']);});
    check($response->getHeader('Cache-Control')==='private, no-store','An explicit private response cannot be overwritten by a page-cache marker');
    if($entrance==='index'){
        $socketProbe=stream_socket_server('tcp://127.0.0.1:0',$errorNumber,$errorMessage);if($socketProbe===false)throw new RuntimeException($errorMessage);
        $address=stream_socket_get_name($socketProbe,false);fclose($socketProbe);
        $log=$temp.'/http.log';$process=proc_open([PHP_BINARY,'-S',$address,__DIR__.'/fixtures/content_cache_http.php'],[0=>['file','/dev/null','r'],1=>['file',$log,'a'],2=>['file',$log,'a']],$pipes,dirname(__DIR__),array_merge(getenv(),['CONTENT_CACHE_HTTP_TEMP'=>$temp]));
        if(!is_resource($process))throw new RuntimeException('Cannot start isolated HTTP fixture');
        try{
            $ready=false;for($attempt=0;$attempt<100;$attempt++){
                $connection=@stream_socket_client('tcp://'.$address,$errorNumber,$errorMessage,0.1);
                if(is_resource($connection)){fclose($connection);$ready=true;break;}usleep(20000);
            }
            check($ready,'Loopback cache-hit fixture is ready');
            $context=stream_context_create(['http'=>['timeout'=>5,'ignore_errors'=>true]]);$body=file_get_contents('http://'.$address.'/',false,$context);
            check($body==='CACHED-PUBLIC-MARKER','Actual cache hit returns the cached public catalog: '.substr((string)$body,0,600).' / '.substr((string)file_get_contents($log),-1500));
            check(preg_match('/^Cache-Control:\s*private, no-store$/mi',implode("\n",$http_response_header))===1,'Framework cache hit must emit a private no-store header');
            check(!preg_match('/Cache-Control:.*public/i',implode("\n",$http_response_header)),'No public header can escape the cache-hit response path');
        }finally{proc_terminate($process);proc_close($process);}
    }
    echo 'framework_audit_content_identity_cache: '.$checks.' checks passed for '.$entrance.' on PHP '.PHP_VERSION.' / MySQL'.PHP_EOL;
}finally{Db::execute('DROP TABLE IF EXISTS audit_identity_user');Db::execute('DROP TABLE IF EXISTS audit_identity_group');audit_remove_temp($temp);}
