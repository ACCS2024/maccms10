<?php
/** Actual API/collector gates and response middleware; DNS is an isolated deterministic fixture. */
declare(strict_types=1);
namespace {
    require dirname(__DIR__).'/vendor/autoload.php';
    require __DIR__.'/fixtures/security_audit_test_helpers.php';
    function request(){return \think\Container::getInstance()->make('request');}
    function config($name,$default=null){return \think\facade\Config::get($name,$default);}
    function lang($name){return $name;}
    function mac_get_refer(){return '';}
    function json($data){return \think\Response::create($data,'json');}
    define('ENTRANCE','api');define('MAC_PATH','/fixture/');
}
namespace app\common\util {
    function gethostbyname($name){
        $GLOBALS['api_access_dns'][]=$name;
        if($name==='failed.example.')throw new \RuntimeException('Fixture resolver unavailable');
        return $GLOBALS['api_access_records'][$name]??$name;
    }
}
namespace {
    trait ApiAccessPresentation {
        protected function label_user(){}
        protected function assign($name,$value=''):void{}
    }
    class ApiAccessCash extends \app\api\controller\Cash {use ApiAccessPresentation;}
    class ApiAccessActor extends \app\api\controller\Actor {use ApiAccessPresentation;}
    class ApiAccessProvide extends \app\api\controller\Provide {use ApiAccessPresentation;}
    class ApiAccessSeacms extends \app\api\controller\Seacms {use ApiAccessPresentation;}
    class ApiAccessRequest extends \app\Request {public function isCli():bool{return false;}}
    $temp=audit_temp_dir('api-access');register_shutdown_function(static fn()=>audit_remove_temp($temp));
    $app=new \think\App($temp.'/');
    $app->instance(\think\exception\Handle::class,new class($app)extends \think\exception\Handle{
        public function render(\think\Request $request,\Throwable $error):\think\Response {
            if(!$error instanceof \think\exception\HttpResponseException)throw $error;
            return parent::render($request,$error);
        }
    });
    $app->config->set(['type'=>'file','name'=>'fixture_session','expire'=>3600,'path'=>$temp.'/sessions'],'session');
    $app->middleware->import([\app\middleware\SecurityHeaders::class,\think\middleware\SessionInit::class]);
    function apiAccessRun($settings,callable $action,$peer='198.51.100.20',array $headers=[],array $proxy=[]):\think\Response {
        global $app;
        $GLOBALS['config']=['site'=>['site_status'=>1],'api'=>array_fill_keys(['publicapi','vod','art','actor','role','website','manga'],$settings),'app'=>[],'user'=>[]];
        $GLOBALS['api_access_dns']=[];$GLOBALS['api_access_reached']=false;
        $app->config->set($GLOBALS['config'],'maccms');$app->config->set($proxy+['trusted_proxies'=>[],'forwarded_header'=>'x-forwarded-for'],'client_ip');
        $request=(new ApiAccessRequest())->withServer(['REQUEST_METHOD'=>'GET','HTTP_HOST'=>'fixture.invalid','REMOTE_ADDR'=>$peer]+$headers)->setController('Cash')->setAction('get_config');
        $app->instance('request',$request);$finished=false;ob_start();
        try {
            $response=$app->middleware->pipeline()->send($request)->then(function()use($action,&$finished){
                try{$action();$GLOBALS['api_access_reached']=true;return \think\Response::create('passed');}
                finally{$finished=true;}
            });
        } finally {$output=ob_get_clean();}
        check($finished&&$output==='','API gate must unwind without printing or terminating the request');
        check($response->getHeader('X-Content-Type-Options')==='nosniff'&&str_contains((string)$response->getHeader('Content-Security-Policy'),"script-src 'self'"),'Response middleware must finalize API rejection headers');
        check($response->getHeader('Cache-Control')==='private, no-store'&&$request->session()!==null,'Session-bearing early responses must stay private and complete initialization');
        $app->middleware->end($response);
        return $response;
    }
    $direct=static fn()=>\app\common\util\ApiAccess::enforce($GLOBALS['config']['api']['publicapi']);
    $public=['status'=>1,'charge'=>0,'auth'=>''];$restricted=['status'=>'1','charge'=>'1','auth'=>'198.51.100.20'];
    foreach([static fn()=>new ApiAccessCash(),static fn()=>new ApiAccessActor(),$direct] as $action) {
        foreach([null,[],false,['status'=>0],['status'=>[]],['status'=>true],['status'=>1],['status'=>1,'charge'=>[]]] as $settings) {
            $response=apiAccessRun($settings,$action);
            check($response->getCode()===503&&$response->getContent()==='closed'&&!$GLOBALS['api_access_reached'],'Disabled or malformed API configuration must prevent controller action dispatch');
        }
        foreach([$public,$restricted] as $settings) {
            check(apiAccessRun($settings,$action)->getCode()===200&&$GLOBALS['api_access_reached'],'Enabled valid API gates must keep legitimate requests usable');
        }
    }
    foreach(['vod','art','actor','role','website','manga'] as $name) {
        $action=static fn()=>(new ApiAccessProvide())->$name();
        check(apiAccessRun(['status'=>0],$action)->getCode()===503,'Every collector resource gate must stop before resource queries');
        check(apiAccessRun($restricted,$action,'203.0.113.7')->getCode()===403,'Every collector resource must enforce the shared IP authorization');
    }
    check(apiAccessRun(['status'=>0],static fn()=>(new ApiAccessSeacms())->vod())->getCode()===503,'SeaCMS closure must unwind through middleware');
    check(apiAccessRun($restricted,static fn()=>(new ApiAccessSeacms())->vod(),'203.0.113.7')->getCode()===403,'SeaCMS must share current IP authorization');
    foreach([null,[],false,'','invalid','0.0.0.0','::'] as $peer) {
        check(apiAccessRun($restricted,$direct,$peer)->getCode()===403,'A missing or malformed native peer cannot acquire API access');
    }
    check(apiAccessRun($restricted,$direct,'203.0.113.7',['HTTP_X_FORWARDED_FOR'=>'198.51.100.20'])->getCode()===403,'Untrusted forwarding headers cannot grant API access');
    check(apiAccessRun($restricted,$direct,'203.0.113.7',['HTTP_X_FORWARDED_FOR'=>'198.51.100.20'],['trusted_proxies'=>['203.0.113.7']])->getCode()===200,'Configured trusted proxy policy must identify the actual permitted client');
    check(apiAccessRun($restricted,$direct,'198.51.100.20',[],['trusted_proxies'=>false])->getCode()===503,'Invalid proxy configuration must fail closed');
    foreach(['127.0.0.1','::1'] as $peer)check(apiAccessRun(['status'=>1,'charge'=>1,'auth'=>''],$direct,$peer)->getCode()===200,'Loopback collectors must remain usable with either IP family');
    check(apiAccessRun(['status'=>1,'charge'=>1,'auth'=>'2001:db8::10'],$direct,'2001:0db8:0:0:0:0:0:10')->getCode()===200,'Equivalent IPv6 literals must compare canonically');
    check(apiAccessRun(['status'=>1,'charge'=>1,'auth'=>" 203.0.113.1 #\r\n 198.51.100.20\n"],$direct)->getCode()===200,'Legacy separators and textarea line breaks must remain usable');
    foreach([[],null,true,str_repeat('a',16385),"ordinary\0name",'https://ordinary.example/path','999.1.1.1',str_repeat('x',254).'.example',implode('#',array_fill(0,129,'198.51.100.20')),
        implode('#',array_map(static fn($i)=>'host'.$i.'.example',range(1,33)))] as $auth) {
        check(apiAccessRun(['status'=>1,'charge'=>1,'auth'=>$auth],$direct)->getCode()===503&&$GLOBALS['api_access_dns']===[],'Malformed or oversized allowlists must fail before DNS activity');
    }
    $GLOBALS['api_access_records']=['allowed.example.'=>'198.51.100.20'];
    check(apiAccessRun(['status'=>1,'charge'=>1,'auth'=>'ALLOWED.EXAMPLE.#allowed.example'],$direct)->getCode()===200&&$GLOBALS['api_access_dns']===['allowed.example.'],'Domain entries must resolve once per distinct absolute hostname');
    foreach(['unknown.example','failed.example'] as $host)check(apiAccessRun(['status'=>1,'charge'=>1,'auth'=>$host],$direct)->getCode()===403,'Unresolved or failed domain lookup cannot grant API access');
    check((new \ReflectionMethod(\app\api\controller\Cash::class,'check_config'))->isProtected(),'The shared configuration guard is an internal method, not a public action');
    apiAccessRun($public,static function()use($app):void {
        $app->setNamespace('app\\api');$app->bind(\app\api\controller\Cash::class,ApiAccessCash::class);$app->config->set([],'route');
        request()->withServer(array_replace(request()->server(),['PATH_INFO'=>'/cash/check_config','REQUEST_URI'=>'/api.php/cash/check_config']));
        try{(new \think\Route($app))->dispatch(request(),false);check(false,'Internal API guard must not be callable through URL routing');}
        catch(\think\exception\HttpException $error){check($error->getStatusCode()===404,'Actual router must reject internal API guard actions with 404');}
    });
    echo 'API access gates: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
}
