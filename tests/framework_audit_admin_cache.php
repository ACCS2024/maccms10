<?php
/** Real administrator route/session/permissions, generated files, runtime cache and search ORM. */
declare(strict_types=1);
define('ADMIN_CACHE_AUDIT',true);define('ENTRANCE','admin');
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
define('APP_PATH',$purchaseTemp.'/application/');define('RUNTIME_PATH',$purchaseTemp.'/runtime/');
mkdir(APP_PATH.'data/update',0700,true);file_put_contents(APP_PATH.'data/update/sec_schema.lock','v2');
mkdir(ROOT_PATH.'static/js',0700,true);$app->setRuntimePath(RUNTIME_PATH);
function url($path,$params=[]){return '/fixture/admin.php/'.$path;}
function redirect($path){return \think\Response::create($path,'redirect',302);}
class AdminCacheIndexFixture extends \app\admin\controller\Index {
    protected function assign($name,$value=''):void{}
}
$app->bind(\app\admin\controller\Index::class,AdminCacheIndexFixture::class);
$fileConfiguration=\app\common\util\CacheConnection::configuration([]);$fileConfiguration['stores']['file']['path']=RUNTIME_PATH.'cache/';
$app->config->set($fileConfiguration,'cache');$runtimeCache=new \think\Cache($app);$app->instance('cache',$runtimeCache);
function adminCacheSeed():array {
    global $app,$runtimeCache;
    $app->instance('cache',$runtimeCache);purchaseCsrfConfig();
    $GLOBALS['config']['app']+=['pagesize'=>20,'makesize'=>20,'security_csrf_admin'=>0,'security_csrf_admin_exempt'=>'index/*'];
    $app->config->set($GLOBALS['config'],'maccms');
    Db::name('Admin')->whereRaw('1 = 1')->delete();Db::name('VodSearch')->whereRaw('1 = 1')->delete();
    Db::name('Admin')->insert(['admin_id'=>2,'admin_name'=>'cache-operator','admin_pwd'=>password_hash('fixture',PASSWORD_BCRYPT,['cost'=>4]),
        'admin_auth'=>',index/clear,','admin_status'=>1,'admin_random'=>'fixture']);
    foreach([['old','vod_name',time()-3000000],['recent','vod_name',time()],['actor','vod_actor',time()],['','vod_actor',0]] as [$word,$field,$time]) {
        Db::name('VodSearch')->insert(['search_key'=>$word===''?'':md5($word),'search_word'=>$word,'search_field'=>$field,'search_update_time'=>$time,'search_result_ids'=>'17','search_result_count'=>1]);
    }
    $memo=new ReflectionProperty(\app\common\model\VodSearch::class,'getResultIdListMemo');$memo->setValue(null,['fixture'=>[17]]);
    foreach(['cache','log','temp'] as $name) {
        $path=RUNTIME_PATH.$name;\app\common\util\Dir::delDir($path);
        if(is_file($path))unlink($path);mkdir($path,0700,true);file_put_contents($path.'/sentinel','fixture');
    }
    $runtimeCache->set('fixture','cached',30);
    file_put_contents(ROOT_PATH.'static/js/playerconfig.js',"var MacPlayerConfig={};\n//缓存开始\nold_cache();\n//缓存结束\n");
    $request=new PurchaseCsrfRequest();$app->instance('request',$request);$app->instance('cookie',new \think\Cookie($request));
    $session=new \think\Session($app);$app->instance('session',$session);$session->init();
    $session->set('admin_auth','1');$session->set('admin_info',Db::name('Admin')->where('admin_id',2)->find());
    $token=\app\common\util\SessionCsrf::issue();$session->save();
    return [['fixture_session'=>$session->getId()],$token];
}
function adminCacheState():array {
    return [file_get_contents(ROOT_PATH.'static/js/playerconfig.js'),
        array_map(static fn($name)=>is_file(RUNTIME_PATH.$name.'/sentinel'),['cache','temp','log']),
        Db::name('VodSearch')->order('search_key')->select()->toArray()];
}
function adminCacheRoute(array $body=[],array $query=[],array $cookies=[],array $headers=[],string $method='POST',array $server=[],string $action='clear'):array {
    global $app;
    $_GET=$query;$_POST=$body;$_COOKIE=$cookies;$_REQUEST=$body+$query;
    $_SERVER=$server+['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid','SCRIPT_NAME'=>'/fixture/admin.php',
        'SCRIPT_FILENAME'=>'/isolated/admin.php','PATH_INFO'=>'/index/'.$action,'REQUEST_URI'=>'/fixture/admin.php/index/'.$action,'HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest'];
    $request=PurchaseCsrfRequest::__make($app)->withHeader($headers);$app->instance('request',$request);$app->instance('cookie',new \think\Cookie($request));
    $session=new \think\Session($app);$app->instance('session',$session);$app->setNamespace('app\\admin');$app->config->set([],'route');
    $middleware=new \think\middleware\SessionInit($app,$session);
    try {$response=$middleware->handle($request,static fn($request)=>(new \think\Route($app))->dispatch($request,false));}
    catch(\think\exception\HttpResponseException $error){$response=$error->getResponse();}
    $middleware->end($response);
    check($response instanceof \think\response\Json||$response->getCode()===302,'Administrator cache route must finish with controlled JSON or a login redirect');
    return $response instanceof \think\response\Json?$response->getData():['code'=>1401];
}
function adminCacheDenied($body,$query,$cookies,$headers=[],$method='POST',$server=[]):void {
    $before=adminCacheState();$result=adminCacheRoute($body,$query,$cookies,$headers,$method,$server);
    check($result['code']!==1&&adminCacheState()===$before,'Rejected clear request must preserve generated configuration, cache files and all search rows');
}
[$cookies,$token]=adminCacheSeed();
foreach(['GET','PUT','PATCH','DELETE','HEAD'] as $method)adminCacheDenied(['csrf_token'=>$token],[],$cookies,[],$method);
foreach([['GET','POST'],['POST','GET'],['PUT','POST']] as [$method,$override])adminCacheDenied(['csrf_token'=>$token],[],$cookies,[],$method,['HTTP_X_HTTP_METHOD_OVERRIDE'=>$override]);
adminCacheDenied(['_method'=>'GET','csrf_token'=>$token],[],$cookies);
foreach([[],['csrf_token'=>[]],['csrf_token'=>'wrong']] as $body)adminCacheDenied($body,['csrf_token'=>$token],$cookies);
adminCacheDenied(['csrf_token'=>$token],[],$cookies,['X-CSRF-Token'=>'wrong']);
adminCacheDenied(['csrf_token'=>$token],[],[]);
Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',index/index,']);adminCacheDenied(['csrf_token'=>$token],[],$cookies);
Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',index/clear,','admin_status'=>0]);adminCacheDenied(['csrf_token'=>$token],[],$cookies);
[$cookies,$token]=adminCacheSeed();
$result=adminCacheRoute([],[],$cookies,['X-CSRF-Token'=>$token]);
check($result['code']===1&&$result['msg']==='admin/index/clear_ok','Ordinary administrator POST with the existing client header must succeed');
check(Db::name('VodSearch')->count()===0,'Explicit clear must remove recent, expired, actor and legacy empty-key search rows');
check((new ReflectionProperty(\app\common\model\VodSearch::class,'getResultIdListMemo'))->getValue()===[],'Search reset must invalidate the process memo after database success');
check($runtimeCache->get('fixture')===null&&!file_exists(RUNTIME_PATH.'temp')&&is_file(RUNTIME_PATH.'log/sentinel'),'Successful cache cleanup must preserve runtime logs needed for diagnosis and audit');
check(str_contains(file_get_contents(ROOT_PATH.'static/js/playerconfig.js'),'MacPlayerConfig.player_list=')&&!str_contains(file_get_contents(ROOT_PATH.'static/js/playerconfig.js'),'old_cache()'),'The real helper must publish the validated player configuration');
check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']===1,'Repeated cleanup with empty cache and search results must remain successful');
// Re-check identity and permissions if they change after construction but before the action executes.
foreach([['admin_auth'=>',index/index,'],['admin_status'=>0]] as $change) {
    [$cookies,$token]=adminCacheSeed();adminCacheDenied([],[],$cookies); // Load the actual administrator session without clearing.
    $request=request()->withPost(['csrf_token'=>$token]);$app->instance('request',$request);
    $controller=new AdminCacheIndexFixture();$before=adminCacheState();
    Db::name('Admin')->where('admin_id',2)->update($change);$response=$controller->clear();
    check($response instanceof \think\response\Json&&$response->getData()['code']!==1&&adminCacheState()===$before,'Action must refresh stale administrator permissions/status immediately before cleanup');
}
[$cookies,$token]=adminCacheSeed();file_put_contents(ROOT_PATH.'static/js/playerconfig.js','invalid markers');$before=adminCacheState();
check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']!==1&&adminCacheState()===$before,'Failed player generation must end the AJAX action without clearing caches or search rows');
[$cookies,$token]=adminCacheSeed();\app\common\util\Dir::delDir(RUNTIME_PATH.'temp');file_put_contents(RUNTIME_PATH.'temp','misconfigured');
check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']!==1&&Db::name('VodSearch')->count()===4&&file_get_contents(RUNTIME_PATH.'temp')==='misconfigured','Partial runtime cleanup cannot fall through to success or delete search rows');
[$cookies,$token]=adminCacheSeed();\app\common\util\Dir::delDir(RUNTIME_PATH.'temp');
mkdir(ROOT_PATH.'outside',0700);file_put_contents(ROOT_PATH.'outside/sentinel','preserved');symlink(ROOT_PATH.'outside',RUNTIME_PATH.'temp');
check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']!==1&&Db::name('VodSearch')->count()===4&&is_link(RUNTIME_PATH.'temp')&&file_get_contents(ROOT_PATH.'outside/sentinel')==='preserved','A linked page-cache root must fail clearly without removing the link, its target or search rows');
class AdminCacheFault {
    public function __construct(public $result) {}
    public function clear() {if($this->result instanceof Throwable)throw $this->result;return $this->result;}
}
foreach([false,new RuntimeException('fixture cache failure'),new Error('fixture cache type failure')] as $failure) {
    [$cookies,$token]=adminCacheSeed();$app->instance('cache',new AdminCacheFault($failure));
    check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']!==1&&Db::name('VodSearch')->count()===4,'Backend refusal or Throwable must produce a failed action and preserve search rows');
}
[$cookies,$token]=adminCacheSeed();
Db::execute($mysql?"CREATE TRIGGER audit_cache_delete_failure BEFORE DELETE ON audit_vod_search FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture refusal'":"CREATE TRIGGER audit_cache_delete_failure BEFORE DELETE ON audit_vod_search BEGIN SELECT RAISE(ABORT, 'fixture refusal'); END");
check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']!==1&&Db::name('VodSearch')->count()===4,'Actual database deletion failure must return a controlled failure without losing cached search rows');
Db::execute('DROP TRIGGER audit_cache_delete_failure');
check(adminCacheRoute(['csrf_token'=>$token],[],$cookies)['code']===1&&Db::name('VodSearch')->count()===0,'A deliberate retry after database recovery must succeed');
[$cookies,$token]=adminCacheSeed();Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',index/clear,index/_cache_clear,']);$before=adminCacheState();
try {adminCacheRoute(['csrf_token'=>$token],[],$cookies,[],'POST',[],'_cache_clear');throw new RuntimeException('Internal clear helper was publicly dispatched');}
catch(\think\exception\HttpException $error){check($error->getStatusCode()===404&&adminCacheState()===$before,'Even an explicitly permitted helper URL must not bypass the public action guard');}
echo 'Administrator cache cleanup: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
