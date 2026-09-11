<?php
/** Real All cache/error methods, middleware/session and isolated HTTP fixture. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function request() { return \think\Container::getInstance()->make('request'); }
function config($key,$default=null) { return \think\facade\Config::get($key,$default); }
function lang($key,...$vars) { return $key; }
function json($data) { return \think\Response::create($data,'json'); }
function mac_param_url() { return []; }
function mac_page_cache_eligible() { return true; }
function mac_cache_lock_acquire($key,$ttl) { return true; }
function mac_cache_lock_release($key) { $GLOBALS['page_lock_released'] = true; }
class PageResponseFixture extends \app\common\controller\All {
    public function __construct() {}
    protected function assign($name,$value=''):void {}
    protected function fetch(string $template='',array $vars=[]):string { return 'rendered:'.$template; }
    public function page() { return $this->label_fetch('index/index'); }
    public function missing() { return $this->page_error('ordinary & missing'); }
}
class PageResponseCache {
    public mixed $value = null;
    public int $writes = 0;
    public int $reads = 0;
    public function get($key) { $this->reads++; return $this->value; }
    public function set($key,$value,$ttl) { $this->writes++; $this->value=$value; return true; }
}
define('ENTRANCE','index'); define('MAC_MOB',0);
$temp=audit_temp_dir('content-identity');
mkdir($temp.'/public',0700); mkdir($temp.'/sessions',0700);
$GLOBALS['MAC_ROOT_TEMPLATE']=$temp.'/';
$GLOBALS['config']=['app'=>['cache_flag'=>'fixture','cache_time_page'=>60,'compress'=>0,'page_404'=>'missing']];
$GLOBALS['user']=['user_id'=>0];
$app=new \think\App($temp.'/app');
$app->config->set(['type'=>'file','name'=>'fixture_session','path'=>$temp.'/sessions','expire'=>3600],'session');
$app->instance('view',new class { public function assign($data){} });
$cache=new PageResponseCache();$app->instance('cache',$cache);
$app->middleware->import([\app\middleware\SecurityHeaders::class,\think\middleware\SessionInit::class]);
$controller=new PageResponseFixture();
function pageRun(bool $error=false, bool $json=false):\think\Response {
    global $app,$controller;
    $request=(new \think\Request())->withServer(['REQUEST_METHOD'=>'GET'])->withHeader(['accept'=>$json?'application/json':'text/html']);
    $request->setController('Index');$request->setAction('index');$app->instance('request',$request);
    $finished=false;ob_start();
    try {
        $response=$app->middleware->pipeline()->send($request)->then(function()use($error,&$finished,$controller){
            try { return \think\Response::create($error?$controller->missing():$controller->page()); }
            finally { $finished=true; }
        });
    } finally { $body=ob_get_clean(); }
    check($finished && $body==='', 'Page response must unwind without directly emitting bytes');
    check($response->getHeader('X-Content-Type-Options')==='nosniff' && $response->getHeader('Cache-Control')==='private, no-store','Page response must complete security middleware');
    check(\think\facade\Cookie::getCookie()!==[],'Page response must complete session cookie emission');
    $app->middleware->end($response);
    return $response;
}
try {
    foreach (['cached page','0',''] as $value) {
        $cache->value=$value;$writes=$cache->writes;
        check(pageRun()->getContent()===$value && $cache->writes===$writes,'Cached HTML including empty/zero must remain a hit');
        $response=pageRun(false,true);
        check($response instanceof \think\response\Json && json_decode($response->getContent(),true,512,JSON_THROW_ON_ERROR)===$value,'JSON cache hits must retain the fragment string and MIME type');
    }
    foreach ([null,false,[],['unexpected'=>'cache shape']] as $value) {
        $cache->value=$value;$GLOBALS['page_lock_released']=false;
        check(pageRun()->getContent()==='rendered:index/index','Missing or invalid cache data must render the page');
        check($GLOBALS['page_lock_released'],'Successful rendering must release its acquisition');
    }
    foreach (['fallback','jump','configured'] as $kind) {
        if ($kind==='jump') { file_put_contents($temp.'/public/jump.html','fixture'); }
        if ($kind==='configured') { file_put_contents($temp.'/public/missing.html','fixture'); }
        $cache->value='cached success';$reads=$cache->reads;$writes=$cache->writes;
        $response=pageRun(true);
        check($response->getCode()===404,'Every missing-page branch must keep HTTP 404');
        check($cache->reads===$reads && $cache->writes===$writes,'Error pages must bypass successful-page cache reads and writes');
        $expected=match($kind){'fallback'=>'<!doctype html><meta charset="utf-8"><title>404</title><h1>404</h1><p>ordinary &amp; missing</p>','jump'=>'rendered:public/jump',default=>'rendered:public/missing'};
        check($response->getContent()===$expected,'404 fallback template/body changed');
    }
    // Exercise real header and cookie transport with the same standalone fixture used by the MySQL identity audit.
    $socket=stream_socket_server('tcp://127.0.0.1:0',$number,$message);$address=stream_socket_get_name($socket,false);fclose($socket);
    $process=proc_open([PHP_BINARY,'-S',$address,__DIR__.'/fixtures/content_cache_http.php'],[0=>['file','/dev/null','r'],1=>['file',$temp.'/http.log','a'],2=>['file',$temp.'/http.log','a']],$pipes,null,array_replace(getenv(),['CONTENT_CACHE_HTTP_TEMP'=>$temp]));
    if(!is_resource($process))throw new RuntimeException('Cannot start loopback cache fixture');
    try {
        $ready=false;
        for($i=0;$i<100;$i++){ $connection=@stream_socket_client('tcp://'.$address,$number,$message,0.05);if(is_resource($connection)){fclose($connection);$ready=true;break;}usleep(10000); }
        check($ready,'Loopback cache fixture starts');
        foreach ([false,true] as $json) {
            $body=file_get_contents('http://'.$address.'/',false,stream_context_create(['http'=>['timeout'=>5,'ignore_errors'=>true,'header'=>'Accept: '.($json?'application/json':'text/html')]]));
            check(($json?json_decode($body,true):$body)==='CACHED-PUBLIC-MARKER','Actual cached HTTP body must survive normal response transport');
            $headers=preg_replace('/:([ \t]*)/',': ',implode("\n",$http_response_header));
            check(str_contains($headers,'Cache-Control: private, no-store') && str_contains($headers,'X-Content-Type-Options: nosniff') && str_contains($headers,'Content-Security-Policy:'),'HTTP cache hit must include finalized security headers: '.$headers);
            check(str_contains($headers,'Set-Cookie: fixture_session='),'HTTP cache hit must include its session cookie');
            if($json)check(str_contains(strtolower($headers),'content-type: application/json'),'JSON hit must have the actual JSON MIME type');
        }
    } finally {proc_terminate($process);proc_close($process);}
    echo 'Page responses: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
} finally {audit_remove_temp($temp);}
