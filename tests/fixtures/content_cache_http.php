<?php
/** Loopback-only fixture for All's direct echo/exit cache-hit transport. No database/site bootstrap. */
declare(strict_types=1);
require dirname(__DIR__, 2).'/vendor/autoload.php';
require dirname(__DIR__, 2).'/application/common.php';
require dirname(__DIR__).'/fixtures/security_audit_test_helpers.php';
define('ENTRANCE','index');define('MAC_MOB',0);
function config($key,$default=null){return think\facade\Config::get($key,$default);}
function request(){return think\Container::getInstance()->make('request');}
class CachedPublicPage {
    public function get($key,$default=null){return 'CACHED-PUBLIC-MARKER';}
}
$directory=getenv('CONTENT_CACHE_HTTP_TEMP');
if(!is_string($directory)||!str_starts_with($directory,sys_get_temp_dir().'/maccms-audit-content-identity-'))throw new RuntimeException('Dedicated fixture directory required');
$app=new think\App($directory.'/app');
$app->config->set(['type'=>'file','name'=>'fixture_session','path'=>$directory.'/sessions','expire'=>3600],'session');
$GLOBALS['config']=['app'=>['cache_page'=>'1','cache_time_page'=>60,'cache_flag'=>'fixture','security_csp'=>'0']];
$GLOBALS['user']=['user_id'=>0];
$r=think\Request::__make($app)->setController('Index')->setAction('index');$app->instance('request',$r);$app->instance('cookie',new think\Cookie($r));$app->instance('cache',new CachedPublicPage());
$s=new think\Session($app);$app->instance('session',$s);
$security=new app\middleware\SecurityHeaders();$sessions=new think\middleware\SessionInit($app,$s);
$security->handle($r,static function($r)use($sessions){
    return $sessions->handle($r,static function(){
        $controller=(new ReflectionClass(app\common\controller\All::class))->newInstanceWithoutConstructor();
        (new ReflectionMethod($controller,'load_page_cache'))->invoke($controller,'index/index');
        throw new RuntimeException('Expected direct cache hit');
    });
});
