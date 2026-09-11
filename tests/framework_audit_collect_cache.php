<?php
/** Actual collector cleanup with a fault-injected cache boundary and real temporary directories. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
$temp=audit_temp_dir('collect-cache');define('RUNTIME_PATH',$temp.'/runtime/');mkdir(RUNTIME_PATH,0700);
register_shutdown_function(static function()use($temp):void{audit_remove_temp($temp);});
function lang($key,...$args){return $key;}
function mac_echo($value){$GLOBALS['collect_cache_messages'][]=$value;}
class CollectCacheBoundary {
    public int $calls=0;
    public function __construct(public $result) {}
    public function clear() {$this->calls++;if($this->result instanceof Throwable)throw $this->result;return $this->result;}
}
$method=new ReflectionMethod(\app\common\model\Collect::class,'collectCacheClear');
function collectCacheFixture($result):array {
    $cache=new CollectCacheBoundary($result);\think\Container::getInstance()->instance('cache',$cache);
    $GLOBALS['collect_cache_messages']=[];
    return [(new ReflectionClass(\app\common\model\Collect::class))->newInstanceWithoutConstructor(),$cache];
}
[$collector,$cache]=collectCacheFixture(true);
check($method->invoke($collector)===true&&$cache->calls===1,'An absent page-cache directory must allow successful collection cleanup');
mkdir(RUNTIME_PATH.'temp',0700);file_put_contents(RUNTIME_PATH.'temp/new','new');
check($method->invoke($collector)===true&&$cache->calls===1&&is_file(RUNTIME_PATH.'temp/new'),'Completed cleanup must not clear again in the same collector instance');
check(count($GLOBALS['collect_cache_messages'])===1&&str_contains($GLOBALS['collect_cache_messages'][0],'clear_ok'),'A completed cleanup prints one success result');
\app\common\util\Dir::delDir(RUNTIME_PATH.'temp');
foreach([false,null,new RuntimeException('backend unavailable'),new Error('backend type failure')] as $failure) {
    [$collector,$cache]=collectCacheFixture($failure);mkdir(RUNTIME_PATH.'temp',0700);file_put_contents(RUNTIME_PATH.'temp/old','old');
    check($method->invoke($collector)===false&&!file_exists(RUNTIME_PATH.'temp'),'Backend failure must remain a failed result while independent temporary files can be cleared');
    check(str_contains($GLOBALS['collect_cache_messages'][0],'clear_err')&&!str_contains($GLOBALS['collect_cache_messages'][0],'clear_ok'),'Backend refusal and Throwable failures must print controlled failure without success');
    $cache->result=true;
    check($method->invoke($collector)===true&&$cache->calls===2,'A failed attempt must not suppress a subsequent permitted cleanup retry');
}
[$collector,$cache]=collectCacheFixture(true);file_put_contents(RUNTIME_PATH.'temp','misconfigured');
check($method->invoke($collector)===false&&file_get_contents(RUNTIME_PATH.'temp')==='misconfigured','Page-cache directory failure must prevent an overall success even when the backend clears');
unlink(RUNTIME_PATH.'temp');
check($method->invoke($collector)===true&&$cache->calls===2,'Fixing the page-cache path allows a later attempt to complete');
mkdir($temp.'/outside',0700);file_put_contents($temp.'/outside/sentinel','preserved');symlink($temp.'/outside',RUNTIME_PATH.'temp');
[$collector,$cache]=collectCacheFixture(true);
check($method->invoke($collector)===false&&is_link(RUNTIME_PATH.'temp')&&file_get_contents($temp.'/outside/sentinel')==='preserved','A linked page-cache root must be preserved and reported as a failed cleanup');
echo 'Collector cache cleanup: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
