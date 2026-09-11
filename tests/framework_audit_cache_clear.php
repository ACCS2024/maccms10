<?php
/** Actual file-store cleanup and Redis failure propagation; no shared cache services. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\CacheConnection;
use app\common\cache\File;
$temp=audit_temp_dir('cache-clear');$app=new \think\App($temp.'/app');$app->setRuntimePath($temp.'/runtime/');
register_shutdown_function(static function()use($temp):void {
    foreach (['locked/child','locked','blocked-parent'] as $name) {
        $path=$temp.'/'.$name;if(is_dir($path)&&!is_link($path))chmod($path,0700);
    }
    audit_remove_temp($temp);
});
$app->config->set(CacheConnection::configuration([]),'cache');$manager=new \think\Cache($app);$store=$manager->store('file');
check($store instanceof File&&CacheConnection::driver(['type'=>'file']) instanceof File,'Production configuration and administrator probe must use the same safe file driver');
check($store->clear()===true,'A never-created physical cache directory is already clear');
check($store->set('ordinary',['value'=>1],30)&&$store->get('ordinary')===['value'=>1],'Existing framework file format must remain readable and writable');
check($store->clear()&&!file_exists($temp.'/runtime/cache')&&$store->get('ordinary')===null,'Successful clear must remove real cache entries');
check($store->clear()&&$store->set('after-clear','new',30)&&$store->get('after-clear')==='new','Repeated cleanup and subsequent writes must work');
$alpha=new File($app,['path'=>$temp.'/namespaced','prefix'=>'alpha']);$beta=new File($app,['path'=>$temp.'/namespaced','prefix'=>'beta']);
$alpha->set('same','alpha',30);$beta->set('same','beta',30);
check($alpha->clear()&&$alpha->get('same')===null&&$beta->get('same')==='beta','Clearing one configured file namespace must preserve sibling namespaces');
$zero=new File($app,['path'=>$temp.'/zero','prefix'=>'0']);$zero->set('ordinary','zero',30);
check($zero->clear()&&$zero->get('ordinary')===null,'Framework false-like string prefix must clear the same location used for storage');
mkdir($temp.'/outside',0700);file_put_contents($temp.'/outside/sentinel','preserved');
foreach(['','/','/.','/./'] as $suffix) {
    symlink($temp.'/outside',$temp.'/linked');$linked=new File($app,['path'=>$temp.'/linked'.$suffix]);
    check(!$linked->clear()&&is_link($temp.'/linked')&&file_get_contents($temp.'/outside/sentinel')==='preserved','A linked file-cache root must fail clearly without deleting its link or target');
    unlink($temp.'/linked');
}
symlink($temp.'/outside',$temp.'/linked');
check(!(new File($app,['path'=>$temp.'/linked','prefix'=>'missing']))->clear(),'A missing namespace under a linked root must not report successful cleanup');
unlink($temp.'/linked');symlink($temp.'/absent',$temp.'/broken');
check(!(new File($app,['path'=>$temp.'/broken']))->clear()&&is_link($temp.'/broken'),'A broken cache root is a configuration failure rather than an empty physical directory');
mkdir($temp.'/children');symlink($temp.'/outside',$temp.'/children/link');symlink($temp.'/absent',$temp.'/children/broken');
check((new File($app,['path'=>$temp.'/children']))->clear()&&file_get_contents($temp.'/outside/sentinel')==='preserved','Child links may be removed as entries without traversing targets');
file_put_contents($temp.'/wrong-file','preserved');
check(!(new File($app,['path'=>$temp.'/wrong-file']))->clear()&&file_get_contents($temp.'/wrong-file')==='preserved','A cache root that is a regular file must fail without deleting it');
check(!(new File($app,['path'=>$temp.'/wrong-file/missing']))->clear(),'A non-directory ancestor cannot masquerade as an already absent cache');
foreach(['../outside','/outside','alpha/../outside','alpha/./child',"bad\0name",'file://outside','alpha\\..\\outside',[],true] as $prefix) {
    check(!(new File($app,['path'=>$temp.'/namespaced','prefix'=>$prefix]))->clear()&&$beta->get('same')==='beta','Malformed namespace must fail before deleting any cache data');
}
check(!(new File($app,['path'=>$temp.'/missing/../outside']))->clear(),'Parent traversal in a missing cache path must fail validation');
if(($argv[1]??'')==='unprivileged') {
    mkdir($temp.'/locked/child',0700,true);file_put_contents($temp.'/locked/child/entry','preserved');chmod($temp.'/locked/child',0555);
    check(!is_writable($temp.'/locked/child'),'Permission fixture must run as an unprivileged account');
    $locked=new File($app,['path'=>$temp.'/locked']);
    check(!$locked->clear()&&file_get_contents($temp.'/locked/child/entry')==='preserved','A real child deletion failure must propagate through the cache driver');
    chmod($temp.'/locked/child',0700);check($locked->clear(),'A deliberate retry after fixing permissions must succeed');
    mkdir($temp.'/blocked-parent',0700);chmod($temp.'/blocked-parent',0000);
    check(!(new File($app,['path'=>$temp.'/blocked-parent/missing']))->clear(),'An inaccessible parent cannot be mistaken for an empty cache');
    chmod($temp.'/blocked-parent',0700);
}
class ClearRedisFixture extends \app\common\cache\Redis {
    public object $client;
    public function __construct($result) {$this->client=new class($result) {
        public int $calls=0;
        public function __construct(public $result) {}
        public function flushDB() {$this->calls++;if($this->result instanceof Throwable)throw $this->result;return $this->result;}
    };}
    public function handler() {return $this->client;}
}
foreach([true,false,null,0,1] as $result) {
    $redis=new ClearRedisFixture($result);
    check($redis->clear()===($result===true)&&$redis->client->calls===1,'Redis clear may report success only after the client confirms it');
}
$redis=new ClearRedisFixture(new RuntimeException('fixture backend failure'));
try {$redis->clear();throw new LogicException('Redis failure was hidden');}
catch(RuntimeException $error) {check($error->getMessage()==='fixture backend failure','Redis exceptions must remain available to the caller');}
echo 'Cache clear: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($argv[1]??'ordinary')."\n";
