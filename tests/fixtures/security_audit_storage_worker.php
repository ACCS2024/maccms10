<?php
/** Real second connection; SDK boundary is controlled and never contacts a provider. */
declare(strict_types=1);
require __DIR__.'/security_audit_storage_providers.php';
require dirname(__DIR__,2).'/vendor/autoload.php';
[$script,$root,$id,$mode,$marker]=$argv;
if (!str_contains(basename(rtrim($root,'/')),'storage-intent-'))throw new RuntimeException('Worker requires isolated storage fixture');
define('ROOT_PATH',$root);define('MAC_PATH','/');chdir($root);
function request() {return think\Container::getInstance()->make('request');}
function config($key,$default=null) {return think\facade\Config::get($key,$default);}
$data=json_decode(file_get_contents($root.'process.json'),true,512,JSON_THROW_ON_ERROR);
$database=$data['database'];$GLOBALS['config']=['upload'=>['api'=>$data['settings']]];
$manager=new think\DbManager();$manager->setConfig($database);$configuration=new think\Config();$configuration->set($database,'database');
think\Container::getInstance()->instance('think\\DbManager',$manager);think\Container::getInstance()->instance('config',$configuration);
think\Container::getInstance()->instance('request',(new think\Request())->withServer(['REQUEST_METHOD'=>'POST','REQUEST_TIME'=>time()]));
$GLOBALS['storage_provider_calls']=0;$GLOBALS['storage_provider_mode']='success';
$GLOBALS['storage_provider_callback']=static function () use($mode,$marker,$root,$id):void {
    file_put_contents($root.'provider-calls.log',$id."\n",FILE_APPEND|LOCK_EX);
    file_put_contents($root.'remote-object-'.$id,'controlled remote bytes');
    if ($mode!=='pause')return;
    file_put_contents($marker.'.ready','provider accepted');$deadline=microtime(true)+15;
    while (!is_file($marker.'.release') && microtime(true)<$deadline){usleep(10000);clearstatcache();}
    if (!is_file($marker.'.release'))throw new RuntimeException('Fixture pause not released');
};
try {$result=app\common\util\StorageTransfer::attempt($id);}
catch(Throwable $error){$result=['outcome'=>'rejected','provider_calls'=>$GLOBALS['storage_provider_calls']];}
echo json_encode($result,JSON_THROW_ON_ERROR);
