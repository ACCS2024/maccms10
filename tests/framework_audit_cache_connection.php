<?php
/** Actual cache stores, native clients and isolated local daemons; no live configuration or credentials. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\CacheConnection;
function lang($key,...$values){return $key;}
function request(){return \think\Container::getInstance()->make('request');}
function json($data){return \think\Response::create($data,'json');}
$temp=audit_temp_dir('cache-connection');$processes=[];
register_shutdown_function(static function()use($temp,&$processes):void{
    foreach($processes as $process){
        if(proc_get_status($process)['running'])proc_terminate($process);
        for($i=0;$i<50&&proc_get_status($process)['running'];$i++)usleep(20000);
        if(proc_get_status($process)['running'])proc_terminate($process,9);
        proc_close($process);
    }
    audit_remove_temp($temp);
});
$app=new \think\App($temp.'/app');
$app->setRuntimePath($temp.'/runtime/');
$GLOBALS['config']=['app'=>['cache_timeout'=>0.2]];
function cachePort():int{$socket=stream_socket_server('tcp://127.0.0.1:0',$error,$message);$name=stream_socket_get_name($socket,false);fclose($socket);return (int)substr($name,strrpos($name,':')+1);}
function cacheBinary(string $name):?string{
    foreach(explode(PATH_SEPARATOR,getenv('PATH')?:'')as $directory){$file=$directory.'/'.$name;if(is_file($file)&&is_executable($file))return $file;}return null;
}
function memcachedCommand(int $port):array{
    $command=[cacheBinary('memcached'),'-l','127.0.0.1','-p',(string)$port,'-U','0'];
    if(function_exists('posix_geteuid')&&posix_geteuid()===0){$command[]='-u';$command[]='root';}
    return $command;
}
function cacheDaemon(array $command,int $port,array $environment=[]):void{
    global $temp,$processes;
    $log=$temp.'/daemon-'.count($processes).'.log';
    $process=proc_open($command,[0=>['file','/dev/null','r'],1=>['file',$log,'a'],2=>['file',$log,'a']],$pipes,$temp,$environment?array_replace(getenv(),$environment):null);
    if(!is_resource($process))throw new RuntimeException('Isolated cache daemon failed to start');$processes[]=$process;
    for($i=0;$i<100;$i++){
        $socket=@fsockopen('127.0.0.1',$port,$error,$message,0.02);if($socket){fclose($socket);return;}
        if(!proc_get_status($process)['running'])throw new RuntimeException('Cache fixture failed: '.file_get_contents($log));usleep(20000);
    }
    throw new RuntimeException('Cache fixture startup timed out');
}
function cacheConfig(array $values):array{
    global $temp;
    $directory=$temp.'/site';if(!is_dir($directory.'/config'))mkdir($directory.'/config',0700,true);
    if(!is_dir($directory.'/application/extra'))mkdir($directory.'/application/extra',0700,true);
    copy(dirname(__DIR__).'/config/cache.php',$directory.'/config/cache.php');
    file_put_contents($directory.'/application/extra/maccms.php','<?php return '.var_export(['app'=>$values],true).';');
    return require $directory.'/config/cache.php';
}
function cacheStore(array $values,string $name):\think\cache\Driver{
    global $app;
    $app->config->set(cacheConfig($values),'cache');return (new \think\Cache($app))->store($name);
}
function cacheProbe(array $body,array $query=[],string $method='POST'):array{
    global $app;
    $request=(new \app\Request())->withServer(['REQUEST_METHOD'=>$method])->withPost($body)->withGet($query);$app->instance('request',$request);
    $controller=(new ReflectionClass(\app\admin\controller\System::class))->newInstanceWithoutConstructor();
    $response=$controller->test_cache();
    check($response instanceof \think\response\Json,'Actual cache test action must return controlled JSON');return $response->getData();
}
function invalidCache(array $values):void{
    try{cacheConfig($values);throw new RuntimeException('Invalid selected cache config was accepted');}
    catch(InvalidArgumentException $error){check(true,'Invalid selected cache settings must be rejected before constructing a connection');}
}
$configuration=cacheConfig(['cache_type'=>'file','cache_host'=>[],'cache_port'=>[],'cache_username'=>[],'cache_password'=>[],'cache_db'=>[],'cache_timeout'=>[]]);
check($configuration['default']==='file'&&$configuration['stores']['file']['expire']===60,'Unselected backend fields cannot break normal file-cache configuration');
$app->config->set($configuration,'cache');$manager=new \think\Cache($app);$file=$manager->store('file');
check($file->set('fixture-file','value',2)&&$file->get('fixture-file')==='value'&&$file->delete('fixture-file'),'Actual file storage remains usable despite unrelated malformed network settings');
try{$manager->store('redis');throw new RuntimeException('Malformed lazy Redis store was accepted');}catch(InvalidArgumentException $error){check(true,'Explicit use of an unselected named store must validate its original settings');}
foreach([null,'',0,'0',-1,'-1']as $value){check(cacheConfig(['cache_time'=>$value])['stores']['file']['expire']===60,'Missing/nonpositive cache lifetime keeps the established fallback');check(CacheConnection::timeout($value)===1.5,'Missing/nonpositive cache timeout keeps the established finite fallback');}
foreach([['cache_type'=>[]],['cache_type'=>'arbitrary\\class'],['cache_time'=>[]],['cache_time'=>true],['cache_time'=>'invalid']]as $values)invalidCache($values);
foreach(['cache_host','cache_port','cache_username','cache_password','cache_db','cache_timeout']as $field){foreach([[],true]as $bad)invalidCache(['cache_type'=>'redis',$field=>$bad]);}
foreach([['cache_port'=>'0'],['cache_port'=>'65536'],['cache_host'=>''],['cache_host'=>"ordinary\ninvalid"],['cache_db'=>'-1'],['cache_timeout'=>'invalid']]as $values)invalidCache(['cache_type'=>'redis']+$values);
foreach(['GET','PUT','DELETE']as $method)check(cacheProbe([],['type'=>'file'],$method)['code']>1,'Cache probing requires an actual POST body');
check(cacheProbe(['type'=>'file','_method'=>'GET'])['code']>1,'An effective GET override must not authorize a cache write probe');
check(cacheProbe(['type'=>'file','_method'=>'POST'],[],'GET')['code']>1,'A GET transport cannot become an authorized write probe through an override');
check(cacheProbe([],['type'=>'file'])['code']>1,'Query parameters cannot supply the backend type');
check(cacheProbe(['type'=>[]])['code']>1,'Structured backend type must not become a dynamic driver class');
check(cacheProbe(['type'=>'file'],['type'=>'redis','host'=>'other.invalid'])['code']===1,'A normal file-cache POST ignores query overrides');
try{trigger_error('fixture prior error handler',E_USER_NOTICE);throw new RuntimeException('Probe lost prior error handler');}
catch(ErrorException $error){check($error->getMessage()==='fixture prior error handler','Probe must restore the application error handler');}
foreach(['memcache','memcached']as $type)invalidCache(['cache_type'=>$type,'cache_time'=>2147483647]);
invalidCache(['cache_type'=>'memcache','cache_username'=>'unsupported']);
invalidCache(['cache_type'=>'memcached','cache_username'=>'incomplete']);
foreach(['memcache','memcached','redis']as $type){
    if(!extension_loaded($type))check(cacheProbe(['type'=>$type,'host'=>'127.0.0.1','port'=>'12345'])['msg']==='Cache extension unavailable','Missing native extension must be an explicit controlled failure');
    else check(cacheProbe(['type'=>$type,'host'=>'127.0.0.1','port'=>(string)cachePort(),'timeout'=>0.05])['code']>1,'A refused connection cannot report successful cache verification');
}
try{CacheConnection::timeout(INF);throw new RuntimeException('Nonfinite timeout accepted');}catch(InvalidArgumentException $error){check(true,'Nonfinite timeouts cannot reach a driver');}
// Explicit null connection fields are malformed, never instructions to choose another host or omit authentication.
invalidCache(['cache_type'=>null]);
foreach(['cache_host','cache_port','cache_username','cache_password','cache_db'] as $field)invalidCache(['cache_type'=>'redis',$field=>null]);
foreach(['tcp://127.0.0.1','tls://127.0.0.1','/tmp/cache.sock','user@host','host?option','host#fragment'] as $host)invalidCache(['cache_type'=>'redis','cache_host'=>$host]);
$listener=stream_socket_server('tcp://127.0.0.1:0',$error,$message);
$listenerName=stream_socket_get_name($listener,false);$listenerPort=(int)substr($listenerName,strrpos($listenerName,':')+1);
try {
    foreach(['redis','memcache','memcached'] as $type) {
        foreach(['host','port','username','password'] as $field) {
            $body=['type'=>$type,'host'=>'127.0.0.1','port'=>$listenerPort,'timeout'=>0.01];$body[$field]=null;
            check(cacheProbe($body)['code']===1001,'Explicit null must be rejected as configuration, before connecting or dropping credentials');
        }
    }
    check(@stream_socket_accept($listener,0)===false,'Malformed connection fields started a real network connection');
} finally {fclose($listener);}
$redisAvailable=extension_loaded('redis')&&cacheBinary('redis-server');
if($redisAvailable){
    $port=cachePort();$acl=$temp.'/users.acl';
    file_put_contents($acl,"user default on >fixture-default ~* +@all\nuser cacheuser on >fixture-named ~* +@all\nuser nodelete on >fixture-named ~* +get +set +setex +ttl +select\n");
    cacheDaemon([cacheBinary('redis-server'),'--bind','127.0.0.1','--port',(string)$port,'--save','','--appendonly','no','--aclfile',$acl],$port);
    $admin=new Redis();$admin->connect('127.0.0.1',$port,0.2);$admin->auth('fixture-default');$admin->set('test','unrelated-value');
    $body=['type'=>'redis','host'=>'127.0.0.1','port'=>(string)$port,'username'=>'cacheuser','password'=>'fixture-named','db'=>'2','timeout'=>'0.2'];
    check(cacheProbe($body)['code']===1,'Real named Redis ACL credentials must work through the actual probe action');
    check($admin->get('test')==='unrelated-value','The probe must not overwrite the legacy fixed test key');
    foreach([['username'=>'unknown','password'=>'fixture-default'],['password'=>'wrong'],['username'=>'','password'=>'fixture-named']]as $bad){
        $result=cacheProbe(array_replace($body,$bad));check($result['code']>1&&$result['msg']==='Cache authentication failed','Invalid Redis ACL credentials must fail even when a different user password is valid');
    }
    $values=['cache_type'=>'redis','cache_host'=>'127.0.0.1','cache_port'=>$port,'cache_username'=>'cacheuser','cache_password'=>'fixture-named','cache_db'=>2,'cache_timeout'=>0.2,'cache_time'=>45];
    $store=cacheStore($values,'redis');
    check($store->set('runtime-fixture',['normal'=>'cache'])&&$store->get('runtime-fixture')===['normal'=>'cache'],'Actual production configuration must authenticate and retain cache serialization');
    check($store->handler()->ttl('runtime-fixture')>0&&$store->handler()->ttl('runtime-fixture')<=45,'Production default TTL must reach the actual Redis database');
    check(abs($store->handler()->getOption(Redis::OPT_READ_TIMEOUT)-0.2)<0.001,'Redis socket read timeout must retain its fractional value');
    $admin->select(0);check(!$admin->exists('runtime-fixture'),'Configured Redis database must be selected in the actual runtime connection');
    $store->delete('runtime-fixture');$store->disconnect();
    $app->config->set(cacheConfig($values),'cache');$sessionManager=new \think\Cache($app);
    $session=new \think\session\driver\Cache($sessionManager,['store'=>'redis','expire'=>45,'prefix'=>'session-fixture-']);
    check($session->write('normal','session-value')&&$session->read('normal')==='session-value'&&$session->delete('normal'),
        'The existing session cache driver must reuse the actual named Redis store and ACL credentials');
    $sessionManager->store('redis')->disconnect();
    check(cacheProbe(array_replace($body,['username'=>'','password'=>'fixture-default']))['code']===1,'Password-only legacy Redis configuration must remain usable');
    check(cacheProbe(array_replace($body,['username'=>'nodelete','db'=>'0']))['code']>1,'A probe that cannot remove its own key cannot report success');
    $keys=$admin->keys('mac_probe_*');check(count($keys)===1,'A cleanup failure leaves only its unpredictable owned probe key');
    check($admin->ttl($keys[0])>0&&$admin->ttl($keys[0])<=30,'A failed cleanup must still leave a short-lived key');$admin->del($keys[0]);
    check(cacheProbe(array_replace($body,['db'=>'100000']))['code']>1,'A refused Redis database index must be controlled');
    $admin->close();
}
$memcachedAvailable=cacheBinary('memcached')&&(extension_loaded('memcache')||extension_loaded('memcached'));
if(getenv('CACHE_AUDIT_REQUIRE_NATIVE')==='1')check($redisAvailable && $memcachedAvailable && extension_loaded('memcache') && extension_loaded('memcached') && Memcached::HAVE_SASL && cacheBinary('saslpasswd2'), 'Required real cache clients, daemons and SASL fixtures must all be available');
if($memcachedAvailable){
    $port=cachePort();cacheDaemon(memcachedCommand($port),$port);
    foreach(['memcache','memcached']as $type){if(!extension_loaded($type))continue;
        $body=['type'=>$type,'host'=>'127.0.0.1','port'=>$port,'timeout'=>0.2];check(cacheProbe($body)['code']===1,'Actual '.$type.' probe must write, read and remove a temporary key');
        $store=cacheStore(['cache_type'=>$type,'cache_host'=>'127.0.0.1','cache_port'=>$port,'cache_timeout'=>0.2],$type);
        check($store->set('normal-'.$type,'value',30)&&$store->get('normal-'.$type)==='value'&&$store->delete('normal-'.$type),'Actual '.$type.' runtime store must share the probe connection settings');
        if($type==='memcached'){check($store->handler()->getOption(Memcached::OPT_CONNECT_TIMEOUT)===200&&$store->handler()->getOption(Memcached::OPT_RECV_TIMEOUT)===200000,'Memcached connection/read timeouts must use the native millisecond/microsecond units');}
        foreach([2592000,2678400,new DateTimeImmutable('+31 days'),new DateInterval('P31D'),0]as $lifetime){
            check($store->set('lifetime-'.$type,'value',$lifetime)&&$store->get('lifetime-'.$type)==='value'&&$store->delete('lifetime-'.$type),
                'Actual '.$type.' storage must preserve relative, long, date, interval and explicit permanent expiry semantics');
        }
        check($store->set('past-'.$type,'value',new DateTimeImmutable('-1 day'))&&$store->get('past-'.$type)===null,
            'A past '.$type.' expiration must not create an immortal cache value');
        try{$store->set('overflow-'.$type,'value',PHP_INT_MAX);throw new RuntimeException('Overflowing expiration accepted');}
        catch(InvalidArgumentException $error){check($store->get('overflow-'.$type)===null,'Overflowing '.$type.' expiration must fail before any write');}
        $store->disconnect();
        $store=cacheStore(['cache_type'=>$type,'cache_host'=>'127.0.0.1','cache_port'=>$port,'cache_timeout'=>0.2,'cache_time'=>2678400],$type);
        check($store->set('default-long-'.$type,'value')&&$store->get('default-long-'.$type)==='value'&&$store->delete('default-long-'.$type),
            'Configured default '.$type.' TTL over 30 days must remain readable');$store->disconnect();
    }
}

if($memcachedAvailable&&extension_loaded('memcached')&&Memcached::HAVE_SASL&&cacheBinary('saslpasswd2')){
    $sasl=$temp.'/sasl';mkdir($sasl);$database=$sasl.'/users.db';$password='fixture+sasl%40&pass';
    $process=proc_open([cacheBinary('saslpasswd2'),'-a','memcached','-c','-p','-f',$database,'cacheuser'],
        [0=>['pipe','r'],1=>['file',$sasl.'/setup.log','a'],2=>['file',$sasl.'/setup.log','a']],$pipes,$temp);
    fwrite($pipes[0],$password."\n");fclose($pipes[0]);check(proc_close($process)===0,'Isolated SASL fixture credentials must initialize');
    file_put_contents($sasl.'/memcached.conf',"mech_list: plain\npwcheck_method: auxprop\nauxprop_plugin: sasldb\nsasldb_path: ".$database."\n");
    $port=cachePort();cacheDaemon(array_merge(memcachedCommand($port),['-S']), $port,['SASL_CONF_PATH'=>$sasl]);
    $body=['type'=>'memcached','host'=>'127.0.0.1','port'=>$port,'username'=>'cacheuser','password'=>$password,'timeout'=>0.2];
    check(cacheProbe($body,['username'=>'other','password'=>'wrong'])['code']===1,'Real Memcached SASL must receive exact POST credentials without query overrides');
    $store=cacheStore(['cache_type'=>'memcached','cache_host'=>'127.0.0.1','cache_port'=>$port,'cache_username'=>'cacheuser','cache_password'=>$password,'cache_timeout'=>0.2],'memcached');
    check($store->set('sasl-runtime','value',30)&&$store->get('sasl-runtime')==='value'&&$store->delete('sasl-runtime'),
        'The actual production Memcached store must use the same working SASL credentials');
    check(!$store->handler()->isPersistent(),'Actual Memcached store must not reuse a persistent client');$store->disconnect();
    $bad=cacheProbe(array_replace($body,['password'=>'wrong']));
    check($bad['code']>1&&$bad['msg']==='Cache authentication failed','Memcached authentication refusal must be identified without exposing credentials');
}
foreach(['redis','memcache','memcached']as $type){if(!extension_loaded($type))continue;
    $port=cachePort();cacheDaemon([PHP_BINARY,__DIR__.'/fixtures/cache_silent_server.php',(string)$port],$port);
    $started=microtime(true);$result=cacheProbe(['type'=>$type,'host'=>'127.0.0.1','port'=>$port,'timeout'=>0.15]);$elapsed=microtime(true)-$started;
    check($result['code']>1&&$elapsed<2,'An unresponsive '.$type.' peer must fail within its bounded fractional read timeout');
}
fwrite(STDOUT,'Cache connection audit passed ('.$checks.' checks; Redis '.($redisAvailable?'real':'unavailable').', Memcache/Memcached '.($memcachedAvailable?'real':'unavailable').")\n");
