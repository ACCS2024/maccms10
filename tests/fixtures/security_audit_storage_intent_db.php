<?php
/** Independent storage-only database and filesystem. Never loads the application entry or production config. */
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/security_audit_test_helpers.php';
require dirname(__DIR__,2).'/migration/lib/StorageIntentMigration.php';
use think\facade\Db;
function request() {return think\Container::getInstance()->make('request');}
function config($key,$default=null) {return think\facade\Config::get($key,$default);}
$mysql=getenv('STORAGE_AUDIT_MYSQL')==='1';
$database=['default'=>'storage','auto_timestamp'=>false,'connections'=>['storage'=>[
    'type'=>$mysql?'mysql':'sqlite','database'=>$mysql?'maccms_audit_storage':':memory:','prefix'=>'storage_audit_',
    'hostname'=>getenv('STORAGE_AUDIT_HOST')?:'127.0.0.1','username'=>'root','password'=>getenv('STORAGE_AUDIT_PASSWORD')?:'',
    'charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false,
]]];
$manager=new think\DbManager();$manager->setConfig($database);
$fixtureConfig=new think\Config();$fixtureConfig->set($database,'database');
think\Container::getInstance()->instance('think\\DbManager',$manager);
think\Container::getInstance()->instance('config',$fixtureConfig);
think\Container::getInstance()->instance('request',(new think\Request())->withServer(['REQUEST_METHOD'=>'POST','REQUEST_TIME'=>time()]));
if ($mysql) {
    Db::execute("SET SESSION sql_mode=''");
    Db::execute('DROP TABLE IF EXISTS storage_audit_storage_intent');
    $migration=new StorageIntentMigration(Db::connect()->getPdo(),'storage_audit_');
    $before=$migration->preflight();
    check($before['blockers']===[] && count($before['changes'])===1,'Fresh storage preflight incorrect');
    check(Db::query("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='storage_audit_storage_intent'")[0]['n']===0,'Read-only preflight created a table');
    check($migration->apply()['changes']===[] && $migration->preflight()['blockers']===[],'Actual MySQL intent DDL did not validate');
    $install=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
    foreach (['user','annex'] as $name) {
        preg_match('/CREATE TABLE `mac_'.$name.'` \([\s\S]*?\) ENGINE[^;]*;/',$install,$match);
        Db::execute('DROP TABLE IF EXISTS storage_audit_'.$name);
        Db::execute(str_replace('`mac_'.$name.'`','`storage_audit_'.$name.'`',$match[0]));
    }
} else {
    $columns=[];
    foreach (StorageIntentMigration::COLUMNS as $name=>$type)$columns[]=$name.' '.(str_contains($type,'int')?'INTEGER':'TEXT').' NOT NULL';
    Db::execute('CREATE TABLE storage_audit_storage_intent ('.implode(',',$columns).',PRIMARY KEY(intent_id),UNIQUE(local_path))');
    Db::execute('CREATE TABLE storage_audit_user (user_id INTEGER PRIMARY KEY, user_portrait TEXT NOT NULL DEFAULT "")');
    Db::execute('CREATE TABLE storage_audit_annex (annex_id INTEGER PRIMARY KEY AUTOINCREMENT,annex_file TEXT,annex_size INTEGER,annex_type TEXT,annex_time INTEGER)');
}
Db::name('User')->insert(['user_id'=>1,'user_portrait'=>'']);
$temporary=audit_temp_dir('storage-intent');$cwd=getcwd();
define('ROOT_PATH',$temporary.'/');define('MAC_PATH','/');chdir($temporary);
register_shutdown_function(static function () use($cwd,$temporary):void {chdir($cwd);if(is_dir($temporary))audit_remove_temp($temporary);});
mkdir('upload/vod',0755,true);mkdir('upload/user/1',0755,true);
mkdir('extend/qiniu',0755,true);mkdir('extend/upyun/vendor',0755,true);
file_put_contents('extend/qiniu/autoload.php','<?php');file_put_contents('extend/upyun/vendor/autoload.php','<?php');
$settings=['bucket'=>'audit-bucket','region'=>'us-east-1','domain'=>'https://objects.fixture.invalid',
    'url'=>'https://objects.fixture.invalid/files','accesskey'=>'fixture-key','secretkey'=>'fixture-secret',
    'username'=>'fixture-user','pwd'=>'fixture-password','host'=>'fixture','port'=>21,'user'=>'fixture','path'=>'/',
    'public_url_prefix'=>'https://images.fixture.invalid/objects'];
foreach(app\common\util\StoragePublicUrl::PROVIDERS as $provider)$GLOBALS['config']['upload']['api'][$provider]=$settings;
$GLOBALS['storage_provider_calls']=0;$GLOBALS['storage_provider_mode']='success';
function storageFile(string $prefix='file'):string {
    $path='upload/vod/'.$prefix.'-'.bin2hex(random_bytes(8)).'.txt';file_put_contents($path,'controlled upload bytes');return $path;
}
function storageRejected(callable $operation,string $label):void {
    $before=Db::name('StorageIntent')->order('intent_id')->select()->toArray();$calls=$GLOBALS['storage_provider_calls'];
    try {$operation();$thrown=false;}catch(Throwable $error){$thrown=true;}
    check($thrown && Db::name('StorageIntent')->order('intent_id')->select()->toArray()===$before
        && $GLOBALS['storage_provider_calls']===$calls,$label.' did not reject without persistence/provider side effects');
}
