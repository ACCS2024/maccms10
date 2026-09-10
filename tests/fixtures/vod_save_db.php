<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require dirname(__DIR__,2).'/application/common.php';
require __DIR__.'/security_audit_test_helpers.php';
function config($name,$default=null){return think\facade\Config::get($name,$default);}
function lang($name,...$args){return $name;}
function request(){return think\Container::getInstance()->make('request');}
class VodSaveCache implements Psr\SimpleCache\CacheInterface {
 public array $data=[];
 public function get(string $key,mixed $default=null):mixed{return $this->data[$key]??$default;}
 public function set(string $key,mixed $value,null|int|DateInterval $ttl=null):bool{$this->data[$key]=$value;return true;}
 public function delete(string $key):bool{unset($this->data[$key]);return true;}
 public function clear():bool{$this->data=[];return true;}
 public function has(string $key):bool{return array_key_exists($key,$this->data);}
 public function getMultiple(iterable $keys,mixed $default=null):iterable{$out=[];foreach($keys as $key)$out[$key]=$this->get($key,$default);return $out;}
 public function setMultiple(iterable $values,null|int|DateInterval $ttl=null):bool{foreach($values as $key=>$value)$this->set($key,$value,$ttl);return true;}
 public function deleteMultiple(iterable $keys):bool{foreach($keys as $key)$this->delete($key);return true;}
}
use think\facade\Db;
$temp=audit_temp_dir('vod-save-probe');mkdir($temp.'/app');mkdir($temp.'/site');
define('ROOT_PATH',$temp.'/site/');define('APP_PATH',dirname(__DIR__,2).'/application/');
register_shutdown_function(static fn()=>audit_remove_temp($temp));
$app=new think\App($temp.'/app');
$app->config->set(['default'=>'file','channels'=>['file'=>['type'=>'file','path'=>$temp.'/logs','level'=>['notice']]]],'log');
$mysql=getenv('FRAMEWORK_AUDIT_MYSQL')==='1';
if(!$mysql)throw new RuntimeException('This model audit requires the dedicated MySQL fixture');
$connection=['type'=>'sqlite','database'=>':memory:','prefix'=>'vod_save_audit_','fields_cache'=>false];
if($mysql){
 $host=getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1';$password=getenv('FRAMEWORK_AUDIT_PASSWORD')?:'';
 $socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
 if($socket!==false){
  if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new RuntimeException('Invalid socket fixture');
  $password=getenv('DATABASE_AUDIT_PASSWORD');
  $dsn='mysql:unix_socket='.$socket.';charset=utf8mb4';
 }else{$database='maccms_audit_vod_save';$dsn='mysql:host='.$host.';charset=utf8mb4';}
 $server=new PDO($dsn,'root',$password,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
 $server->exec('CREATE DATABASE IF NOT EXISTS `'.$database.'` CHARACTER SET utf8mb4');$server=null;
 $connection=['type'=>'mysql','hostname'=>$host,'database'=>$database,'dsn'=>$dsn.';dbname='.$database,'username'=>'root','password'=>$password,'charset'=>'utf8mb4','prefix'=>'vod_save_audit_','fields_cache'=>false];
}
$configuration=['default'=>'mysql','auto_timestamp'=>false,'connections'=>['mysql'=>$connection]];
$app->config->set($configuration,'database');$manager=new think\DbManager();$manager->setConfig($configuration);$app->instance('think\DbManager',$manager);
$cache=new VodSaveCache();$cache->data['vod_save_type_list']=[1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>1,'type_name'=>'Vod']];$app->instance('cache',$cache);
$GLOBALS['config']=['app'=>['cache_flag'=>'vod_save','cache_core'=>0,'count_cache_sec'=>0], 'meilisearch'=>['enabled'=>0], 'upload'=>['protocol'=>'https']];
$sql=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');preg_match('/CREATE TABLE `mac_vod` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$match);
$fields=[];
foreach(explode("\n",$match[0])as $line){
 if(!preg_match('/^\s*`([a-z0-9_]+)`\s+(\w+)/',$line,$field))continue;
 if($field[1]==='vod_id'){$fields[]='vod_id INTEGER PRIMARY KEY AUTOINCREMENT';continue;}
 $type=preg_match('/int$/i',$field[2])?'INTEGER':(preg_match('/^(decimal|float|double)$/i',$field[2])?'REAL':'TEXT');
 $default=$type==='TEXT'?"''":'0';
 if(preg_match('/DEFAULT\s+(NULL|\x27[^\x27]*\x27|[0-9.]+)/i',$line,$value))$default=$value[1];
 $fields[]='`'.$field[1].'` '.$type.' DEFAULT '.$default;
}
Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod');
if($mysql){Db::execute(str_replace('`mac_vod`','`vod_save_audit_vod`',$match[0]));}
else{Db::execute('CREATE TABLE vod_save_audit_vod ('.implode(',',$fields).')');}
Db::execute('DROP TABLE IF EXISTS vod_save_audit_type');
if($mysql){
 preg_match('/CREATE TABLE `mac_type` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$typeDdl);
 Db::execute(str_replace('`mac_type`','`vod_save_audit_type`',$typeDdl[0]));
}else{Db::execute('CREATE TABLE vod_save_audit_type (type_id INTEGER PRIMARY KEY,type_pid INTEGER,type_mid INTEGER)');}
register_shutdown_function(static function(){Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod');Db::execute('DROP TABLE IF EXISTS vod_save_audit_type');});

Db::execute("SET SESSION sql_mode=''");
Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod_search');
preg_match('/CREATE TABLE `mac_vod_search` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$searchDdl);
Db::execute(str_replace('`mac_vod_search`','`vod_save_audit_vod_search`',$searchDdl[0]));
Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod_repeat');
Db::execute('CREATE TABLE vod_save_audit_vod_repeat (id1 INT UNSIGNED,name1 VARCHAR(255))');
register_shutdown_function(static function(){Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod_search');Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod_repeat');});
