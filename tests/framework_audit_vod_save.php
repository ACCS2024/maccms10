<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
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
define('ROOT_PATH',$temp.'/site/');define('APP_PATH',dirname(__DIR__).'/application/');
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
$sql=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');preg_match('/CREATE TABLE `mac_vod` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$match);
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

function vodSaveSeed():array {
 Db::execute('DELETE FROM vod_save_audit_vod');Db::execute('DELETE FROM vod_save_audit_vod_repeat');
 Db::name('Vod')->insert(['vod_id'=>7,'vod_name'=>'Before','type_id'=>1,'vod_en'=>'before','vod_content'=>'Before description','vod_blurb'=>'Before summary',
 'vod_plot_name'=>'','vod_plot_detail'=>'',
 'vod_play_from'=>'oldplayer','vod_play_server'=>'oldserver','vod_play_note'=>'Old note','vod_play_url'=>'Episode$https://cdn.example/old.mp4',
 'vod_down_from'=>'olddown','vod_down_server'=>'oldserver','vod_down_note'=>'Old download note','vod_down_url'=>'Download$https://cdn.example/old.zip']);
 return Db::name('Vod')->where('vod_id',7)->find();
}
function vodSave(array $data):array {
 $result=(new app\common\model\Vod())->saveData($data);check($result['code']===1,'Normal source save succeeds');
 return Db::name('Vod')->where('vod_id',7)->find();
}
function vodSaveReject($data,string $label):void {
 $before=Db::name('Vod')->order('vod_id')->select()->toArray();$repeat=Db::query('SELECT * FROM vod_save_audit_vod_repeat');
 $result=(new app\common\model\Vod())->saveData($data);check($result['code']===1001,'Invalid input is controlled: '.$label);
 check(Db::name('Vod')->order('vod_id')->select()->toArray()===$before && Db::query('SELECT * FROM vod_save_audit_vod_repeat')===$repeat,'Rejected input changes neither resource nor repeat catalog: '.$label);
}
define('ENTRANCE','admin');define('MAC_PLAYER_SORT','0');
$app->config->set(['oldplayer'=>['status'=>'1','sort'=>1],'player'=>['status'=>'1','sort'=>1],'second'=>['status'=>'1','sort'=>2]],'vodplayer');
$app->config->set(['olddown'=>['status'=>'1','sort'=>1],'player'=>['status'=>'1','sort'=>1],'second'=>['status'=>'1','sort'=>2]],'voddowner');
$app->config->set([],'vodserver');
$base=['vod_id'=>7,'vod_name'=>'Ordinary video','type_id'=>1];
foreach(['','NO_AUTO_VALUE_ON_ZERO','STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO']as $mode){
 Db::execute("SET SESSION sql_mode='".$mode."'");
 foreach(['omitted','',null,0,'0','000']as $id){
  vodSaveSeed();$data=['vod_name'=>'New video','type_id'=>1];if($id!=='omitted')$data['vod_id']=$id;
  $result=(new app\common\model\Vod())->saveData($data);$row=Db::name('Vod')->where('vod_id','<>',7)->find();
  check($result['code']===1 && $row!==null && $row['vod_id']>7,'Minimum insert uses actual auto increment');
  foreach(['vod_content','vod_play_url','vod_down_url','vod_plot_name','vod_plot_detail']as $field)check($row[$field]==='','Strict SQL receives explicit MEDIUMTEXT default: '.$field);
 }
 $before=vodSaveSeed();$row=vodSave($base);
 foreach(['vod_content','vod_blurb','vod_play_from','vod_play_server','vod_play_note','vod_play_url','vod_down_from','vod_down_server','vod_down_note','vod_down_url']as $field)check($row[$field]===$before[$field],'Omitted edit column is preserved: '.$field);
 foreach(['',null,'0','Ordinary description']as $body){
  vodSaveSeed();$row=vodSave($base+['vod_content'=>$body]);
  check($row['vod_content']===($body??'') && $row['vod_blurb']===($body??''),'Description clear/null/zero/plain semantics');
  check($row['vod_play_from']==='oldplayer' && $row['vod_down_from']==='olddown','Description edit keeps both source groups');
 }
 foreach(['play','down']as $op){
  $prefix='vod_'.$op.'_';$other='vod_'.($op==='play'?'down':'play').'_';
  foreach(['strings','arrays','optional-metadata']as $shape){
   vodSaveSeed();$data=[$prefix.'from'=>'player$$$second',$prefix.'url'=>'One$https://cdn.example/1.mp4$$$Two$https://cdn.example/2.mp4'];
   if($shape!=='optional-metadata')$data+=[$prefix.'server'=>'no$$$no',$prefix.'note'=>'First$$$Second'];
   if($shape==='arrays')foreach($data as $key=>$value)$data[$key]=explode('$$$',$value);
   $row=vodSave($base+$data);$pages=mac_play_list($row[$prefix.'from'],$row[$prefix.'url'],$row[$prefix.'server'],$row[$prefix.'note'],$op);
   check(array_keys($pages)===[1,2] && $pages[2]['urls'][1]['url']==='https://cdn.example/2.mp4','Actual reader preserves source/episode coordinates: '.$shape.'/'.$op);
   check($row[$other.'url']===($op==='play'?'Download$https://cdn.example/old.zip':'Episode$https://cdn.example/old.mp4'),'Updating one source group preserves the other');
  }
  foreach(["\n","\r\n","\r"]as $newline){
   vodSaveSeed();$row=vodSave($base+[$prefix.'from'=>['player'],$prefix.'url'=>['One$https://cdn.example/1.mp4'.$newline.'Two$https://cdn.example/2.mp4']]);
   $pages=mac_play_list($row[$prefix.'from'],$row[$prefix.'url'],$row[$prefix.'server'],$row[$prefix.'note'],$op);
   check(count($pages[1]['urls'])===2 && $pages[1]['urls'][2]['url']==='https://cdn.example/2.mp4','CR/LF/CRLF each separate real episodes');
  }
  foreach([[$prefix.'from'=>[]],[$prefix.'from'=>''],[$prefix.'present'=>'1']]as $clear){
   $before=vodSaveSeed();$row=vodSave($base+$clear);
   foreach(['from','server','note','url']as $suffix)check($row[$prefix.$suffix]==='' && $row[$other.$suffix]===$before[$other.$suffix],'Explicit clear affects only its submitted group');
  }
  foreach(['url','note','server']as $suffix)vodSaveReject($base+[$prefix.$suffix=>'value'],'companion without source');
 }
 vodSaveSeed();$row=vodSave($base+['vod_play_present'=>1,'vod_down_present'=>'1']);check($row['vod_play_url']==='' && $row['vod_down_url']==='','Full form can delete every group');
 foreach(['vod_id'=>'7.5','type_id'=>32768,'vod_play_present'=>[],'vod_content'=>['nested'],'vod_play_from'=>[['nested']]]as $field=>$value)vodSaveReject(array_replace($base,[$field=>$value]),$field);
 vodSaveSeed();$prefix='Episode$https://cdn.example/';$episode=$prefix.str_repeat('a',419-strlen($prefix)).'#';check(strlen($episode)===420,'Capacity fixture uses bounded ordinary episode URLs');
 $prefix='Episode$https://cdn.example/';$remainder=8388608%420;
 $urls=str_repeat($episode,intdiv(8388608,420)).$prefix.str_repeat('b',$remainder-strlen($prefix));
 $row=vodSave($base+['vod_content'=>str_repeat('c',1048576),'vod_play_from'=>'player','vod_play_url'=>$urls,'vod_down_from'=>'player','vod_down_url'=>str_replace('cdn.example','dlx.example',$urls)]);
 check(strlen($row['vod_content'])===1048576 && strlen($row['vod_play_url'])===8388608 && strlen($row['vod_down_url'])===8388608,'Combined description and both episode catalogs persist at their byte limits');
 unset($row,$urls);

}
echo 'Vod save fixture peak: '.round(memory_get_peak_usage(true)/1048576,2).' MiB; limit '.ini_get('memory_limit').PHP_EOL;
echo 'framework_audit_vod_save: '.$checks.' checks passed on PHP '.PHP_VERSION.' / installation MySQL (three SQL modes)'.PHP_EOL;
