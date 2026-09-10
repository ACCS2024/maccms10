<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function config($name,$default=null){return think\facade\Config::get($name,$default);}
function lang($name,...$args){return $name;}
function request(){return think\Container::getInstance()->make('request');}
class MangaSaveCache implements Psr\SimpleCache\CacheInterface {
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
$temp=audit_temp_dir('manga-save-probe');mkdir($temp.'/app');mkdir($temp.'/site');
define('ROOT_PATH',$temp.'/site/');define('APP_PATH',dirname(__DIR__).'/application/');
register_shutdown_function(static fn()=>audit_remove_temp($temp));
$app=new think\App($temp.'/app');
$app->config->set(['default'=>'file','channels'=>['file'=>['type'=>'file','path'=>$temp.'/logs','level'=>['notice']]]],'log');
$mysql=getenv('FRAMEWORK_AUDIT_MYSQL')==='1';
$connection=['type'=>'sqlite','database'=>':memory:','prefix'=>'save_audit_','fields_cache'=>false];
if($mysql){
 $host=getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1';$password=getenv('FRAMEWORK_AUDIT_PASSWORD')?:'';
 $server=new PDO('mysql:host='.$host.';charset=utf8mb4','root',$password,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
 $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_manga_save CHARACTER SET utf8mb4');$server=null;
 $connection=['type'=>'mysql','hostname'=>$host,'database'=>'maccms_audit_manga_save','username'=>'root','password'=>$password,'charset'=>'utf8mb4','prefix'=>'save_audit_','fields_cache'=>false];
}
$configuration=['default'=>'save','auto_timestamp'=>false,'connections'=>['save'=>$connection]];
$app->config->set($configuration,'database');$manager=new think\DbManager();$manager->setConfig($configuration);$app->instance('think\DbManager',$manager);
$cache=new MangaSaveCache();$cache->data['manga_save_type_list']=[1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>12,'type_name'=>'Manga']];$app->instance('cache',$cache);
$GLOBALS['config']=['app'=>['cache_flag'=>'manga_save','cache_core'=>0,'count_cache_sec'=>0], 'meilisearch'=>['enabled'=>0], 'upload'=>['protocol'=>'https']];
$sql=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');preg_match('/CREATE TABLE `mac_manga` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$match);
$fields=[];
foreach(explode("\n",$match[0])as $line){
 if(!preg_match('/^\s*`([a-z0-9_]+)`\s+(\w+)/',$line,$field))continue;
 if($field[1]==='manga_id'){$fields[]='manga_id INTEGER PRIMARY KEY AUTOINCREMENT';continue;}
 $type=preg_match('/int$/i',$field[2])?'INTEGER':(preg_match('/^(decimal|float|double)$/i',$field[2])?'REAL':'TEXT');
 $default=$type==='TEXT'?"''":'0';
 if(preg_match('/DEFAULT\s+(NULL|\x27[^\x27]*\x27|[0-9.]+)/i',$line,$value))$default=$value[1];
 $fields[]='`'.$field[1].'` '.$type.' DEFAULT '.$default;
}
Db::execute('DROP TABLE IF EXISTS save_audit_manga');
if($mysql){Db::execute(str_replace('`mac_manga`','`save_audit_manga`',$match[0]));}
else{Db::execute('CREATE TABLE save_audit_manga ('.implode(',',$fields).')');}
Db::execute('DROP TABLE IF EXISTS save_audit_type');
if($mysql){
 preg_match('/CREATE TABLE `mac_type` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$typeDdl);
 Db::execute(str_replace('`mac_type`','`save_audit_type`',$typeDdl[0]));
}else{Db::execute('CREATE TABLE save_audit_type (type_id INTEGER PRIMARY KEY,type_pid INTEGER,type_mid INTEGER)');}
register_shutdown_function(static function(){Db::execute('DROP TABLE IF EXISTS save_audit_manga');Db::execute('DROP TABLE IF EXISTS save_audit_type');});

function mangaSaveSeed():array {
 Db::execute('DELETE FROM save_audit_manga');
 Db::name('Manga')->insert(['manga_id'=>7,'manga_name'=>'before','type_id'=>1,'manga_en'=>'before',
  'manga_content'=>'Before description','manga_blurb'=>'Before summary','manga_pic'=>'https://cdn.example/old.jpg',
  'manga_chapter_from'=>'source','manga_chapter_url'=>'Chapter one$https://cdn.example/page.jpg',
  'manga_tag'=>'existing tag','manga_time'=>100]);
 return Db::name('Manga')->where('manga_id',7)->find();
}
function mangaSave(array $data):array {
 $result=(new app\common\model\Manga())->saveData($data);
 check($result['code']===1,'Ordinary model save succeeds');
 return Db::name('Manga')->where('manga_id',$data['manga_id']??7)->find();
}
function mangaSaveReject($data,string $label):void {
 $before=Db::name('Manga')->order('manga_id')->select()->toArray();
 $result=(new app\common\model\Manga())->saveData($data);
 check($result['code']===1001,'Invalid input is controlled: '.$label);
 check(Db::name('Manga')->order('manga_id')->select()->toArray()===$before,'Invalid input never writes: '.$label);
}
$base=['manga_id'=>7,'manga_name'=>'Ordinary manga','type_id'=>1];
$modes=$mysql?['','NO_AUTO_VALUE_ON_ZERO','STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO']:['sqlite'];
foreach($modes as $mode){
 if($mysql)Db::execute("SET SESSION sql_mode='".$mode."'");
 foreach(['omitted','',null,0,'0','000']as $newId){
  mangaSaveSeed();$data=['manga_name'=>'Ordinary manga','type_id'=>'1'];if($newId!=='omitted')$data['manga_id']=$newId;
  $result=(new app\common\model\Manga())->saveData($data);
  $row=Db::name('Manga')->where('manga_id','<>',7)->find();
  check($result['code']===1 && $row!==null && (int)$row['manga_id']>7,'Missing/blank/zero create ID uses actual auto increment: '.var_export($newId,true));
  check($row['manga_en']!=='' && $row['manga_blurb']==='' && (int)$row['manga_time']>100,'Minimum insert derives its optional defaults');
 }
 $before=mangaSaveSeed();$row=mangaSave($base);
 foreach(['manga_content','manga_blurb','manga_pic','manga_chapter_from','manga_chapter_url','manga_tag','manga_time']as $field){
  check($row[$field]===$before[$field],'Omitted edit field retains storage: '.$field);
 }
 foreach(['',null,'0','Ordinary description','中文简介']as $description){
  mangaSaveSeed();$row=mangaSave($base+['manga_content'=>$description]);
  check($row['manga_content']===($description??''),'String and nullable descriptions persist exactly');
  check($row['manga_blurb']===($description??''),'Provided description derives summary, including string zero');
  check($row['manga_pic']==='https://cdn.example/old.jpg','No image leaves the existing cover unchanged');
 }
 mangaSaveSeed();$row=mangaSave($base+['manga_content'=>['First','Second',0,null],'manga_title'=>['Title'],'manga_note'=>[]]);
 check($row['manga_content']==='First$$$Second$$$0$$$','Bounded flat legacy fragments retain separator semantics');
 check($row['manga_blurb']==='FirstSecond0','Summary derives from normalized fragments');
 mangaSaveSeed();$row=mangaSave($base+['manga_content'=>'<p>Ordinary description</p>','manga_title'=>'','manga_note'=>'']);
 check($row['manga_content']==='<p>Ordinary description</p>' && $row['manga_blurb']==='Ordinary description','Ordinary rich text needs no image or legacy schema fields');
 mangaSaveSeed();$row=mangaSave($base+['manga_pic'=>'','manga_content'=>'<p>Ordinary</p><img src="https://cdn.example/picture.jpg"><img src="https://cdn.example/two.jpg">']);
 check($row['manga_pic']==='https://cdn.example/picture.jpg','A real first image becomes the empty cover');
 check(str_contains($row['manga_content'],'mac://cdn.example/picture.jpg') && str_contains($row['manga_content'],'mac://cdn.example/two.jpg'),'Image protocol normalization still applies');
 mangaSaveSeed();$row=mangaSave($base+['manga_pic'=>'https://cdn.example/selected.jpg','manga_content'=>'<img src="https://cdn.example/picture.jpg">']);
 check($row['manga_pic']==='https://cdn.example/selected.jpg','An explicit cover takes precedence');
 mangaSaveSeed();$row=mangaSave($base+['uptime'=>'1','uptag'=>'0','manga_content'=>'Changed']);
 check((int)$row['manga_time']>100 && $row['manga_tag']==='existing tag','String checkbox values update time without rewriting tags');
 mangaSaveSeed();$row=mangaSave($base+['manga_content'=>str_repeat('a',1048576)]);
 check(strlen($row['manga_content'])===1048576,'Exactly one MiB of ordinary description is accepted');
 mangaSaveSeed();$row=mangaSave($base+['manga_content'=>array_fill(0,1024,'part')]);
 check(substr_count($row['manga_content'],'$$$')===1023,'Exactly 1024 legacy fragments are accepted');
 foreach([null,'text',new stdClass(),[],['type_id'=>1],['manga_name'=>'Name']]as $data)mangaSaveReject($data,'top level / required fields');
 foreach(['manga_content'=>[['nested']], 'manga_name'=>['Name'],'manga_en'=>new stdClass(),'manga_pic'=>['cover'],'manga_chapter_url'=>['url'],
  'uptime'=>'yes','uptag'=>[], 'manga_id'=>'7.5','type_id'=>'1.5']as $field=>$value){
  mangaSaveReject(array_replace($base,[$field=>$value]),'shape '.$field);
 }
 foreach(['-1','4294967296','1e2',true,1.5]as $id)mangaSaveReject(array_replace($base,['manga_id'=>$id]),'invalid ID');
 foreach([0,65536,'1e2',true]as $type)mangaSaveReject(array_replace($base,['type_id'=>$type]),'invalid type ID');
 mangaSaveReject(array_replace($base,array_fill_keys(array_map(static fn($i)=>'extra_'.$i,range(1,254)),'')),'field count');
 mangaSaveReject($base+[0=>'value'],'non-string field name');
 foreach(['manga_content','manga_title','manga_note']as $field){
  mangaSaveReject($base+[$field=>str_repeat('a',1048577)],'text bytes '.$field);
  mangaSaveReject($base+[$field=>array_fill(0,1025,'')],'fragment count '.$field);
  mangaSaveReject($base+[$field=>[str_repeat('a',1048575),'']],'joined delimiter bytes '.$field);
 }
 $savedCache=$cache->data['manga_save_type_list'];
 foreach([[2=>['type_pid'=>0]],'malformed',[1=>null],[1=>['type_pid'=>[]]],[1=>['type_pid'=>65536]]]as $cached){
  $cache->data['manga_save_type_list']=$cached;mangaSaveReject($base,'missing/malformed cached category');
 }
 $cache->data['manga_save_type_list']=$savedCache;
}
// Exercise the actual importer preparation before the existing real model, including rejection without writes.
foreach($modes as $importMode){
 if($importMode!=='sqlite'){Db::execute("SET SESSION sql_mode='".$importMode."'");}
 $importBase=['manga_id'=>'7','manga_name'=>'Imported ordinary row','type_id'=>'1'];
 foreach(['manga_id'=>['7ordinary','7.5',' 7',true,[],4294967296], 'type_id'=>['1ordinary','1.5',true,[],0],
     'uptime'=>['1ordinary',true], 'uptag'=>['0ordinary',[]]]as $importField=>$importValues){
  foreach($importValues as $importValue){
   mangaSaveSeed();$importBefore=Db::name('Manga')->order('manga_id')->select()->toArray();$importRejected=false;
   try{$importData=\app\common\util\BulkTableIo::prepareGenericForSave(array_replace($importBase,[$importField=>$importValue]),'manga');
       $importResult=(new \app\common\model\Manga())->saveData($importData);$importRejected=$importResult['code']!==1;}
   catch(\InvalidArgumentException $error){$importRejected=true;}
   check($importRejected && Db::name('Manga')->order('manga_id')->select()->toArray()===$importBefore,'Import preparation cannot hide invalid identity/flags from the actual model: '.$importField);
  }
 }
 foreach(['omitted','',null,'0','Ordinary imported body']as $importBody){
  $importBefore=mangaSaveSeed();$importData=$importBase;
  if($importBody!=='omitted'){$importData['manga_content']=$importBody;}
  $importData=\app\common\util\BulkTableIo::prepareGenericForSave($importData,'manga');
  $importResult=(new \app\common\model\Manga())->saveData($importData);$importRow=Db::name('Manga')->where('manga_id',7)->find();
  check($importResult['code']===1 && $importRow['manga_content']===($importBody==='omitted'?$importBefore['manga_content']:($importBody??'')),
      'Imported omitted/empty/null/zero/body values retain their actual storage meaning');
 }
 mangaSaveSeed();$importData=['manga_id'=>'000','manga_name'=>'Imported new row','type_id'=>'1'];
 $importResult=(new \app\common\model\Manga())->saveData(\app\common\util\BulkTableIo::prepareGenericForSave($importData,'manga'));
 check($importResult['code']===1 && Db::name('Manga')->where('manga_id','>',7)->count()===1,'Imported zero ID creates a new row rather than updating an existing one');
 mangaSaveSeed();$importBody=str_repeat('ordinary$$$',1100);
 $importResult=(new \app\common\model\Manga())->saveData(\app\common\util\BulkTableIo::prepareGenericForSave($importBase+['manga_content'=>$importBody],'manga'));
 check($importResult['code']===1 && Db::name('Manga')->where('manga_id',7)->value('manga_content')===$importBody,'A bounded manga description is not expanded into thousands of artificial form fragments');
}
echo 'framework_audit_manga_save: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL (three SQL modes)':'SQLite').PHP_EOL;
