<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function config($name,$default=null){return think\facade\Config::get($name,$default);}
function lang($name,...$args){return $name;}
function request(){return think\Container::getInstance()->make('request');}
class ArtSaveCache implements Psr\SimpleCache\CacheInterface {
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
$temp=audit_temp_dir('art-save-probe');mkdir($temp.'/app');mkdir($temp.'/site');
define('ROOT_PATH',$temp.'/site/');define('APP_PATH',dirname(__DIR__).'/application/');
register_shutdown_function(static fn()=>audit_remove_temp($temp));
$app=new think\App($temp.'/app');
$app->config->set(['default'=>'file','channels'=>['file'=>['type'=>'file','path'=>$temp.'/logs','level'=>['notice']]]],'log');
$mysql=getenv('FRAMEWORK_AUDIT_MYSQL')==='1';
$connection=['type'=>'sqlite','database'=>':memory:','prefix'=>'save_audit_','fields_cache'=>false];
if($mysql){
 $host=getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1';$password=getenv('FRAMEWORK_AUDIT_PASSWORD')?:'';
 $server=new PDO('mysql:host='.$host.';charset=utf8mb4','root',$password,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
 $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_art_save CHARACTER SET utf8mb4');$server=null;
 $connection=['type'=>'mysql','hostname'=>$host,'database'=>'maccms_audit_art_save','username'=>'root','password'=>$password,'charset'=>'utf8mb4','prefix'=>'save_audit_','fields_cache'=>false];
}
$configuration=['default'=>'save','auto_timestamp'=>false,'connections'=>['save'=>$connection]];
$app->config->set($configuration,'database');$manager=new think\DbManager();$manager->setConfig($configuration);$app->instance('think\DbManager',$manager);
$cache=new ArtSaveCache();$cache->data['art_save_type_list']=[1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>2,'type_name'=>'Art']];$app->instance('cache',$cache);
$GLOBALS['config']=['app'=>['cache_flag'=>'art_save','cache_core'=>0,'count_cache_sec'=>0], 'meilisearch'=>['enabled'=>0], 'upload'=>['protocol'=>'https']];
$sql=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');preg_match('/CREATE TABLE `mac_art` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$match);
$fields=[];
foreach(explode("\n",$match[0])as $line){
 if(!preg_match('/^\s*`([a-z0-9_]+)`\s+(\w+)/',$line,$field))continue;
 if($field[1]==='art_id'){$fields[]='art_id INTEGER PRIMARY KEY AUTOINCREMENT';continue;}
 $type=preg_match('/int$/i',$field[2])?'INTEGER':(preg_match('/^(decimal|float|double)$/i',$field[2])?'REAL':'TEXT');
 $default=$type==='TEXT'?"''":'0';
 if(preg_match('/DEFAULT\s+(NULL|\x27[^\x27]*\x27|[0-9.]+)/i',$line,$value))$default=$value[1];
 $fields[]='`'.$field[1].'` '.$type.' DEFAULT '.$default;
}
Db::execute('DROP TABLE IF EXISTS save_audit_art');
if($mysql){Db::execute(str_replace('`mac_art`','`save_audit_art`',$match[0]));}
else{Db::execute('CREATE TABLE save_audit_art ('.implode(',',$fields).')');}
Db::execute('DROP TABLE IF EXISTS save_audit_type');
if($mysql){
 preg_match('/CREATE TABLE `mac_type` \([\s\S]*?\) ENGINE[^;]*;/',$sql,$typeDdl);
 Db::execute(str_replace('`mac_type`','`save_audit_type`',$typeDdl[0]));
}else{Db::execute('CREATE TABLE save_audit_type (type_id INTEGER PRIMARY KEY,type_pid INTEGER,type_mid INTEGER)');}
register_shutdown_function(static function(){Db::execute('DROP TABLE IF EXISTS save_audit_art');Db::execute('DROP TABLE IF EXISTS save_audit_type');});

function artSaveSeed():array {
 Db::execute('DELETE FROM save_audit_art');
 Db::name('Art')->insert(['art_id'=>7,'art_name'=>'before','type_id'=>1,'art_en'=>'before',
  'art_content'=>'Before description','art_blurb'=>'Before summary','art_pic'=>'https://cdn.example/old.jpg',
  'art_title'=>'Original title','art_note'=>'Original note',
  'art_tag'=>'existing tag','art_time'=>100]);
 return Db::name('Art')->where('art_id',7)->find();
}
function artSave(array $data):array {
 $result=(new app\common\model\Art())->saveData($data);
 check($result['code']===1,'Ordinary model save succeeds');
 return Db::name('Art')->where('art_id',$data['art_id']??7)->find();
}
function artSaveReject($data,string $label):void {
 $before=Db::name('Art')->order('art_id')->select()->toArray();
 $result=(new app\common\model\Art())->saveData($data);
 check($result['code']===1001,'Invalid input is controlled: '.$label);
 check(Db::name('Art')->order('art_id')->select()->toArray()===$before,'Invalid input never writes: '.$label);
}
$base=['art_id'=>7,'art_name'=>'Ordinary art','type_id'=>1];
$modes=$mysql?['','NO_AUTO_VALUE_ON_ZERO','STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO']:['sqlite'];
foreach($modes as $mode){
 if($mysql)Db::execute("SET SESSION sql_mode='".$mode."'");
 foreach(['omitted','',null,0,'0','000']as $newId){
  artSaveSeed();$data=['art_name'=>'Ordinary art','type_id'=>'1'];if($newId!=='omitted')$data['art_id']=$newId;
  $result=(new app\common\model\Art())->saveData($data);
  $row=Db::name('Art')->where('art_id','<>',7)->find();
  check($result['code']===1 && $row!==null && (int)$row['art_id']>7,'Missing/blank/zero create ID uses actual auto increment: '.var_export($newId,true));
  check($row['art_title']==='' && $row['art_note']==='' && $row['art_content']==='', 'Required MEDIUMTEXT columns get explicit defaults on insert');
  check($row['art_en']!=='' && $row['art_blurb']==='' && (int)$row['art_time']>100,'Minimum insert derives its optional defaults');
 }
 $before=artSaveSeed();$row=artSave($base);
 foreach(['art_content','art_blurb','art_pic','art_title','art_note','art_tag','art_time']as $field){
  check($row[$field]===$before[$field],'Omitted edit field retains storage: '.$field);
 }
 foreach(['',null,'0','Ordinary description','中文简介']as $description){
  artSaveSeed();$row=artSave($base+['art_content'=>$description]);
  check($row['art_content']===($description??''),'String and nullable descriptions persist exactly');
  check($row['art_blurb']===($description??''),'Provided description derives summary, including string zero');
  check($row['art_pic']==='https://cdn.example/old.jpg','No image leaves the existing cover unchanged');
 }
 artSaveSeed();$row=artSave($base+['art_content'=>['First','Second',0,null],'art_title'=>['Title'],'art_note'=>[]]);
 check($row['art_content']==='First$$$Second$$$0$$$','Bounded flat legacy fragments retain separator semantics');
 check($row['art_blurb']==='FirstSecond0','Summary derives from normalized fragments');
 artSaveSeed();$row=artSave($base+['art_content'=>'<p>Ordinary description</p>','art_title'=>'','art_note'=>'']);
 check($row['art_content']==='<p>Ordinary description</p>' && $row['art_blurb']==='Ordinary description','Ordinary rich text needs no image or legacy schema fields');
 artSaveSeed();$row=artSave($base+['art_pic'=>'','art_content'=>'<p>Ordinary</p><img src="https://cdn.example/picture.jpg"><img src="https://cdn.example/two.jpg">']);
 check($row['art_pic']==='https://cdn.example/picture.jpg','A real first image becomes the empty cover');
 check(str_contains($row['art_content'],'mac://cdn.example/picture.jpg') && str_contains($row['art_content'],'mac://cdn.example/two.jpg'),'Image protocol normalization still applies');
 artSaveSeed();$row=artSave($base+['art_pic'=>'https://cdn.example/selected.jpg','art_content'=>'<img src="https://cdn.example/picture.jpg">']);
 check($row['art_pic']==='https://cdn.example/selected.jpg','An explicit cover takes precedence');
 artSaveSeed();$row=artSave($base+['uptime'=>'1','uptag'=>'0','art_content'=>'Changed']);
 check((int)$row['art_time']>100 && $row['art_tag']==='existing tag','String checkbox values update time without rewriting tags');
 artSaveSeed();$row=artSave($base+['art_content'=>str_repeat('a',8388608)]);
 check(strlen($row['art_content'])===8388608,'Exactly eight MiB of ordinary body is accepted');
 artSaveSeed();$row=artSave($base+['art_content'=>array_fill(0,1024,'part')]);
 check(substr_count($row['art_content'],'$$$')===1023,'Exactly 1024 legacy fragments are accepted');
 foreach([null,'text',new stdClass(),[],['type_id'=>1],['art_name'=>'Name']]as $data)artSaveReject($data,'top level / required fields');
 foreach(['art_content'=>[['nested']], 'art_name'=>['Name'],'art_en'=>new stdClass(),'art_pic'=>['cover'],'art_status'=>['1'],
  'uptime'=>'yes','uptag'=>[], 'art_id'=>'7.5','type_id'=>'1.5']as $field=>$value){
  artSaveReject(array_replace($base,[$field=>$value]),'shape '.$field);
 }
 foreach(['-1','4294967296','1e2',true,1.5]as $id)artSaveReject(array_replace($base,['art_id'=>$id]),'invalid ID');
 foreach([0,65536,'1e2',true]as $type)artSaveReject(array_replace($base,['type_id'=>$type]),'invalid type ID');
 artSaveReject(array_replace($base,array_fill_keys(array_map(static fn($i)=>'extra_'.$i,range(1,254)),'')),'field count');
 artSaveReject($base+[0=>'value'],'non-string field name');
 foreach(['art_content','art_title','art_note']as $field){
  $limit=$field==='art_content'?8388608:1048576;
  artSaveReject($base+[$field=>str_repeat('a',$limit+1)],'text bytes '.$field);
  artSaveReject($base+[$field=>array_fill(0,1025,'')],'fragment count '.$field);
  artSaveReject($base+[$field=>[str_repeat('a',$limit-1),'']],'joined delimiter bytes '.$field);
 }
 foreach(['art_content','art_title','art_note']as $field){
  artSaveReject($base+[$field=>str_repeat('$$$',1024)],'prejoined page count '.$field);
  artSaveReject($base+[$field=>[str_repeat('$$$',1023),'']],'embedded fragment separators '.$field);
  artSaveReject($base+[$field=>[str_repeat('$$$',1022).'$$','$']],'separator run across joined fragments '.$field);
 }
 artSaveSeed();$row=artSave($base+['art_content'=>'First$$$Second$$$','art_title'=>'One$$$Two','art_note'=>null]);
 $pages=app\common\util\ContentResource::artPages($row);
 check(array_keys($pages)===[1,2,3] && $pages[1]['title']==='One' && $pages[2]['title']==='Two' && $pages[3]['content']==='', 'Actual reader retains prejoined page coordinates and empty trailing page');
 artSaveSeed();$row=artSave($base+['art_title'=>['New title'],'art_note'=>['New note']]);
 check($row['art_content']==='Before description' && $row['art_title']==='New title' && $row['art_note']==='New note','Metadata-only edit retains its body');
 artSaveSeed();$row=artSave($base+['art_content'=>['First','Second'],'art_title'=>['One','Two'],'art_note'=>['Note one','Note two']]);
 $pages=app\common\util\ContentResource::artPages($row);
 check(count($pages)===2 && $pages[2]['content']==='Second' && $pages[2]['title']==='Two' && $pages[2]['note']==='Note two','Actual form arrays retain their paired page metadata');
 artSaveReject($base+['art_content'=>str_repeat('$<plain></plain>$<plain></plain>$',1024)],'page count after ordinary tag removal');
 artSaveSeed();$row=artSave($base+['art_content'=>str_repeat('b',8388608),'art_title'=>str_repeat('t',1048576),'art_note'=>str_repeat('n',1048576)]);
 check(strlen($row['art_content'])===8388608 && strlen($row['art_title'])===1048576 && strlen($row['art_note'])===1048576,'Combined body/title/note byte limits persist without clipping');
 $savedCache=$cache->data['art_save_type_list'];
 foreach([[2=>['type_pid'=>0]],'malformed',[1=>null],[1=>['type_pid'=>[]]],[1=>['type_pid'=>65536]]]as $cached){
  $cache->data['art_save_type_list']=$cached;artSaveReject($base,'missing/malformed cached category');
 }
 $cache->data['art_save_type_list']=$savedCache;
}
// Exercise the actual importer preparation before the existing real model, including rejection without writes.
foreach($modes as $importMode){
 if($importMode!=='sqlite'){Db::execute("SET SESSION sql_mode='".$importMode."'");}
 $importBase=['art_id'=>'7','art_name'=>'Imported ordinary row','type_id'=>'1'];
 foreach(['art_id'=>['7ordinary','7.5',' 7',true,[],4294967296], 'type_id'=>['1ordinary','1.5',true,[],0],
     'uptime'=>['1ordinary',true], 'uptag'=>['0ordinary',[]]]as $importField=>$importValues){
  foreach($importValues as $importValue){
   artSaveSeed();$importBefore=Db::name('Art')->order('art_id')->select()->toArray();$importRejected=false;
   try{$importData=\app\common\util\BulkTableIo::prepareGenericForSave(array_replace($importBase,[$importField=>$importValue]),'art');
       $importResult=(new \app\common\model\Art())->saveData($importData);$importRejected=$importResult['code']!==1;}
   catch(\InvalidArgumentException $error){$importRejected=true;}
   check($importRejected && Db::name('Art')->order('art_id')->select()->toArray()===$importBefore,'Import preparation cannot hide invalid identity/flags from the actual model: '.$importField);
  }
 }
 foreach(['omitted','',null,'0','Ordinary imported body']as $importBody){
  $importBefore=artSaveSeed();$importData=$importBase;
  if($importBody!=='omitted'){$importData['art_content']=$importBody;}
  $importData=\app\common\util\BulkTableIo::prepareGenericForSave($importData,'art');
  $importResult=(new \app\common\model\Art())->saveData($importData);$importRow=Db::name('Art')->where('art_id',7)->find();
  check($importResult['code']===1 && $importRow['art_content']===($importBody==='omitted'?$importBefore['art_content']:($importBody??'')),
      'Imported omitted/empty/null/zero/body values retain their actual storage meaning');
 }
 artSaveSeed();$importData=['art_id'=>'000','art_name'=>'Imported new row','type_id'=>'1'];
 $importResult=(new \app\common\model\Art())->saveData(\app\common\util\BulkTableIo::prepareGenericForSave($importData,'art'));
 check($importResult['code']===1 && Db::name('Art')->where('art_id','>',7)->count()===1,'Imported zero ID creates a new row rather than updating an existing one');

}
echo 'Art save fixture peak: '.round(memory_get_peak_usage(true)/1048576,2).' MiB; limit '.ini_get('memory_limit').PHP_EOL;
echo 'framework_audit_art_save: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL (three SQL modes)':'SQLite').PHP_EOL;
