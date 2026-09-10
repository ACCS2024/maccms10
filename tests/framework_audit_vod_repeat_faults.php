<?php
declare(strict_types=1);
require __DIR__.'/fixtures/vod_save_db.php';
use think\facade\Db;
use app\common\util\VodRepeatCatalog as Catalog;

$observer=new PDO($dsn.';dbname='.$database,'root',$password,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
function catalogSeed():void {
 Db::execute('DROP TABLE IF EXISTS vod_save_audit_vod_repeat');
 Db::execute('DELETE FROM vod_save_audit_vod');
 foreach([7=>'Before',8=>'Before',10=>'Other',11=>'Other',12=>'Caller']as $id=>$name){
  Db::name('Vod')->insert(['vod_id'=>$id,'vod_name'=>$name,'type_id'=>1,'vod_en'=>'video-'.$id,'vod_remarks'=>'original',
   'vod_content'=>'Ordinary description','vod_play_url'=>'','vod_down_url'=>'','vod_plot_name'=>'','vod_plot_detail'=>'']);
 }
 Catalog::rebuild();
}
function catalogRows():array {return Db::query('SELECT id1,name1 FROM vod_save_audit_vod_repeat ORDER BY name1,id1');}
function catalogEdit(string $name='Changed',int $id=7):array {
 return (new app\common\model\Vod())->saveData(['vod_id'=>$id,'vod_name'=>$name,'type_id'=>1]);
}
function catalogPending(array $result):void {
 check($result['code']===1 && $result['info']['repeat_index_pending']===true,'Acknowledged save reports pending directory maintenance');
 check(str_contains($result['msg'],'save_ok') && str_contains($result['msg'],'admin/vod/repeat_refresh_pending'),'Admin receives both save acknowledgement and maintenance message');
}
function catalogRejected(callable $action,string $message):void {
 $error=null;try{$action();}catch(Throwable $caught){$error=$caught;}
 check($error!==null,$message);
}
function catalogSchemaPreserved(PDO $observer,string $database,string $trigger):void {
 check($observer->query("SHOW COLUMNS FROM vod_save_audit_vod_repeat LIKE 'audit_marker'")->fetchAll()!==[],'Original extra column survives database rejection');
 $statement=$observer->prepare('SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=? AND TRIGGER_NAME=?');
 $statement->execute([$database,$trigger]);check((int)$statement->fetchColumn()===1,'Original rejecting trigger survives database rejection');
}
// Exercise the real data action and ORM; only the page renderer/auth constructor is outside this fixture.
class CatalogControllerFixture extends app\admin\controller\Vod {
 public function __construct() {$this->_pagesize=20;}
 protected function error($msg='',$url=null,$data='',$wait=3) {return ['code'=>0,'msg'=>$msg];}
}
foreach(['','NO_AUTO_VALUE_ON_ZERO','STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO']as $mode){
 Db::execute("SET SESSION sql_mode='".$mode."'");
 foreach(['orm','pdo']as $owner){
  catalogSeed();Db::execute('DROP TABLE vod_save_audit_vod_repeat');
  $pdo=Db::connect()->getPdo();
  if($owner==='orm'){Db::startTrans();}else{$pdo->beginTransaction();}
  try{
   Db::name('Vod')->where('vod_id',12)->update(['vod_remarks'=>'caller-sentinel']);
   catalogPending(catalogEdit());
   check($pdo===Db::connect()->getPdo() && $pdo->inTransaction(),'Missing directory never commits or replaces original caller PDO');
   check(Db::query("SHOW TABLES LIKE 'vod_save_audit_vod_repeat'")===[],'Save performs no missing-table DDL');
   check($observer->query('SELECT vod_name FROM vod_save_audit_vod WHERE vod_id=7')->fetchColumn()==='Before','Independent observer cannot see the uncommitted video edit');
   catalogRejected(static fn()=>Catalog::rebuild(),'Explicit rebuild also rejects a caller-owned transaction');
   check($pdo->inTransaction(),'Rejected rebuild leaves caller transaction active');
  }finally{if($owner==='orm'){Db::rollback();}else{$pdo->rollBack();}}
  check($observer->query('SELECT vod_name FROM vod_save_audit_vod WHERE vod_id=7')->fetchColumn()==='Before','Independent observer confirms actual video rollback');
  check($observer->query('SELECT vod_remarks FROM vod_save_audit_vod WHERE vod_id=12')->fetchColumn()==='original','Independent observer confirms caller sentinel rollback');
  check(!$cache->has(Catalog::CACHE_KEY),'Deferred maintenance invalidates the full-build stamp');
 }
 catalogSeed();$before=catalogRows();Db::startTrans();$pdo=Db::connect()->getPdo();
 try{
  catalogRejected(static fn()=>Catalog::rebuild(),'Existing-table rebuild rejects a caller before TRUNCATE');
  check(catalogRows()===$before && $pdo->inTransaction(),'Rejected existing-table rebuild preserves rows and caller ownership');
 }finally{Db::rollback();}
 // Real ORM/PDO state disagreement: maintenance may not repair a caller's nesting counter.
 Db::startTrans();$pdo->commit();
 try{
  catalogRejected(static fn()=>Catalog::rebuild(),'Stale ORM nesting rejects maintenance even when PDO is inactive');
  check(catalogRows()===$before,'Stale ORM depth causes no derived mutation');
  $depth=(new ReflectionProperty(think\db\PDOConnection::class,'transTimes'))->getValue(Db::connect());
  check($depth===1,'Maintenance does not alter caller ORM nesting');
 }finally{Db::rollback();}

 catalogSeed();$before=catalogRows();
 Db::execute("ALTER TABLE vod_save_audit_vod_repeat ADD COLUMN audit_marker VARCHAR(20) DEFAULT 'kept'");
 Db::execute("CREATE TRIGGER vod_save_audit_repeat_deny BEFORE DELETE ON vod_save_audit_vod_repeat FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture delete denied'");
 catalogPending(catalogEdit());
 catalogSchemaPreserved($observer,$database,'vod_save_audit_repeat_deny');
 check(catalogRows()===$before,'Rejected DELETE neither drops nor clears original directory');
 check($observer->query('SELECT vod_name FROM vod_save_audit_vod WHERE vod_id=7')->fetchColumn()==='Changed','Primary autocommit edit persists despite directory rejection');
 check(!$cache->has(Catalog::CACHE_KEY),'Rejected directory update cannot retain a valid full-build stamp');

 catalogSeed();
 Db::name('Vod')->insert(['vod_id'=>9,'vod_name'=>'Before','type_id'=>1,'vod_en'=>'video-9',
  'vod_content'=>'Ordinary description','vod_play_url'=>'','vod_down_url'=>'','vod_plot_name'=>'','vod_plot_detail'=>'']);
 Db::execute("ALTER TABLE vod_save_audit_vod_repeat ADD COLUMN audit_marker VARCHAR(20) DEFAULT 'kept'");
 Db::execute("CREATE TRIGGER vod_save_audit_repeat_deny BEFORE INSERT ON vod_save_audit_vod_repeat FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture insert denied'");
 catalogPending(catalogEdit('Other'));
 catalogSchemaPreserved($observer,$database,'vod_save_audit_repeat_deny');
 check(count(catalogRows())===1 && catalogRows()[0]['name1']==='Other','First refresh failure stops before modifying the next group');
 check(!$cache->has(Catalog::CACHE_KEY),'Partial directory refresh remains explicitly invalid');
 $cache->set(Catalog::CACHE_KEY,123);
 catalogRejected(static fn()=>Catalog::rebuild(),'Explicit rebuild propagates fill rejection without destructive fallback');
 catalogSchemaPreserved($observer,$database,'vod_save_audit_repeat_deny');
 check(!$cache->has(Catalog::CACHE_KEY),'Failed explicit rebuild clears a previous full-build stamp');
 foreach([['repeat'=>1,'cache'=>1],['repeat'=>1]]as $params){
  $app->instance('request',(new think\Request())->withGet($params)->withServer(['REQUEST_METHOD'=>'GET']));
  $result=(new CatalogControllerFixture())->data();
  check($result===['code'=>0,'msg'=>'admin/vod/repeat_refresh_failed'],'Real controller returns a controlled rebuild failure before listing');
 }

 catalogSeed();$cache->set(Catalog::CACHE_KEY,123);Catalog::refresh('Before');
 check($cache->get(Catalog::CACHE_KEY)===123,'Partial refresh never claims the full catalog was rebuilt');
 $result=catalogEdit('Before');
 check($result['code']===1 && $result['info']['repeat_index_pending']===false,'Healthy save acknowledges ready directory');
 $result=catalogEdit('Before');check($result['code']===1,'Legitimate unchanged update is not confused with missing record');
 $before=catalogRows();$result=catalogEdit('Absent',999);
 check($result['code']===1002 && catalogRows()===$before,'Missing video is rejected without directory changes');

 // A similarly named view must never redirect DELETE into another relation.
 Db::execute('DROP TABLE vod_save_audit_vod_repeat');
 Db::execute('CREATE VIEW vod_save_audit_vod_repeat AS SELECT vod_id AS id1,vod_name AS name1 FROM vod_save_audit_vod');
 try{
  catalogPending(catalogEdit());
  check((int)$observer->query('SELECT COUNT(*) FROM vod_save_audit_vod')->fetchColumn()===5,'View rejection preserves all source records');
  catalogRejected(static fn()=>Catalog::rebuild(),'Explicit rebuild refuses an existing view');
 }finally{Db::execute('DROP VIEW vod_save_audit_vod_repeat');}
}

// Use the active connection's actual prefix, even when the legacy mysql configuration differs.
catalogSeed();
Db::execute('CREATE TABLE vod_save_audit_decoy_vod_repeat (id1 INT,name1 VARCHAR(255))');
Db::execute("INSERT INTO vod_save_audit_decoy_vod_repeat VALUES (999,'Decoy')");
$aliasConfig=$configuration;$aliasConfig['default']='catalog_alias';
$aliasConfig['connections']['catalog_alias']=$connection;
$aliasConfig['connections']['mysql']['prefix']='vod_save_audit_decoy_';
$aliasManager=new think\DbManager();$aliasManager->setConfig($aliasConfig);
$app->config->set($aliasConfig,'database');$app->instance('think\DbManager',$aliasManager);
try{
 $result=catalogEdit();check($result['code']===1 && $result['info']['repeat_index_pending']===false,'Non-mysql default alias refreshes its own real directory');
 check(count(catalogRows())===1 && catalogRows()[0]['name1']==='Other','Active alias uses its actual video and directory tables');
 Catalog::rebuild();
 check($observer->query('SELECT name1 FROM vod_save_audit_decoy_vod_repeat')->fetchAll(PDO::FETCH_COLUMN)===['Decoy'],'Legacy mysql-prefix decoy remains untouched during save and rebuild');
}finally{
 $app->instance('think\DbManager',$manager);$app->config->set($configuration,'database');
 $observer->exec('DROP TABLE vod_save_audit_decoy_vod_repeat');
}

class UnavailableCatalogCache extends VodSaveCache {
 public function delete(string $key):bool {if($key===Catalog::CACHE_KEY){throw new RuntimeException('fixture cache unavailable');}return parent::delete($key);}
}
catalogSeed();Db::execute('DROP TABLE vod_save_audit_vod_repeat');
$brokenCache=new UnavailableCatalogCache();$brokenCache->data=$cache->data;$app->instance('cache',$brokenCache);
try{
 catalogPending(catalogEdit());
 check($observer->query('SELECT vod_name FROM vod_save_audit_vod WHERE vod_id=7')->fetchColumn()==='Changed','Cache invalidation failure does not undo or misreport primary save');
}finally{$app->instance('cache',$cache);}
echo 'framework_audit_vod_repeat_faults: '.$checks.' checks passed on PHP '.PHP_VERSION.' / installation MySQL (three SQL modes)'.PHP_EOL;
