<?php
declare(strict_types=1);
require __DIR__.'/fixtures/vod_save_db.php';
use think\facade\Db;

function repeatRows():array {
 $rows=Db::query('SELECT id1,name1 FROM vod_save_audit_vod_repeat ORDER BY name1,id1');
 $out=[];foreach($rows as $row)$out[$row['name1']][]=(int)$row['id1'];return $out;
}
function repeatSeed():void {
 Db::execute('DELETE FROM vod_save_audit_vod');
 foreach([7=>'Before',8=>'Before',9=>'Before',10=>'Other',11=>'Other',12=>'Solo']as $id=>$name){
  Db::name('Vod')->insert(['vod_id'=>$id,'vod_name'=>$name,'type_id'=>1,'vod_en'=>'video-'.$id,
   'vod_content'=>'Ordinary description','vod_play_url'=>'','vod_down_url'=>'','vod_plot_name'=>'','vod_plot_detail'=>'']);
 }
 (new app\common\model\Vod())->createRepeatCache();
 check(repeatRows()===['Before'=>[7],'Other'=>[10]],'Fixture starts with a complete duplicate catalog');
}
function repeatSave(int $id,string $name,array $fields=[]):void {
 $result=(new app\common\model\Vod())->saveData(['vod_id'=>$id,'vod_name'=>$name,'type_id'=>1]+$fields);
 check($result['code']===1,'Ordinary video edit succeeds');
}
foreach(['','NO_AUTO_VALUE_ON_ZERO','STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO']as $mode){
 Db::execute("SET SESSION sql_mode='".$mode."'");
 repeatSeed();repeatSave(7,'Renamed');
 check(repeatRows()===['Before'=>[8],'Other'=>[10]],'Rename refreshes the previous group using its new minimum ID');
 check(Db::name('Vod')->where('vod_id',7)->value('vod_name')==='Renamed','Renamed resource actually persists');
 repeatSave(8,'Another name');
 check(repeatRows()===['Other'=>[10]],'A group with only one remaining item leaves the duplicate catalog');
 repeatSeed();repeatSave(7,'Other');
 check(repeatRows()===['Before'=>[8],'Other'=>[7]],'Moving between duplicate groups refreshes both representatives');
 repeatSeed();
 for($i=0;$i<4;$i++){
  repeatSave(12,'Solo',['vod_remarks'=>'Ordinary update '.$i]);
  check(repeatRows()===['Before'=>[7],'Other'=>[10]],'Unrelated saves do not append existing duplicate groups');
 }
 for($i=0;$i<4;$i++){
  (new app\common\model\Vod())->cacheRepeatWithName('Before');
  check(repeatRows()===['Before'=>[7],'Other'=>[10]],'Repeated single-name refresh is idempotent in serial use');
 }
 Db::execute("INSERT INTO vod_save_audit_vod_repeat (id1,name1) VALUES (7,'Before')");
 (new app\common\model\Vod())->cacheRepeatWithName('Before');
 check(repeatRows()===['Before'=>[7],'Other'=>[10]],'Refreshing a polluted target group removes its duplicate rows');
 repeatSeed();repeatSave(7,'Before',['vod_recycle_time'=>100]);
 check(repeatRows()===['Before'=>[8],'Other'=>[10]],'Recycling the representative selects a current member');
 repeatSave(8,'Before',['vod_recycle_time'=>100]);
 check(repeatRows()===['Other'=>[10]],'Recycled videos do not keep an otherwise unique group in the catalog');
 repeatSeed();Db::execute('DROP TABLE vod_save_audit_vod_repeat');
 $missingRejected=false;try{(new app\common\model\Vod())->cacheRepeatWithName('Solo');}catch(RuntimeException $error){$missingRejected=true;}
 check($missingRejected,'A normal refresh never creates a missing catalog');
 check(Db::query("SHOW TABLES LIKE 'vod_save_audit_vod_repeat'")===[],'Missing catalog remains absent until explicit rebuild');
 (new app\common\model\Vod())->createRepeatCache();
 check(repeatRows()===['Before'=>[7],'Other'=>[10]],'Explicit rebuild initializes the complete catalog once');
 (new app\common\model\Vod())->cacheRepeatWithName('Solo');
 check(repeatRows()===['Before'=>[7],'Other'=>[10]],'The next refresh does not repeat the full-table append');
 repeatSeed();Db::name('Vod')->whereIn('vod_id',[7,8,9])->update(['vod_name'=>"Studio's Film"]);
 (new app\common\model\Vod())->createRepeatCache();
 (new app\common\model\Vod())->cacheRepeatWithName("Studio's Film");
 check(repeatRows()===['Other'=>[10],"Studio's Film"=>[7]],'Ordinary apostrophes stay bound as name data');
 repeatSeed();$before=repeatRows();Db::startTrans();
 try{
  repeatSave(7,'Renamed');check(Db::connect()->getPdo()->inTransaction(),'Normal existing-table refresh preserves caller transaction');
  check(repeatRows()===$before,'Caller-owned save defers catalog DML until an independent rebuild');
 }finally{Db::rollback();}
 check(repeatRows()===$before && Db::name('Vod')->where('vod_id',7)->value('vod_name')==='Before','Caller rollback restores resource and preserves the deferred catalog');
}
echo 'framework_audit_vod_repeat: '.$checks.' checks passed on PHP '.PHP_VERSION.' / installation MySQL (three SQL modes)'.PHP_EOL;
