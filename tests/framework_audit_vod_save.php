<?php
declare(strict_types=1);
require __DIR__.'/fixtures/vod_save_db.php';
use think\facade\Db;

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
// Exercise the actual importer preparation before the existing real model, including rejection without writes.
foreach(['','NO_AUTO_VALUE_ON_ZERO','STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO'] as $importMode){
 if($importMode!=='sqlite'){Db::execute("SET SESSION sql_mode='".$importMode."'");}
 $importBase=['vod_id'=>'7','vod_name'=>'Imported ordinary row','type_id'=>'1'];
 foreach(['vod_id'=>['7ordinary','7.5',' 7',true,[],4294967296], 'type_id'=>['1ordinary','1.5',true,[],0],
     'uptime'=>['1ordinary',true], 'uptag'=>['0ordinary',[]]]as $importField=>$importValues){
  foreach($importValues as $importValue){
   vodSaveSeed();$importBefore=Db::name('Vod')->order('vod_id')->select()->toArray();$importRejected=false;
   try{$importData=\app\common\util\BulkTableIo::prepareGenericForSave(array_replace($importBase,[$importField=>$importValue]),'vod');
       $importResult=(new \app\common\model\Vod())->saveData($importData);$importRejected=$importResult['code']!==1;}
   catch(\InvalidArgumentException $error){$importRejected=true;}
   check($importRejected && Db::name('Vod')->order('vod_id')->select()->toArray()===$importBefore,'Import preparation cannot hide invalid identity/flags from the actual model: '.$importField);
  }
 }
 foreach(['omitted','',null,'0','Ordinary imported body']as $importBody){
  $importBefore=vodSaveSeed();$importData=$importBase;
  if($importBody!=='omitted'){$importData['vod_content']=$importBody;}
  $importData=\app\common\util\BulkTableIo::prepareGenericForSave($importData,'vod');
  $importResult=(new \app\common\model\Vod())->saveData($importData);$importRow=Db::name('Vod')->where('vod_id',7)->find();
  check($importResult['code']===1 && $importRow['vod_content']===($importBody==='omitted'?$importBefore['vod_content']:($importBody??'')),
      'Imported omitted/empty/null/zero/body values retain their actual storage meaning');
 }
 vodSaveSeed();$importData=['vod_id'=>'000','vod_name'=>'Imported new row','type_id'=>'1'];
 $importResult=(new \app\common\model\Vod())->saveData(\app\common\util\BulkTableIo::prepareGenericForSave($importData,'vod'));
 check($importResult['code']===1 && Db::name('Vod')->where('vod_id','>',7)->count()===1,'Imported zero ID creates a new row rather than updating an existing one');
 foreach(['play','down']as $importGroup){
  vodSaveSeed();$importData=$importBase+['vod_'.$importGroup.'_from'=>''];
  $importResult=(new \app\common\model\Vod())->saveData(\app\common\util\BulkTableIo::prepareGenericForSave($importData,'vod'));
  $importRow=Db::name('Vod')->where('vod_id',7)->find();
  check($importResult['code']===1 && $importRow['vod_'.$importGroup.'_from']==='' && $importRow['vod_'.$importGroup.'_url']==='',
      'Explicit imported empty source clears its group instead of preserving old episodes');
 }
}
echo 'Vod save fixture peak: '.round(memory_get_peak_usage(true)/1048576,2).' MiB; limit '.ini_get('memory_limit').PHP_EOL;
echo 'framework_audit_vod_save: '.$checks.' checks passed on PHP '.PHP_VERSION.' / installation MySQL (three SQL modes)'.PHP_EOL;
