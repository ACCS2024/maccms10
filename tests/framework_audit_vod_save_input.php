<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\VodSaveInput;

$base=['vod_id'=>7,'vod_name'=>'Ordinary video','type_id'=>1];
$data=VodSaveInput::normalize($base);
check(VodSaveInput::normalize($base+['vod_pic_original'=>'form-value','vod_pic_thumb_original'=>'form-thumb'])===$data,
    'Ordinary edit/import must not rewrite original cover evidence');
foreach(['vod_play_from','vod_down_from','vod_content']as $field)check($data!==null && !array_key_exists($field,$data),'Omitted patch column stays omitted: '.$field);
foreach(['omitted','',null,0,'0','000']as $id){
 $input=['vod_name'=>'New video','type_id'=>1];if($id!=='omitted')$input['vod_id']=$id;
 $data=VodSaveInput::normalize($input);
 check($data!==null && !isset($data['vod_id']) && $data['vod_content']==='' && $data['vod_play_url']==='' && $data['vod_down_url']==='','Create gets explicit body/group defaults and no zero ID');
}
foreach([null,'text',new stdClass(),[],['vod_id'=>'7.2','type_id'=>1],['vod_id'=>true,'type_id'=>1],['type_id'=>32768],['type_id'=>'1e2']]as $input){
 check(VodSaveInput::normalize($input)===null,'Invalid input/ID/type is controlled');
}
foreach(['uptime','uptag','vod_play_present','vod_down_present']as $flag){
 foreach([[],false,'yes','',2]as $value)check(VodSaveInput::normalize($base+[$flag=>$value])===null,'Invalid flag '.$flag);
}
check(VodSaveInput::normalize($base+array_fill_keys(array_map(static fn($i)=>'extra_'.$i,range(1,254)),''))===null,'Field count bounded');
check(VodSaveInput::normalize($base+[0=>'value'])===null,'Non-string field name rejected');
foreach(['',null,'0','普通简介']as $value){
 $data=VodSaveInput::normalize($base+['vod_content'=>$value]);check($data['vod_content']===($value??''),'Description value retained');
}
check(strlen(VodSaveInput::normalize($base+['vod_content'=>str_repeat('a',1048576)])['vod_content'])===1048576,'Exact description byte boundary');
foreach([str_repeat('a',1048577),['nested'],new stdClass(),"\xff"]as $value)check(VodSaveInput::normalize($base+['vod_content'=>$value])===null,'Invalid description shape/size/encoding');
foreach(['play','down']as $operation){
 $prefix='vod_'.$operation.'_';
 $input=$base+[$prefix.'from'=>['player','second'],$prefix.'server'=>['no','no'],$prefix.'note'=>['First','Second'],$prefix.'url'=>['One$https://cdn.example/1.mp4','Two$https://cdn.example/2.mp4']];
 $before=$input;$data=VodSaveInput::normalize($input);
 check($input===$before && $data[$prefix.'from']==='player$$$second' && $data[$prefix.'note']==='First$$$Second','Form arrays normalize without modifying caller data');
 $joined=$input;foreach(['from','server','note','url']as $suffix)$joined[$prefix.$suffix]=implode('$$$',$input[$prefix.$suffix]);
 check(VodSaveInput::normalize($joined)===$data,'Prejoined input and actual form arrays have the same result');
 foreach([[$prefix.'from'=>[]],[$prefix.'from'=>''],[$prefix.'present'=>'1']]as $clear){
  $data=VodSaveInput::normalize($base+$clear);foreach(['from','server','note','url']as $suffix)check($data[$prefix.$suffix]==='','Explicit clearing normalizes each source column');
  check(!isset($data[$prefix.'present']),'Internal form marker is consumed');
 }
 $data=VodSaveInput::normalize($base+[$prefix.'from'=>'player',$prefix.'url'=>'One$https://cdn.example/video.mp4']);
 check($data[$prefix.'server']==='' && $data[$prefix.'note']==='','Missing optional companion fields are empty strings');
 foreach(["\n","\r\n","\r"]as $newline){
  $data=VodSaveInput::normalize($base+[$prefix.'from'=>'player',$prefix.'url'=>'one'.$newline.'two']);
  check($data[$prefix.'url']==='one#two','Ordinary line ending becomes one episode delimiter');
 }
 foreach(['url','note','server']as $suffix)check(VodSaveInput::normalize($base+[$prefix.$suffix=>'value'])===null,'Companion-only patch rejected');
 foreach(['',' ','0']as $from)check(VodSaveInput::normalize($base+[$prefix.'from'=>$from,$prefix.'url'=>'one'])===null,'No readable source cannot discard a provided URL');
 foreach([['nested'],new stdClass(),true,"\xff"]as $from)check(VodSaveInput::normalize($base+[$prefix.'from'=>[$from]])===null,'Invalid source fragment rejected');
 check(VodSaveInput::normalize($base+[$prefix.'from'=>array_fill(0,257,'p')])===null,'Source fragment count checked before join');
 check(VodSaveInput::normalize($base+[$prefix.'from'=>str_repeat('p$$$',256)])===null,'Prejoined source count bounded');
 check(VodSaveInput::normalize($base+[$prefix.'from'=>['p','']])===null,'Trailing empty identifier rejected');
 check(VodSaveInput::normalize($base+[$prefix.'from'=>'p',$prefix.'url'=>'one$$$two'])===null,'Extra URL group cannot be silently dropped');
 foreach(['from','server','note']as $suffix){
  $input=$base+[$prefix.'from'=>'p'];$input[$prefix.$suffix]=str_repeat('a',255);
  check(VodSaveInput::normalize($input)!==null,'Exact stored metadata character limit');
  $input[$prefix.$suffix].='a';check(VodSaveInput::normalize($input)===null,'Metadata exceeding the schema is rejected');
  $input[$prefix.$suffix]=str_repeat('&',52);check(VodSaveInput::normalize($input)===null,'Capacity includes the actual text filter expansion');
 }
 check(VodSaveInput::normalize($base+[$prefix.'from'=>'p',$prefix.'note'=>'$<plain></plain>$$'])===null,'Ordinary tag removal cannot create an extra metadata group');
 $data=VodSaveInput::normalize($base+[$prefix.'from'=>'p',$prefix.'url'=>str_repeat('a',8388608)]);
 check(strlen($data[$prefix.'url'])===8388608,'Exact URL byte boundary accepted');unset($data);
 check(VodSaveInput::normalize($base+[$prefix.'from'=>'p',$prefix.'url'=>str_repeat('a',8388609)])===null,'Oversized URL rejected before join');
 check(VodSaveInput::normalize($base+[$prefix.'from'=>'p$$$q',$prefix.'url'=>[str_repeat('a',8388607),'']])===null,'Byte budget includes join delimiters');
 $data=VodSaveInput::normalize($base+[$prefix.'from'=>'p',$prefix.'url'=>str_repeat('episode#',19999).'episode']);
 check(substr_count($data[$prefix.'url'],'#')===19999,'Exactly 20000 logical episodes accepted');
 check(VodSaveInput::normalize($base+[$prefix.'from'=>'p',$prefix.'url'=>str_repeat('episode#',20000).'episode'])===null,'Episode count bounded');
}
echo 'framework_audit_vod_save_input: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
