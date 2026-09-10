<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require dirname(__DIR__,2).'/application/common.php';
require __DIR__.'/security_audit_test_helpers.php';
$temporary=audit_temp_dir('editor-textarea');
register_shutdown_function(static fn()=>audit_remove_temp($temporary));
$GLOBALS['config']=['upload'=>['protocol'=>'https','img_key'=>'']];
$viewConfig=require dirname(__DIR__,2).'/config/view.php';
$viewConfig['cache_path']=$temporary.'/';
$fields=[
 ['actor/info.html','actor_content','info','actor_content'],
 ['art/info.html','art_content0','vo','content'],
 ['manga/info.html','manga_content','info','manga_content'],
 ['role/info.html','role_content','info','role_content'],
 ['topic/info.html','topic_content','info','topic_content'],
 ['vod/info.html','vod_content','info','vod_content'],
 ['website/info.html','website_content','info','website_content'],
 ['vod/iplot.html','vod_plot_detail0','vo','detail'],
];
$cases=[
 'plain'=>['Ordinary text','Ordinary text'],
 'rich'=>['<p>中文 & ordinary <em>text</em></p>','<p>中文 & ordinary <em>text</em></p>'],
 'entities'=>['<p>&lt;em&gt;ordinary&lt;/em&gt; &amp; &#65;</p>','<p>&lt;em&gt;ordinary&lt;/em&gt; &amp; &#65;</p>'],
 'quotes'=>['"Quoted" and \'ordinary\' text','"Quoted" and \'ordinary\' text'],
 'closing'=>['Before</textarea><p id="editor-boundary-probe">Ordinary note</p><textarea>After','Before</textarea><p id="editor-boundary-probe">Ordinary note</p><textarea>After'],
 'leading_lf'=>["\n\nOrdinary text","\n\nOrdinary text"],
 'line_endings'=>["\r\nFirst\rSecond\nThird","\nFirst\nSecond\nThird"],
 'null'=>[null,''],
 'zero'=>[0,'0'],
 'invalid_utf8'=>["Before\xFFAfter","Before\u{FFFD}After"],
 'protocol'=>['<img src="mac://images.example/ordinary.png">','<img src="https://images.example/ordinary.png">'],
];
$result=[];
foreach($fields as [$file,$id,$parent,$key]){
 $source=file_get_contents(dirname(__DIR__,2).'/application/admin/view/'.$file);
 $templateId=str_replace('0','{$key}',$id);
 if(!preg_match('~<textarea\b[^>]*\bid="'.preg_quote($templateId,'~').'"[^>]*>.*?</textarea>~s',$source,$match)){
  throw new RuntimeException('Actual textarea missing: '.$file.' / '.$templateId);
 }
 $samples=$cases;
 if($file==='vod/iplot.html'){
  $samples['protocol'][1]=$samples['protocol'][0];
  $samples['entities']=['Literal &lt;em&gt; and &amp;','Literal &lt;em&gt; and &amp;'];
  $samples['plot_separators']=['First#Second',"First\nSecond"];
 }
 if(($argv[1]??'')==='capacity'){
  if($file!=='art/info.html'){continue;}
  $value=str_repeat('"',8*1024*1024);
  $engine=new think\Template($viewConfig);ob_start();$engine->display($match[0],[$parent=>[$key=>$value],'key'=>0]);
  $length=ob_get_length();ob_end_clean();
  check($length>8*1024*1024,'Maximum article content actually rendered');
  echo json_encode(['input_bytes'=>strlen($value),'html_bytes'=>$length,'peak_bytes'=>memory_get_peak_usage(true),'limit'=>ini_get('memory_limit')],JSON_THROW_ON_ERROR).PHP_EOL;
  exit;
 }
 foreach($samples as $case=>[$value,$expected]){
  $engine=new think\Template($viewConfig);ob_start();$engine->display($match[0],[$parent=>[$key=>$value],'key'=>0]);$html=ob_get_clean();
  $result[]=['template'=>$file,'id'=>$id,'case'=>$case,'expected'=>$expected,'html'=>$html];
 }
}
echo json_encode(['php'=>PHP_VERSION,'cases'=>$result],JSON_INVALID_UTF8_SUBSTITUTE|JSON_THROW_ON_ERROR);
