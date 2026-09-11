<?php
/** Exercise extension error/argument-order boundaries with ordinary PHP stand-ins, not a native extension. */
declare(strict_types=1);
namespace app\common\util { function extension_loaded($name){return $name==='opencc' || \extension_loaded($name);} }
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\OpenccConverter as Converter;
function opencc_open($config){
    $GLOBALS['opencc_opens']++;
    if($GLOBALS['opencc_mode']==='open-failure')throw new RuntimeException('Fixture cannot open this config');
    return (object)['config'=>$config];
}
function opencc_convert($first,$second){
    if($GLOBALS['opencc_mode']==='convert-failure')throw new TypeError('Fixture conversion unavailable');
    if($GLOBALS['opencc_mode']==='text-first'){
        if(!is_string($first)||!is_object($second))throw new TypeError('Fixture text-first API');$text=$first;
    }else{
        if(!is_object($first)||!is_string($second))throw new TypeError('Fixture handle-first API');$text=$second;
    }
    return str_replace('软件','軟件',$text);
}
$path=getenv('PATH');putenv('PATH=/nonexistent-opencc-fixture');
try {
    foreach(['handle-first','text-first','open-failure','convert-failure'] as $mode){
        $GLOBALS['opencc_mode']=$mode;$GLOBALS['opencc_opens']=0;
        foreach(['shellChecked'=>false,'shellAvailable'=>false,'conversionWorks'=>null,'cache'=>[],'cacheBytes'=>0,'extOd'=>[]] as $key=>$value)(new ReflectionProperty(Converter::class,$key))->setValue(null,$value);
        $success=in_array($mode,['handle-first','text-first'],true);
        check(Converter::s2t(" 软件\n")===($success?" 軟件\n":" 软件\n"),'Optional extension failures must preserve input and valid argument orders must work');
        check(Converter::available()===$success,'Availability must reflect actual conversion, not merely installed functions');
        if($success){
            for($i=0;$i<40;$i++)Converter::convert('软件','fixture_'.$i);
            check(count((new ReflectionProperty(Converter::class,'extOd'))->getValue())<=32,'Distinct native handle candidates must be bounded');
        }
    }
    echo 'OpenCC extension boundary: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
}finally{putenv('PATH='.$path);}
}
