<?php
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\OpenccConverter as Converter;
$app=new \think\App(sys_get_temp_dir().'/opencc-fixture-app');
$cache=new class {
    public array $data=[];
    public function get($key){return $this->data[$key]??null;}
    public function set($key,$value,$ttl){$this->data[$key]=$value;return true;}
};
$app->instance('cache',$cache);class_exists(\think\Cache::class);
$temp=audit_temp_dir('opencc');$oldPath=getenv('PATH');
$native=($argv[1]??'')==='native';
function openccReset():void {
    foreach(['shellChecked'=>false,'shellAvailable'=>false,'conversionWorks'=>null,'cache'=>[],'cacheBytes'=>0,'extOd'=>[]] as $name=>$value){(new ReflectionProperty(Converter::class,$name))->setValue(null,$value);}
    $GLOBALS['cache']->data=[];
}
try {
    if (!$native) {
        $script=<<<'CODE'
<?php
if (($argv[1]??'')==='--version'){echo "OpenCC 1.0.0 fixture\n";exit;}
$text=stream_get_contents(STDIN);
$mode=getenv('OPENCC_FIXTURE_MODE');
if($mode==='timeout'){echo 'partial';sleep(10);exit;}
if($mode==='failure'){echo 'partial';exit(1);}
if($mode==='noisy'){fwrite(STDERR,str_repeat('x',18000000));echo 'partial';exit;}
if($mode==='legacy-config' && str_ends_with($argv[2]??'','.json')){echo 'partial';exit(1);}
echo str_replace(['软件','軟件'],str_starts_with($argv[2]??'','t2s')?['软件','软件']:['軟件','軟件'],$text);
CODE;
        file_put_contents($temp.'/opencc','#!'.PHP_BINARY."\n".$script);chmod($temp.'/opencc',0700);
        putenv('PATH='.$temp);putenv('OPENCC_FIXTURE_MODE=normal');
    }
    if ($native) {
        $version=\app\common\util\LocalProcess::capture(['opencc','--version']);
        check(is_string($version) && stripos($version,'OpenCC')!==false,'Native CLI must expose its supported version option');
        check((new ReflectionMethod(Converter::class,'execOpencc'))->invoke(null," 软件\r\n",'s2t')===" 軟件\r\n",'Actual CLI stdin/stdout conversion must preserve whitespace');
    }
    openccReset();
    check(Converter::available(),'Actual tool must pass the conversion probe');
    $text=" \t软件\r\n";$expected=" \t軟件\r\n";
    check(Converter::s2t($text)===$expected,'Conversion must preserve leading/trailing whitespace and CRLF');
    check(Converter::t2s($expected)===$text,'Traditional-to-simplified conversion must preserve original bytes around the text');
    check(Converter::s2t($text)===$expected,'Completed cached conversion must remain stable');
    foreach ([[],new stdClass(),true] as $bad)check(Converter::s2t($bad)==='','Wrong text shape must not emit diagnostics');
    foreach ([null,[],true,'../config',str_repeat('a',65)] as $bad)check(Converter::convert('软件',$bad)==='软件','Invalid config shape/name must not reach a process');
    check(Converter::s2t("软件\xff")==="软件\xff",'Invalid UTF-8 must remain unchanged');
    check(Converter::s2t(str_repeat('a',8388609))===str_repeat('a',8388609),'Oversized optional conversion must preserve original input');
    check(in_array('%软件%',Converter::likePatterns('软件'),true),'Search variants preserve the original keyword');
    if (!$native) {
        foreach (['failure','timeout','noisy','legacy-config'] as $mode) {
            openccReset();putenv('OPENCC_FIXTURE_MODE='.$mode);
            (new ReflectionProperty(Converter::class,'shellExecTimeout'))->setValue(null,1);
            $time=microtime(true);$value=Converter::s2t('软件 '.$mode);
            check($value===($mode==='legacy-config'?'軟件 ':'软件 ').$mode,'Failed/partial conversion must preserve input; valid legacy config may recover');
            check(microtime(true)-$time<4,'Both config attempts must remain bounded');
            if($mode!=='legacy-config'){
                check(!array_filter(array_keys($cache->data),fn($key)=>str_starts_with($key,'opencc:v2:')),'Failed identity fallback must not persist as a successful conversion');
                putenv('OPENCC_FIXTURE_MODE=normal');
                check(Converter::s2t('软件 '.$mode)==='軟件 '.$mode,'A recovered tool must retry the same input');
            }
        }
        openccReset();putenv('OPENCC_FIXTURE_MODE=failure');
        Converter::s2t('软件 probe');
        check(!Converter::available(),'A version banner alone must not claim working conversion');
        $remember=new ReflectionMethod(Converter::class,'remember');
        for($i=0;$i<100;$i++){$remember->invoke(null,(string)$i,str_repeat('x',65536));}
        check((new ReflectionProperty(Converter::class,'cacheBytes'))->getValue()<=4194304,'Process cache must obey a byte budget');
        $count=count((new ReflectionProperty(Converter::class,'cache'))->getValue());
        $remember->invoke(null,'large',str_repeat('x',65537));
        check(count((new ReflectionProperty(Converter::class,'cache'))->getValue())===$count,'Oversized cache values must not be retained');
        openccReset();putenv('PATH='.$temp.'/missing');
        check(Converter::s2t('软件')==='软件' && !Converter::available(),'Missing command must use the ordinary identity fallback');
        check(glob($temp.'/mcc_*')===[],'Piped conversion must not create temporary input/output files');
    }
    echo 'OpenCC conversion: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($native?'native OpenCC':'fault tool fixture')."\n";
} finally {putenv('PATH='.$oldPath);putenv('OPENCC_FIXTURE_MODE');audit_remove_temp($temp);}
