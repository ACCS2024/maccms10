<?php
/** Unicode slicing and actual search, SEO, template and installation path callers. */
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
foreach ([
    ['abc XYZ-123',4,0,'abc '], ['ASCII text',50,0,'ASCII text'], ['中文测试',2,0,'中文'],
    ['A😀中🧑B',3,1,'😀中🧑'], ['αβγ',2,1,'βγ'], ['éx',2,0,'é'],
    ['A😀B',1,1,'😀'], ['A😀B',1,2,'B'], ['text',0,0,''], ['text',1,4,''],
    ['text',1,1000000,''], ['',8,0,''], [null,8,0,''], [[],8,0,''], [new stdClass(),8,0,''],
    [12345,3,1,'234'], [true,1,0,'1'], [false,1,0,''],
    ['字符slice','0003','0001','符sl'], ['text',PHP_INT_MAX,0,'text'],
] as [$text,$length,$offset,$expected]) {
    check(mac_substring($text,$length,$offset)===$expected, 'Substring changed valid text or its code-point coordinates');
}
foreach ([null,[],new stdClass(),true,false,1.2,'1.2','1e2','-1',-1,' 2','2 ',(string)PHP_INT_MAX.'0'] as $bad) {
    check(mac_substring('text',$bad)==='', 'Malformed length reached an implicit PHP conversion');
    check(mac_substring('text',2,$bad)==='', 'Malformed offset selected another substring');
}
$encoding=mb_internal_encoding();$substitute=mb_substitute_character();
try {
    mb_internal_encoding('ISO-8859-1');mb_substitute_character(0xFFFD);
    check(mac_substring('A😀中',2,1)==='😀中','Global mb encoding changed UTF-8 slicing');
    check(mac_substring("A\xffB",3)==="A�B",'Invalid input bytes escaped as malformed UTF-8');
} finally {mb_internal_encoding($encoding);mb_substitute_character($substitute);}
$GLOBALS['config']=['app'=>['search_len'=>'3'], 'ai_seo'=>['template_inject'=>1], 'site'=>['site_name'=>'Fixture']];
$keys=['wd','tag','class','letter','name','state','level','area','lang','version','actor','director','starsign','blood'];
$parameters=array_fill_keys($keys,'');$parameters['wd']='A😀中文XYZ';$parameters['actor']='Actor name';
$result=mac_search_len_check($parameters);
check($result['wd']==='A😀中' && $result['actor']==='Act','Actual search clipping loses ASCII or four-byte characters');
class SubstringSeoProbe extends \app\common\controller\All {
    public array $assigned=[];
    public function __construct() {$this->_maccms=['site_name'=>'Fixture'];}
    protected function assign($name,$value=''):void {$this->assigned[$name]=$value;}
    public function renderDescription(array $row):string {$this->mergeDetailSeoIntoMaccms(1,$row,[]);return $this->assigned['maccms']['page_detail_description'];}
}
$description=(new SubstringSeoProbe())->renderDescription(['vod_name'=>'Video','vod_tag'=>'tag','vod_class'=>'class','vod_blurb'=>'','vod_content'=>'<p>ASCII😀中文 description</p>']);
check($description==='ASCII😀中文 description','Actual SEO fallback description is blank or corrupted');
$temp=audit_temp_dir('substring');
try {
    $template=new think\Template(['cache_path'=>$temp.'/templates/','tpl_cache'=>false,'default_filter'=>'']);
    ob_start();try {$template->display('<meta name="description" content="{:mac_substring($text,4)}">',['text'=>'ABC😀中文']);$html=ob_get_contents();} finally {ob_end_clean();}
    check($html==='<meta name="description" content="ABC😀">','Actual template expression corrupts its generated metadata');
    class SubstringInstallProbe extends \app\install\controller\Index {
        public array $assigned=[];
        public function __construct() {}
        protected function assign($name,$value=''):void {$this->assigned[$name]=$value;}
        protected function fetch(string $template='',array $vars=[]):string {return $template;}
    }
    $step=new ReflectionMethod(\app\install\controller\Index::class,'step3');
    foreach (['/install.php'=>'/', '/site/install.php'=>'/site/', '/中文/😀/install.php'=>'/中文/😀/', '/site/'=>'/site/', 'install.php'=>'/'] as $script=>$expected) {
        $_SERVER['SCRIPT_NAME']=$script;$controller=new SubstringInstallProbe();$step->invoke($controller);
        check($controller->assigned['install_dir']===$expected,'Actual installation form mixed byte and Unicode offsets');
    }
    foreach ([null,[]] as $script) {
        $_SERVER['SCRIPT_NAME']=$script;$controller=new SubstringInstallProbe();$step->invoke($controller);
        check($controller->assigned['install_dir']==='/','Missing/malformed server script name must not break the form');
    }
    echo 'Substring and callers: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
} finally {audit_remove_temp($temp);}
