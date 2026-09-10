<?php
/** Actual Annex model/template/check call chain with nonempty committed remote records. */
use think\facade\Db;
function mac_day($timestamp,$format=''){return date('Y-m-d',(int)$timestamp);}
function mac_echo($text){$GLOBALS['remote_check_output'][]=$text;}
function mac_jump($url,$seconds){$GLOBALS['remote_check_jump']=$url;}
function url($route,$parameters=[]){return '/fixture/'.$route;}

$path=Db::name('StorageIntent')->where('reference_state','committed')->where('transfer_state','remote_confirmed')->where('provider','upyun')->select()->toArray()[0]['local_path'];
$list=(new app\common\model\Annex())->listData(['annex_file'=>$path],'annex_id asc')['list'];
check(count($list)===1 && str_starts_with($list[0]['annex_url'],'https://objects.fixture.invalid/'),'Actual Annex list did not resolve a committed remote object');
$source=file_get_contents(dirname(__DIR__,2).'/application/admin/view/annex/index.html');
if(!preg_match('/\{volist name="list" id="vo"\}[\s\S]*?\{\/volist\}/',$source,$match))throw new RuntimeException('Annex list template block missing');
$template=new think\Template(['cache_path'=>ROOT_PATH.'view-cache/','tpl_cache'=>false,'default_filter'=>'']);
ob_start();try{$template->display($match[0],['list'=>$list]);$html=ob_get_contents();}finally{ob_end_clean();}
$dom=new DOMDocument();@$dom->loadHTML('<table>'.$html.'</table>');$link=$dom->getElementsByTagName('a')->item(0);
check($link && $link->getAttribute('href')===$list[0]['annex_url'] && $link->textContent===$path,'Rendered Annex link still prepended the install path to a remote URL');
$helper=file_get_contents(dirname(__DIR__,2).'/application/common.php');
if(!preg_match('/function mac_get_user_portrait\([^)]*\)\s*\{[\s\S]*?\n\}/',$helper,$match))throw new RuntimeException('Avatar helper missing');
eval($match[0]);
$profile=file_get_contents(dirname(__DIR__,2).'/application/admin/view/user/info.html');
if(!preg_match('/<input[^\n]+id="user_portrait"[^\n]*>/',$profile,$input))throw new RuntimeException('Admin avatar input missing');
foreach([['user_id'=>1],[],['user_id'=>0],['user_id'=>[]],['user_id'=>'4294967296']] as $info) {
    ob_start();try{$template->display($input[0],['info'=>$info]);$html=ob_get_contents();}finally{ob_end_clean();}
    $dom=new DOMDocument();@$dom->loadHTML($html);$element=$dom->getElementsByTagName('input')->item(0);
    $expected=($info['user_id']??null)===1?app\common\util\UserPortrait::url(1):'';
    check($element && $element->getAttribute('value')===$expected && $element->hasAttribute('readonly') && !$element->hasAttribute('name'),
        'Rendered admin avatar lost its trusted URL, owner boundary or read-only contract');
}

$unrelated='upload/vod/missing-local-fixture.txt';
Db::name('Annex')->insert(['annex_file'=>$unrelated,'annex_size'=>1,'annex_type'=>'file','annex_time'=>time()]);
$before=Db::name('Annex')->order('annex_id')->select()->toArray();
uploadIdentityRequest(['num'=>0,'start'=>1,'page_count'=>1,'data_count'=>count($before)],'GET',false);
$controller=(new ReflectionClass(app\admin\controller\Annex::class))->newInstanceWithoutConstructor();$controller->check();
$after=Db::name('Annex')->order('annex_id')->select()->toArray();
check(count($after)===count($before)-1 && !in_array($unrelated,array_column($after,'annex_file'),true),'Actual check did not preserve remote refs while removing an unrelated missing local row');
check(Db::name('Annex')->where('annex_file',$path)->find()!==null,'Actual check deleted a committed remote attachment');

Db::name('Annex')->insert(['annex_file'=>$unrelated,'annex_size'=>1,'annex_type'=>'file','annex_time'=>time()]);
$before=Db::name('Annex')->order('annex_id')->select()->toArray();
Db::execute('ALTER TABLE upload_audit_storage_intent RENAME TO upload_audit_storage_check_saved');
try {
    uploadIdentityRequest(['num'=>0,'start'=>1,'page_count'=>1,'data_count'=>count($before)],'GET',false);$controller->check();
    check(Db::name('Annex')->order('annex_id')->select()->toArray()===$before,'Unavailable intent metadata was treated as proof to delete an attachment');
} finally {Db::execute('ALTER TABLE upload_audit_storage_check_saved RENAME TO upload_audit_storage_intent');}
