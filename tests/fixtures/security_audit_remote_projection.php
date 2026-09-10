<?php
/** Actual auth label, member constructor and shipped template filters after a new request. */
use think\facade\Db;
final class RemotePortraitLabel extends app\common\controller\All
{
    public array $assigned = [];
    public function __construct() {}
    public function assign($name, $value = ''): void { $this->assigned[$name] = $value; }
    public function loadUser(): void { $this->label_user(); }
}
$source=file_get_contents(dirname(__DIR__,2).'/application/common.php');
foreach(['mac_scalar_string','mac_filter_xss','mac_default','mac_url_img'] as $helper) {
    if(function_exists($helper))continue;
    if(!preg_match('/function '.preg_quote($helper,'/').'\([^\n]*\)\s*\{[\s\S]*?\n\}/',$source,$match))throw new RuntimeException('Template helper missing: '.$helper);
    eval($match[0]);
}
$before=Db::name('User')->find(1);
uploadIdentityRequest([], 'GET', false);request()->setAction('index');
$label=new RemotePortraitLabel();$label->loadUser();
check($GLOBALS['user']['user_portrait']===$path && $label->assigned['user']['user_portrait']===$selected,
    'Auth label changed the identity row or omitted the verified display URL');
check(!isset($label->assigned['user']['user_random'],$label->assigned['user']['user_pwd']), 'Template projection disclosed authentication fields');
$template=new think\Template(['cache_path'=>ROOT_PATH.'projection-cache/','tpl_cache'=>false,'default_filter'=>'']);
$legacy=file_get_contents(dirname(__DIR__,2).'/template/demo/html/user/index.html');
if(!preg_match('/<img[^>]+src="\{\$obj\.user_portrait[^>]+>/',$legacy,$image))throw new RuntimeException('Shipped member avatar template missing');
foreach(['index','orders'] as $action) {
    request()->setAction($action);
    $controller=new app\index\controller\User();
    check($controller->assigned['obj']['user_portrait']===$selected && $GLOBALS['user']['user_portrait']===$path,
        'Member constructor changed identity or lost the verified URL for '.$action);
    ob_start();try{$template->display($image[0],['obj'=>$controller->assigned['obj']]);$html=ob_get_contents();}finally{ob_end_clean();}
    $dom=new DOMDocument();@$dom->loadHTML($html);$rendered=$dom->getElementsByTagName('img')->item(0);
    check($rendered && $rendered->getAttribute('src')===$selected,'Reloaded member template reverted to a removed local replica');
}
check(Db::name('User')->find(1)===$before,'Read projection mutated the stored member');
foreach([0,[], '4294967296'] as $invalid) {
    request()->setAction('index');$GLOBALS['user']=['user_id'=>$invalid,'user_portrait'=>'guest-placeholder.png'];
    $controller=new app\index\controller\User();
    check($controller->assigned['obj']['user_portrait']==='guest-placeholder.png','Invalid template owner fell back to the authenticated Cookie owner');
}
$GLOBALS['user']=$before;
