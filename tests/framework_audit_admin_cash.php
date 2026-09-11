<?php
/** Real administrator constructor, permission/session refresh, cash ORM and route dispatch. */
declare(strict_types=1);
define('CASH_WRITE_AUDIT',true);define('CASH_ADMIN_AUDIT',true);define('ENTRANCE','admin');
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
define('APP_PATH',$purchaseTemp.'/application/');
mkdir(APP_PATH.'data/update',0700,true);file_put_contents(APP_PATH.'data/update/sec_schema.lock','v2');
function url($path,$params=[]){return '/fixture/admin.php/'.$path.($params === [] ? '' : '?'.http_build_query($params));}
function redirect($path){return \think\Response::create($path,'redirect',302);}
class AdminCashFixture extends \app\admin\controller\Cash {
    private array $assigned=[];
    protected function assign($name,$value=''):void{$this->assigned[$name]=$value;}
    protected function fetch(string $template='',array $vars=[]):string{
        global $purchaseTemp;
        $source=file_get_contents(dirname(__DIR__).'/application/admin/view/'.str_replace('admin@','',$template).'.html');
        $source=preg_replace('/\{include\b[^}]*\}/','',$source);
        $source=str_replace(['__STATIC__','__ASSETV__'],['/fixture/static','fixture'],$source);
        $engine=new \think\Template(['cache_path'=>$purchaseTemp.'/']+(require dirname(__DIR__).'/config/view.php'));ob_start();
        try{$engine->display($source,$vars+$this->assigned);return ob_get_contents();}finally{ob_end_clean();}
    }
}
$app->bind(\app\admin\controller\Cash::class,AdminCashFixture::class);
function adminCashState():array {
    return purchaseCsrfState()+['CashHistory'=>Db::name('CashHistory')->order('cash_id')->select()->toArray(),'cash'=>Db::name('Cash')->order('cash_id')->select()->toArray(),
        'requests'=>Db::name('CashRequest')->order('user_id,request_id')->select()->toArray()];
}
function adminCashSeed():array {
    global $app;
    purchaseCsrfSeed();$GLOBALS['config']['app']+=['pagesize'=>20,'makesize'=>20,'security_csrf_admin'=>0,'security_csrf_admin_exempt'=>'cash/*'];
    $GLOBALS['config']['user']+=['cash_status'=>1,'cash_ratio'=>100,'cash_min'=>'0.01'];
    $app->config->set($GLOBALS['config'],'maccms');
    Db::name('Admin')->insert(['admin_id'=>2,'admin_name'=>'cash-operator','admin_pwd'=>password_hash('fixture',PASSWORD_BCRYPT,['cost'=>4]),
        'admin_auth'=>',cash/audit,cash/del,','admin_status'=>1,'admin_random'=>'fixture']);
    foreach([1,2] as $owner){
        Db::name('User')->where('user_id',$owner)->update(['user_points'=>100]);
        $res=(new \app\common\model\Cash())->saveRequestForUser($owner,['request_id'=>str_repeat('a',64),'cash_money'=>'0.29','cash_bank_name'=>'Ordinary bank','cash_bank_no'=>'1234','cash_payee_name'=>'Ordinary name']);
        check($res['code']===1,'Admin fixture must seed actual reserved funds');
    }
    $request=new PurchaseCsrfRequest();$app->instance('request',$request);$app->instance('cookie',new \think\Cookie($request));
    $session=new \think\Session($app);$app->instance('session',$session);$session->init();
    $session->set('admin_auth','1');$session->set('admin_info',Db::name('Admin')->where('admin_id',2)->find());
    $token=\app\common\util\SessionCsrf::issue();$session->save();
    return [['fixture_session'=>$session->getId()],$token];
}
function adminCashRoute(string $action,array $body=[],array $query=[],array $cookies=[],array $headers=[],string $method='POST',array $server=[]):array {
    global $app;
    $_GET=$query;$_POST=$body;$_COOKIE=$cookies;$_REQUEST=$body+$query;
    $_SERVER=$server+['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid','SCRIPT_NAME'=>'/fixture/admin.php',
        'SCRIPT_FILENAME'=>'/isolated/admin.php','PATH_INFO'=>'/cash/'.$action,'REQUEST_URI'=>'/fixture/admin.php/cash/'.$action,'HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest'];
    $request=PurchaseCsrfRequest::__make($app)->withHeader($headers);$app->instance('request',$request);$app->instance('cookie',new \think\Cookie($request));
    $session=new \think\Session($app);$app->instance('session',$session);$app->setNamespace('app\\admin');$app->config->set([],'route');
    $middleware=new \think\middleware\SessionInit($app,$session);
    try{$response=$middleware->handle($request,static fn($request)=>(new \think\Route($app))->dispatch($request,false));}
    catch(\think\exception\HttpResponseException $error){$response=$error->getResponse();}
    $middleware->end($response);
    check($response instanceof \think\response\Json||$response->getCode()===302||($action==='index'&&$response->getCode()===200),'Administrator route must return controlled data, HTML or a login redirect');
    return ['response'=>$response,'data'=>$response instanceof \think\response\Json?$response->getData():['code'=>$response->getCode()===200?1:1401]];
}
function adminCashDenied($action,$body,$query,$cookies,$headers=[],$method='POST',$server=[]):void {
    $before=adminCashState();$result=adminCashRoute($action,$body,$query,$cookies,$headers,$method,$server);
    check(($result['data']['code']??1)!==1&&adminCashState()===$before,'Rejected admin '.$action.' must preserve balances, cash records, receipts and ledgers');
}
foreach(['del','audit'] as $action) {
    [$cookies,$token]=adminCashSeed();$id=(string)Db::name('Cash')->where('user_id',1)->value('cash_id');
    foreach(['GET','PUT','PATCH','DELETE','HEAD'] as $method)adminCashDenied($action,['csrf_token'=>$token,'ids'=>$id],[],$cookies,[],$method);
    foreach([['GET','POST'],['POST','GET'],['PUT','POST']] as [$method,$override])adminCashDenied($action,['csrf_token'=>$token,'ids'=>$id],[],$cookies,[],$method,['HTTP_X_HTTP_METHOD_OVERRIDE'=>$override]);
    adminCashDenied($action,['_method'=>'GET','csrf_token'=>$token,'ids'=>$id],[],$cookies);
    foreach([[],['csrf_token'=>[]],['csrf_token'=>'wrong']] as $credential)adminCashDenied($action,$credential+['ids'=>$id],['csrf_token'=>$token],$cookies);
    adminCashDenied($action,['ids'=>$id,'csrf_token'=>$token],[],$cookies,['X-CSRF-Token'=>'wrong']);
    adminCashDenied($action,['ids'=>$id,'csrf_token'=>$token],[],[]);
    foreach([[],['ids'=>[]],['ids'=>[['1']]],['ids'=>['named'=>'1']],['ids'=>['1,2']],['ids'=>'-'.$id],['ids'=>'1%2C2'],['ids'=>'4294967296'],['all'=>true]] as $selection) {
        adminCashDenied($action,['csrf_token'=>$token]+$selection,['ids'=>$id,'all'=>'1'],$cookies);
    }
    if($action==='audit')adminCashDenied($action,['all'=>'1','csrf_token'=>$token],[],$cookies);
    Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',cash/index,']);
    adminCashDenied($action,['csrf_token'=>$token,'ids'=>$id],[],$cookies);
    Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',cash/del,cash/audit,','admin_status'=>0]);
    adminCashDenied($action,['csrf_token'=>$token,'ids'=>$id],[],$cookies);
    [$cookies,$token]=adminCashSeed();$id=(string)Db::name('Cash')->where('user_id',1)->value('cash_id');$other=(string)Db::name('Cash')->where('user_id',2)->value('cash_id');
    $result=adminCashRoute($action,['ids'=>[$id,$id]],['ids'=>$other,'all'=>'1'],$cookies,['X-CSRF-Token'=>$token]);
    check($result['data']['code']===1,'Valid checkbox selection with current permission and token must succeed');
    check((int)Db::name('User')->where('user_id',2)->value('user_points_froze')===29&&(int)Db::name('Cash')->where('cash_id',$other)->value('cash_status')===0,'Query parameters cannot expand selected administrator scope');
    check((int)Db::name('User')->where('user_id',1)->value('user_points_froze')===0&&Db::name('Plog')->count()===($action==='audit'?1:0),'Selected operation must change its financial state exactly once');
    $state=adminCashState();check(adminCashRoute($action,['ids'=>$id,'csrf_token'=>$token],[],$cookies)['data']['code']===1&&adminCashState()===$state,'Repeating a selected admin operation cannot settle or refund twice');
}
[$cookies,$token]=adminCashSeed();$result=adminCashRoute('del',['all'=>'1','csrf_token'=>$token],[],$cookies);
check($result['data']['code']===1&&Db::name('Cash')->count()===0&&Db::name('CashRequest')->count()===2,'Explicit admin clear must preserve durable creation receipts');
check((int)Db::name('User')->where('user_id',1)->value('user_points')===100&&(int)Db::name('User')->where('user_id',2)->value('user_points')===100,'Clear must refund each pending reservation once');
adminCashSeed();$rows=(new \app\common\model\Cash())->listData([],'cash_id',1,20)['list'];
$source=file_get_contents(dirname(__DIR__).'/application/admin/view/cash/index.html');$source=preg_replace('/\{include\b[^}]*\}/','',$source);
$source=str_replace(['__STATIC__','__ASSETV__'],['/fixture/static','fixture'],$source);
$engine=new \think\Template(['cache_path'=>$purchaseTemp.'/']+(require dirname(__DIR__).'/config/view.php'));ob_start();
try{$engine->display($source,['list'=>$rows,'total'=>2,'page'=>1,'limit'=>20,'param'=>['status'=>'','wd'=>'','page'=>'{page}','limit'=>'{limit}']]);$html=ob_get_contents();}finally{ob_end_clean();}
check(substr_count($html,'js-cash-action')===7&&!str_contains($html,'?ids='),'Actual admin template must render body-based handlers for every bulk and row action');
check(str_contains($html,'/fixture/static/js/cash-write.js')&&str_contains($html,'/fixture/static/js/admin_cash.js'),'Actual admin template must load the dedicated financial write scripts');

// Browse with the existing read permission through the real constructor, query and templates.
[$cookies,$token]=adminCashSeed();
Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',cash/index,']);
$ids=Db::name('Cash')->order('cash_id')->column('cash_id');$cash=new \app\common\model\Cash();
Db::name('Cash')->where('cash_id',$ids[0])->update(['cash_bank_no'=>'literal%2B+&"account']);
$before=adminCashState();$result=adminCashRoute('index',[],['wd'=>'literal%2B+&"account'],$cookies,[],'GET');
$html=$result['response']->getContent();
check($result['data']['code']===1&&str_contains($html,'literal%2B+&amp;&quot;account')&&adminCashState()===$before,'Active search must bind the original keyword once and escape HTML output without mutation');
check(str_contains($html,'archive=1'),'Active page must expose the read-only archive link');
check($cash->auditData(['cash_id'=>$ids[1]])['code']===1,'Archive read fixture must settle the approved withdrawal');
check($cash->delData(['cash_id'=>$ids],['type'=>'admin','id'=>2])['code']===1,'Archive read fixture must retain both cancellation and approval');
$before=adminCashState();
foreach([[],['status'=>'2'],['status'=>'1'],['uid'=>'1'],['wd'=>'literal%2B+&"account'],['limit'=>'1','page'=>'2']] as $filters){
    $result=adminCashRoute('index',[],['archive'=>'1']+$filters,$cookies,[],'GET');$html=$result['response']->getContent();
    check($result['data']['code']===1&&str_contains($html,'admin/cash/archive_readonly')&&adminCashState()===$before,'Archive queries must render their real template without financial writes');
    check(!str_contains($html,'js-cash-action')&&!str_contains($html,'checkbox')&&!str_contains($html,'cash-write.js'),'Archive template must have no financial write controls or script');
    $rows=substr_count($html,'admin/cash/actor_admin');
    check($rows===($filters===[]?2:1),'Archive status, owner, keyword and page filters must select the expected rows');
}
foreach(['page'=>[[],0,-1,'1e2','1.2',true,'4294967295'],'limit'=>[[],0,-1,101,'1e2',true],
    'status'=>[[],0,3,'01',true],'archive'=>[[],2,true],'uid'=>[[],0,'4294967296',true],'wd'=>[[],true,str_repeat('a',201),"a\0b","\xff"]] as $field=>$values){
    foreach($values as $value)adminCashDenied('index',[],array_replace(['archive'=>'1'],[$field=>$value]),$cookies,[],'GET');
}
adminCashDenied('index',[],['archive'=>'1'],[],[],'GET');
Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',cash/audit,cash/del,']);
adminCashDenied('index',[],['archive'=>'1'],$cookies,[],'GET');
Db::name('Admin')->where('admin_id',2)->update(['admin_auth'=>',cash/index,']);
Db::name('CashHistory')->where('cash_id',$ids[0])->update(['cash_payload_hash'=>str_repeat('0',64)]);
$before=adminCashState();$result=adminCashRoute('index',[],['archive'=>'1'],$cookies,[],'GET');
check(($result['data']['code']??1)!==1&&$result['data']['msg']==='admin/cash/archive_unavailable'&&adminCashState()===$before,'Corrupt snapshot must produce a controlled error, not disappear or render partial financial data');
Db::execute('DROP TABLE audit_cash_history');
$result=adminCashRoute('index',[],['archive'=>'1'],$cookies,[],'GET');
check(($result['data']['code']??1)!==1&&$result['data']['msg']==='admin/cash/archive_unavailable','An unmigrated installation must receive an explicit archive error');
echo 'Admin cash routes: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
