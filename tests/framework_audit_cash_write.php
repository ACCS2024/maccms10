<?php
/** Real Cookie/JWT/session/route/controller and installed financial tables. No payment provider. */
declare(strict_types=1);
define('CASH_WRITE_AUDIT', true);
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
class CashWriteApi extends \app\api\controller\Cash { protected function assign($name,$value=''):void{} }
$app->bind(\app\api\controller\Cash::class,CashWriteApi::class);
function cashWriteSeed():void {
    global $app;
    purchaseCsrfSeed();
    $GLOBALS['config']['user'] += ['cash_status'=>1,'cash_ratio'=>100,'cash_min'=>'0.01'];
    $app->config->set($GLOBALS['config'],'maccms');
}
function cashWriteBody(array $changes=[]):array {
    return $changes+['request_id'=>str_repeat('a',64),'cash_money'=>'0.29','cash_bank_name'=>'Bank + branch','cash_bank_no'=>'001%20+234','cash_payee_name'=>'Ordinary name'];
}
function cashWriteState():array {
    return purchaseCsrfState()+['Cash'=>Db::name('Cash')->order('cash_id')->select()->toArray(),'CashRequest'=>Db::name('CashRequest')->order('user_id,request_id')->select()->toArray()];
}
function cashWriteToken():array {
    $cookies=purchaseCsrfCookies();$before=cashWriteState();
    $result=purchaseCsrfRoute('user/write_token',[],[],$cookies,[],'GET');
    check($result['data']['code']===1&&cashWriteState()===$before,'Token route must preserve financial and account storage');
    return [$cookies+['fixture_session'=>$result['session_id']],$result['data']['info']['csrf_token']];
}
function cashWriteDenied($target,$body,$query,$cookies,$headers=[],$method='POST',$server=[]):array {
    $before=cashWriteState();$result=purchaseCsrfRoute($target,$body,$query,$cookies,$headers,$method,$server);
    check($result['data']['code']>1&&cashWriteState()===$before,'Denied '.$target.' must preserve all users, funds, ledgers and reservations');
    return $result['data'];
}
foreach(['user/cash','cash/create'] as $target) {
    cashWriteSeed();[$cookies,$token]=cashWriteToken();
    foreach(['request_id','cash_money','cash_bank_name','cash_bank_no','cash_payee_name'] as $field) {
        $body=cashWriteBody(['csrf_token'=>$token]);unset($body[$field]);
        cashWriteDenied($target,$body,[$field=>cashWriteBody()[$field]],$cookies);
        foreach([[],null,true] as $bad)cashWriteDenied($target,cashWriteBody([$field=>$bad,'csrf_token'=>$token]),[],$cookies);
    }
    $result=purchaseCsrfRoute($target,cashWriteBody(['csrf_token'=>$token,'user_id'=>'2','cash_points'=>'1','cash_status'=>'1']),
        ['cash_money'=>'9','user_id'=>'2','csrf_token'=>'wrong'],$cookies);
    check($result['data']['code']===1,'Expected routed cash creation: '.json_encode($result['data']));
    $cash=Db::name('Cash')->order('cash_id')->find();$user=Db::name('User')->where('user_id',1)->find();
    check($result['data']['code']===1&&(int)$cash['user_id']===1&&(int)$cash['cash_status']===0
        &&(int)$cash['cash_points']===29&&(int)$user['user_points']===71&&(int)$user['user_points_froze']===29,
        'Real '.$target.' must bind body money and server-calculated points to its authenticated owner');
    check($cash['cash_bank_no']==='001%20+234','Routed form fields must retain already-decoded literal characters');
}
foreach(['user/cash','cash/create','user/cash_del','cash/del'] as $target) {
    cashWriteSeed();[$cookies,$token]=cashWriteToken();
    $delete=str_ends_with($target,'del');
    $body=$delete?['all'=>'1']:cashWriteBody();
    foreach([[[],[]],[[],['csrf_token'=>$token]],[['csrf_token'=>[]],[]],[['csrf_token'=>'wrong'],[]]] as [$fields,$query]) {
        $result=cashWriteDenied($target,$fields+$body,$query,$cookies);
        check($result['code']===1403,'Browser cash writes require a session-bound POST token');
    }
    cashWriteDenied($target,['csrf_token'=>$token]+$body,[],$cookies,['X-CSRF-Token'=>'wrong']);
    cashWriteDenied($target,['csrf_token'=>$token]+$body,[],purchaseCsrfCookies());
    cashWriteDenied($target,['csrf_token'=>$token]+$body,[],[]);
    cashWriteDenied($target,$body,[],$cookies,['Authorization'=>'Bearer '.purchaseCsrfBearer().'x']);
    $GLOBALS['config']['app']['api_jwt_enabled']=0;
    cashWriteDenied($target,$body,[],$cookies,['Authorization'=>'Bearer ordinary-disabled-token']);
    $GLOBALS['config']['app']['api_jwt_enabled']=1;
    foreach(['GET','PUT','PATCH','DELETE','HEAD'] as $method) {
        if($target==='user/cash'&&$method==='GET')continue; // The ordinary GET remains a read-only page; covered by user_lists.
        cashWriteDenied($target,['csrf_token'=>$token]+$body,[],$cookies,[],$method);
    }
    foreach([['GET','POST'],['POST','GET'],['PUT','POST']] as [$method,$override]) {
        cashWriteDenied($target,['csrf_token'=>$token]+$body,[],$cookies,[],$method,['HTTP_X_HTTP_METHOD_OVERRIDE'=>$override]);
    }
    cashWriteDenied($target,['_method'=>'DELETE','csrf_token'=>$token]+$body,[],$cookies);
    Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60]);
    cashWriteDenied($target,$body,[],$cookies);
    check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,'Controller ancestry cannot write expired membership before cash authorization');
    Db::name('User')->where('user_id',1)->update(['user_status'=>0]);
    cashWriteDenied($target,['csrf_token'=>$token]+$body,[],$cookies);
}
foreach(['user/cash','cash/create'] as $target) {
    cashWriteSeed();$result=purchaseCsrfRoute($target,cashWriteBody(['user_id'=>'2']),[],purchaseCsrfCookies(2),['Authorization'=>'Bearer '.purchaseCsrfBearer(1)]);
    check($result['data']['code']===1&&(int)Db::name('Cash')->value('user_id')===1,'Verified Bearer identity takes precedence over another account Cookie');
}
foreach(['user/cash_del','cash/del'] as $target) {
    cashWriteSeed();[$cookies,$token]=cashWriteToken();
    (new \app\common\model\Cash())->saveForUser(1,cashWriteBody());
    Db::name('User')->where('user_id',2)->update(['user_points'=>100]);
    (new \app\common\model\Cash())->saveForUser(2,cashWriteBody());
    $own=(string)Db::name('Cash')->where('user_id',1)->value('cash_id');$other=(string)Db::name('Cash')->where('user_id',2)->value('cash_id');
    foreach([[],['ids'=>[]],['ids'=>'-'.$own],['ids'=>$own.'%2C'.$other],['ids'=>'0'],['ids'=>'4294967296'],['ids'=>$own.','],['ids'=>'1e0'],['all'=>[]],['all'=>'true']] as $selection) {
        cashWriteDenied($target,['csrf_token'=>$token]+$selection,[],$cookies);
    }
    cashWriteDenied($target,['csrf_token'=>$token],['ids'=>$own,'all'=>'1'],$cookies);
    $before=cashWriteState();$result=purchaseCsrfRoute($target,['csrf_token'=>$token,'ids'=>$other],[],$cookies);
    check($result['data']['code']===1&&cashWriteState()===$before,'Foreign selection must never refund or remove another account reservation');
    $result=purchaseCsrfRoute($target,['csrf_token'=>$token,'ids'=>$own.','.$own],['all'=>'1','ids'=>$other],$cookies);
    check($result['data']['code']===1&&Db::name('Cash')->count()===1&&(int)Db::name('Cash')->value('user_id')===2
        &&(int)Db::name('User')->where('user_id',1)->value('user_points')===100,'Selected owner refund must happen exactly once');
    (new \app\common\model\Cash())->saveForUser(1,cashWriteBody());
    $result=purchaseCsrfRoute($target,['all'=>'1'],[],[],['Authorization'=>'Bearer '.purchaseCsrfBearer(1)]);
    check($result['data']['code']===1&&Db::name('Cash')->count()===1&&(int)Db::name('Cash')->value('user_id')===2,'Explicit delete-all must retain the authenticated owner scope');
}
echo 'framework_audit_cash_write: '.$checks.' checks passed ('.($mysql?'MySQL':'SQLite').') on PHP '.PHP_VERSION.PHP_EOL;
