<?php
/** Authenticated cash reads and public exact configuration through real routes and installed tables. */
declare(strict_types=1);
define('CASH_WRITE_AUDIT',true);
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
class CashApiReadFixture extends \app\api\controller\Cash { protected function assign($name,$value=''):void{} }
$app->bind(\app\api\controller\Cash::class,CashApiReadFixture::class);
purchaseCsrfSeed();
$GLOBALS['config']['user']+=['cash_status'=>1,'cash_ratio'=>'0.5','cash_min'=>'0.29'];
$app->config->set($GLOBALS['config'],'maccms');$cash=new \app\common\model\Cash();
Db::name('User')->whereIn('user_id',[1,2])->update(['user_points'=>100]);
foreach([1,1,2] as $owner) {
    check($cash->saveForUser($owner,['cash_money'=>'1.01','cash_bank_name'=>'Read bank','cash_bank_no'=>'123','cash_payee_name'=>'Read name'])['code']===1,'API read fixture must reserve funds through the real model');
}
$ids=Db::name('Cash')->order('cash_id')->column('cash_id');
check($cash->auditData(['cash_id'=>$ids[0]])['code']===1,'API read fixture must settle the approved row');
function cashApiReadState():array {
    return purchaseCsrfState()+['cash'=>Db::name('Cash')->order('cash_id')->select()->toArray(),
        'history'=>Db::name('CashHistory')->order('cash_id')->select()->toArray(),
        'requests'=>Db::name('CashRequest')->order('user_id,request_id')->select()->toArray()];
}
$cookies=purchaseCsrfCookies();$before=cashApiReadState();
foreach([[],['status'=>'0'],['status'=>'1'],['limit'=>'1','page'=>'2'],['user_id'=>2,'uid'=>2,'archive'=>1]] as $query) {
    $result=purchaseCsrfRoute('cash/get_list',['user_id'=>2],$query,$cookies,[],'GET')['data'];
    check($result['code']===1&&cashApiReadState()===$before,'GET list must preserve all account and financial data');
    $expected=isset($query['status'])||isset($query['limit'])?1:2;
    check(count($result['info']['list'])===$expected&&array_unique(array_map('intval',array_column($result['info']['list'],'user_id'))) === [1],'List filters cannot expand the verified account scope');
    check(!str_contains(json_encode($result),'user_random')&&!str_contains(json_encode($result),'user_pwd'),'Identity credentials cannot appear in financial read responses');
}
$result=purchaseCsrfRoute('cash/get_list',[],[],purchaseCsrfCookies(2),['Authorization'=>'Bearer '.purchaseCsrfBearer(1)],'GET')['data'];
check($result['code']===1&&$result['info']['total']===2,'Enabled verified Bearer identity must take precedence over another account Cookie');
$result=purchaseCsrfRoute('cash/get_detail',[],['cash_id'=>$ids[0],'user_id'=>2],$cookies,[],'GET')['data'];
check($result['code']===1&&(int)$result['info']['user_id']===1,'Detail must return the requested owner record');
check(purchaseCsrfRoute('cash/get_detail',[],['cash_id'=>$ids[2]],$cookies,[],'GET')['data']['code']!==1,'Detail cannot reveal another account withdrawal');
foreach(['get_list'=>[],'get_detail'=>['cash_id'=>$ids[0]]] as $action=>$valid) {
    foreach([[[],[]],[$cookies,['Authorization'=>'Bearer invalid']],[$cookies,['Authorization'=>'Bearer '.purchaseCsrfBearer().'x']]] as [$credential,$headers]) {
        check(purchaseCsrfRoute('cash/'.$action,[],$valid,$credential,$headers,'GET')['data']['code']!==1,'Private cash read requires verified current identity');
    }
    foreach(['POST','PUT','PATCH','DELETE','HEAD'] as $method) {
        check(purchaseCsrfRoute('cash/'.$action,$valid,$valid,$cookies,[],$method)['data']['code']===1001,'Only the documented native GET can query private cash records');
    }
    check(purchaseCsrfRoute('cash/'.$action,[],$valid,$cookies,[],'GET',['HTTP_X_HTTP_METHOD_OVERRIDE'=>'POST'])['data']['code']===1001,'Effective method overrides cannot bypass GET semantics');
}
foreach(['page'=>[[],null,true,false,0,-1,'1e2','1.2','4294967295'],'limit'=>[[],null,true,0,101,'1e2'],'status'=>[[],null,true,2,'01']] as $field=>$values) {
    foreach($values as $value)check(purchaseCsrfRoute('cash/get_list',[],[$field=>$value],$cookies,[],'GET')['data']['code']===1001,'Malformed list fields must return a controlled parameter error');
}
foreach([[],null,true,0,-1,'1.0','1e0','4294967296'] as $value) {
    check(purchaseCsrfRoute('cash/get_detail',['cash_id'=>$ids[0]],['cash_id'=>$value],$cookies,[],'GET')['data']['code']===1001,'Malformed detail identity cannot be repaired from a request body');
}
Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60]);$before=cashApiReadState();
foreach(['get_list'=>[],'get_detail'=>['cash_id'=>$ids[0]]] as $action=>$query) {
    check(purchaseCsrfRoute('cash/'.$action,[],$query,$cookies,[],'GET')['data']['code']===1&&cashApiReadState()===$before,'Read identity refresh must not persist expired membership changes');
}
Db::name('User')->where('user_id',1)->update(['user_status'=>0]);$before=cashApiReadState();
check(purchaseCsrfRoute('cash/get_list',[],[],$cookies,[],'GET')['data']['code']!==1&&cashApiReadState()===$before,'A disabled member loses cash read access immediately');

// Public configuration retains numeric fields and adds exact decimal strings.
$settings=$GLOBALS['config']['user'];
foreach([['0.5','0.29','0.5','0.29'],['000100.000','0','100','0.00'],['0.00000001',null,'0.00000001','0.00'],
    ['9999999999.99999999','9999999999.99','9999999999.99999999','9999999999.99']] as [$rate,$minimum,$exactRate,$exactMinimum]) {
    $GLOBALS['config']['user']=array_replace($settings,['cash_ratio'=>$rate,'cash_min'=>$minimum]);
    $result=purchaseCsrfRoute('cash/get_config',[],[],[],[],'GET')['data'];
    check($result['code']===1&&$result['info']['cash_ratio_decimal']===$exactRate&&$result['info']['cash_min_decimal']===$exactMinimum,'Public configuration must preserve exact configured decimal values');
    check($result['info']['cash_ratio']===(str_contains($exactRate,'.')?(float)$exactRate:(int)$exactRate),'Legacy numeric rate must retain the fractional component');
}
foreach(['cash_ratio'=>[[],null,true,0,'1e2',INF],'cash_min'=>[[],true,-1,'0.001',INF],'cash_status'=>[[],null,true,2]] as $field=>$values) {
    foreach($values as $value) {
        $GLOBALS['config']['user']=array_replace($settings,[$field=>$value]);
        check(purchaseCsrfRoute('cash/get_config',[],[],[],[],'GET')['data']['code']===1001,'Invalid rule configuration cannot be coerced to a plausible number');
    }
}
$GLOBALS['config']['user']=false;
check(purchaseCsrfRoute('cash/get_config',[],[],[],[],'GET')['data']['code']===1001,'Malformed configuration container must fail without a PHP diagnostic');
$GLOBALS['config']['user']=$settings;
check(purchaseCsrfRoute('cash/get_config',[],[],[],[],'POST')['data']['code']===1001,'Public configuration also uses the documented GET method');
Db::name('User')->where('user_id',1)->update(['user_status'=>1]);
Db::execute('DROP TABLE audit_cash');
foreach(['get_list'=>[],'get_detail'=>['cash_id'=>$ids[0]]] as $action=>$query) {
    $result=purchaseCsrfRoute('cash/'.$action,[],$query,$cookies,[],'GET')['data'];
    check($result['code']!==1&&!isset($result['info']),'Unavailable financial storage cannot become a successful empty API response');
}
echo 'Cash API reads: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
