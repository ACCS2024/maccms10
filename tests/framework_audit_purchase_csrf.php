<?php
/** Actual routes, constructor authentication and real session persistence before financial writes. */
declare(strict_types=1);
require __DIR__.'/fixtures/purchase_csrf.php';
use think\facade\Db;
function purchaseToken(array $cookies):array{
    $before=purchaseCsrfState();$result=purchaseCsrfRoute('user/write_token',[],[],$cookies,[],'GET');
    check(($result['data']['code']??0)===1&&is_string($result['data']['info']['csrf_token']??null),'An authenticated GET must issue a real session token');
    check(purchaseCsrfState()===$before,'Token issuance must not change accounts, balances, ledgers or receipts');
    check($result['response']->getHeader('Cache-Control')==='private, no-store'&&$result['response']->getHeader('Pragma')==='no-cache'
        &&$result['response']->getHeader('Vary')==='Cookie, Authorization','A session token must have explicit private response headers');
    return [$cookies+['fixture_session'=>$result['session_id']],$result['data']['info']['csrf_token']];
}
function purchaseDenied(string $target,array $body,array $query,array $cookies,array $headers=[],string $method='POST',array $server=[]):array{
    $before=purchaseCsrfState();$reads=$GLOBALS['purchase_resource_reads'];$result=purchaseCsrfRoute($target,$body,$query,$cookies,$headers,$method,$server);
    check(($result['data']['code']??1)>1&&purchaseCsrfState()===$before&&$GLOBALS['purchase_resource_reads']===$reads,'Rejected purchase must leave all financial and account rows unchanged');
    return $result;
}
purchaseCsrfSeed();[$cookies,$token]=purchaseToken(purchaseCsrfCookies());
$again=purchaseCsrfRoute('user/write_token',[],[],$cookies,[],'GET');
check($again['data']['info']['csrf_token']===$token&&$again['session_id']===$cookies['fixture_session'],'The actual SessionInit must restore the same token across requests');
foreach(['user/ajax_buy_popedom','payment/buy_popedom']as $target){
    purchaseCsrfSeed();[$cookies,$token]=purchaseToken(purchaseCsrfCookies());
    $result=purchaseCsrfRoute($target,purchaseCsrfBody(['csrf_token'=>$token,'user_id'=>'999','ulog_points'=>'0']),
        ['mid'=>'2','id'=>'999','type'=>'1','user_id'=>'999','csrf_token'=>'wrong'],$cookies);
    check($result['data']['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===80,'Actual '.$target.' must buy using body parameters and authenticated owner');
    check(Db::name('Ulog')->count()===1&&(int)Db::name('Ulog')->value('ulog_rid')===17&&(int)Db::name('Ulog')->value('user_id')===1
        &&Db::name('Plog')->count()===4,'A successful routed purchase must create actual buyer/referral ledgers and one correct receipt');
    $state=purchaseCsrfState();$repeat=purchaseCsrfRoute($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies);
    check($repeat['data']['code']===1&&purchaseCsrfState()===$state,'Retry through the actual endpoint must not charge a second time');
}

foreach(['user/ajax_buy_popedom','payment/buy_popedom']as $target){
    purchaseCsrfSeed();[$cookies,$token]=purchaseToken(purchaseCsrfCookies());
    foreach(['mid','id','type']as $required){
        $body=purchaseCsrfBody(['csrf_token'=>$token]);unset($body[$required]);
        purchaseDenied($target,$body,[$required=>purchaseCsrfBody()[$required]],$cookies);
    }
    foreach(['mid','id','type','sid','nid']as $field){
        foreach([[],['ordinary'],null,true,1.5]as $value)purchaseDenied($target,purchaseCsrfBody([$field=>$value,'csrf_token'=>$token]),[],$cookies);
    }
    foreach([
        [[],['csrf_token'=>$token],[]],
        [[],[],['X-CSRF-Token'=>'wrong']],
        [['csrf_token'=>$token],[],['X-CSRF-Token'=>'wrong']],
        [['csrf_token'=>$token],[],['X-CSRF-Token'=>'']],
        [['csrf_token'=>$token],[],['X-CSRF-Token'=>[]]],
        [['csrf_token'=>[]],[],[]],
        [['csrf_token'=>null],[],[]],
        [['csrf_token'=>true],[],[]],
        [['csrf_token'=>'wrong'],[],[]],
    ]as [$fields,$query,$headers]){
        $result=purchaseDenied($target,purchaseCsrfBody($fields),$query,$cookies,$headers);
        check($result['data']['code']===1403,'Token errors must use the explicit authorization response');
    }
    purchaseDenied($target,purchaseCsrfBody(),[],$cookies+['csrf_token'=>$token]);
    purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],purchaseCsrfCookies());
    foreach(['GET','PUT','PATCH','DELETE','HEAD']as $method)purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies,[],$method);
    foreach([
        ['GET',[],['HTTP_X_HTTP_METHOD_OVERRIDE'=>'POST']],
        ['PUT',[],['HTTP_X_HTTP_METHOD_OVERRIDE'=>'POST']],
        ['POST',[],['HTTP_X_HTTP_METHOD_OVERRIDE'=>'GET']],
        ['POST',['_method'=>'GET'],[]],
        ['POST',['_method'=>'DELETE'],[]],
        ['GET',['_method'=>'POST'],[]],
    ]as [$method,$fields,$server])purchaseDenied($target,purchaseCsrfBody($fields+['csrf_token'=>$token]),[],$cookies,[],$method,$server);
    foreach([[],['user_id'=>'1','user_name'=>'fixture1'],['group_id'=>'3','is_member'=>'1'],
        array_replace($cookies,['user_check'=>str_repeat('0',32)]),array_replace($cookies,['user_id'=>[]])]as $credentials){
        purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$credentials);
    }
    purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies,['Authorization'=>'Bearer '.purchaseCsrfBearer().'x']);
    $GLOBALS['config']['app']['api_jwt_enabled']=0;
    $result=purchaseDenied($target,purchaseCsrfBody(),[],$cookies,['Authorization'=>'Bearer fixture-token']);
    check($result['data']['code']===1403,'A Bearer-looking header with JWT disabled must not exempt a real Cookie session from CSRF');
    purchaseDenied($target,purchaseCsrfBody(),[],[],['Authorization'=>'Bearer fixture-token']);
    $result=purchaseCsrfRoute($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies,['Authorization'=>'Bearer fixture-token']);
    check($result['data']['code']===1,'JWT-disabled deployments must retain valid Cookie plus CSRF purchases despite an ignored Bearer header');
    $GLOBALS['config']['app']['api_jwt_enabled']=1;
    $oldBearer=purchaseCsrfBearer();$oldCookies=$cookies;
    Db::name('User')->where('user_id',1)->update(['user_random'=>str_repeat('a',32)]);
    purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$oldCookies);
    purchaseDenied($target,purchaseCsrfBody(),[],[],['Authorization'=>'Bearer '.$oldBearer]);
    purchaseCsrfSeed();
    $bearer=purchaseCsrfBearer();$result=purchaseCsrfRoute($target,purchaseCsrfBody(),[],[],['Authorization'=>'Bearer '.$bearer]);
    check($result['data']['code']===1&&(int)Db::name('User')->where('user_id',1)->value('user_points')===80,
        'An enabled and actually verified Bearer may purchase without a browser CSRF token');
    purchaseCsrfSeed();
    $otherCookies=purchaseCsrfCookies(2);$bearer=purchaseCsrfBearer(1);
    $result=purchaseCsrfRoute($target,purchaseCsrfBody(['csrf_token'=>'wrong']),[],$otherCookies,['Authorization'=>'Bearer '.$bearer]);
    check($result['data']['code']===1&&(int)Db::name('Ulog')->value('user_id')===1,
        'Valid Bearer precedence must bind the purchase to its owner even with another account Cookie');
    purchaseCsrfSeed();[$cookies,$token]=purchaseToken(purchaseCsrfCookies());
    Db::name('User')->where('user_id',1)->update(['user_status'=>0]);
    purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies);
    purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60]);
    [$cookies,$token]=purchaseToken(purchaseCsrfCookies());
    purchaseDenied($target,purchaseCsrfBody(),[],$cookies);
    purchaseDenied($target,purchaseCsrfBody(['mid'=>[],'csrf_token'=>$token]),[],$cookies);
    purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies,[],'GET');
    check((int)Db::name('User')->where('user_id',1)->value('group_id')===3,
        'Actual protected controller ancestry must not persist an expired membership downgrade before a rejected purchase');
    $result=purchaseCsrfRoute($target,purchaseCsrfBody(['csrf_token'=>'wrong']),[],$cookies,['X-CSRF-Token'=>$token]);
    check($result['data']['code']===1&&(int)Db::name('User')->where('user_id',1)->value('group_id')===3,
        'A valid header must take priority over body token while successful purchase leaves expired-group storage to its normal lifecycle');
}
purchaseCsrfSeed();
foreach([[],['user_id'=>'1','user_name'=>'fixture1'],['user_id'=>'1','user_name'=>'fixture1','user_check'=>'wrong']]as $cookies){
    $before=purchaseCsrfState();$result=purchaseCsrfRoute('user/write_token',[],[],$cookies,[],'GET');
    check($result['data']['code']>1&&!isset($result['data']['info']['csrf_token'])&&purchaseCsrfState()===$before,'Unauthenticated token GET must never issue a browser credential');
    check($result['response']->getHeader('Cache-Control')==='private, no-store','Denied token responses must also be private');
}
[$cookies,$token]=purchaseToken(purchaseCsrfCookies());
foreach(['POST','HEAD','PUT']as $method)purchaseDenied('user/write_token',[],[],$cookies,[],$method);
purchaseDenied('user/write_token',['_method'=>'GET'],[],$cookies,[],'POST');
purchaseDenied('user/write_token',[],[],$cookies,[],'GET',['HTTP_X_HTTP_METHOD_OVERRIDE'=>'POST']);
$session=\think\Container::getInstance()->make('session');$session->set('__csrf_token__',['old-invalid-state']);$session->save();
$result=purchaseCsrfRoute('user/write_token',[],[],$cookies,[],'GET');
check($result['data']['code']===1&&is_string($result['data']['info']['csrf_token'])&&$result['data']['info']['csrf_token']!==$token,
    'Malformed persisted session state must be replaced by a new usable server token');
purchaseCsrfSeed();[$staleCookies,$staleToken]=purchaseToken(purchaseCsrfCookies());$staleBearer=purchaseCsrfBearer();
Db::name('User')->where('user_id',1)->update(['user_random'=>str_repeat('b',32)]);
purchaseDenied('user/write_token',[],[],$staleCookies,[],'GET');
purchaseDenied('user/write_token',[],[],[],['Authorization'=>'Bearer '.$staleBearer],'GET');
purchaseCsrfSeed();Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60]);
[$cookies,$token]=purchaseToken(purchaseCsrfCookies());$before=purchaseCsrfState();
$result=(new \app\common\model\User())->checkLogin(false);
check($result['code']===1&&(int)$result['info']['group_id']===2&&purchaseCsrfState()===$before,'Read-only authentication must use the expired effective group without changing storage');
$result=(new \app\common\model\User())->checkLogin();
check($result['code']===1&&(int)Db::name('User')->where('user_id',1)->value('group_id')===2,
    'Existing callers must retain the default membership-expiry persistence behavior');

foreach(['user/ajax_buy_popedom','payment/buy_popedom','user/write_token']as $target){
    purchaseCsrfSeed();[$cookies,$token]=purchaseToken(purchaseCsrfCookies());
    foreach([[],['ordinary'],null,true,3]as $method){
        $result=purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token,'_method'=>$method]),[],$cookies);
        check($result['response']->getCode()===400,'Structured method override must use production Request controlled HTTP 400');
    }
    foreach([[],true,3]as $method){
        foreach(['REQUEST_METHOD','HTTP_X_HTTP_METHOD_OVERRIDE']as $name){
            $result=purchaseDenied($target,purchaseCsrfBody(['csrf_token'=>$token]),[],$cookies,[],'POST',[$name=>$method]);
            check($result['response']->getCode()===400,'Invalid transport method type must be rejected before normal route dispatch');
        }
    }
}
fwrite(STDOUT,'Purchase CSRF route audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
