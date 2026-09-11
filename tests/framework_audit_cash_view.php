<?php
/** Render both shipped cash pages with valid, zero and malformed balances/configuration. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\CashView;
use app\common\util\OrderAmount;
function url($route,$params=[]){return '/fixture/index.php/'.$route;}
function lang($name){return $name;}
function mac_url_img($value){return $value;}
function mac_default($value,$default){return $value?:$default;}
$temp=audit_temp_dir('cash-view');register_shutdown_function(static fn()=>audit_remove_temp($temp));
foreach([[1,3,'0.33'],[1,'0.5','2.00'],[0,1,'0.00'],[65535,100,'655.35'],[100000,1,'65535.00'],
    [65535,'0.33333333','196605.00'],[1,'0.00000001','100000000.00'],[4294967295,'0.00000001','9999999999.99']] as [$points,$rate,$expected]) {
    $maximum=CashView::maximumMoney($points,$rate);check($maximum===$expected,'Displayed maximum must match the actual fractional debit and per-request limits');
    if($maximum!=='0.00')check(OrderAmount::withdrawal($maximum,$rate)['order_points']<=min($points,65535),'Displayed amount must be payable with the available whole points');
    $minor=OrderAmount::minorUnits($maximum,true);
    if($minor<OrderAmount::MAX_MINOR){$next=OrderAmount::withdrawal(OrderAmount::decimal($minor+1),$rate);check($next===null||$next['order_points']>min($points,65535),'One cent beyond the displayed limit must exceed the available points');}
}
foreach([null,[],false,0,'0','1e2','invalid',INF] as $rate)check(CashView::maximumMoney(100,$rate)===null,'Invalid/zero rate must not reach template division');
foreach([null,[],true,-1,'4294967296'] as $points)check(CashView::maximumMoney($points,100)===null,'Invalid balance must not be coerced into a displayable allowance');
$files=['template/default/html/user/cash.html','template/m1938pc3_v2/html9/user/cash.html'];
foreach($files as $file) {
    $source=file_get_contents(dirname(__DIR__).'/'.$file);
    $source=preg_replace('/\{include\b[^}]*\}/','',$source);
    foreach([
        [['cash_status'=>1,'cash_ratio'=>100,'cash_min'=>1],['user_points'=>1000,'user_points_froze'=>50],'10.00'],
        [['cash_status'=>1,'cash_ratio'=>100,'cash_min'=>1],['user_points'=>0,'user_points_froze'=>0],'0.00'],
        [['cash_status'=>1,'cash_ratio'=>0,'cash_min'=>[]],['user_points'=>[],'user_points_froze'=>[]],'--'],
        [[],[],'--'],
    ] as [$settings,$user,$maximum]) {
        $GLOBALS['config']=['user'=>$settings];$GLOBALS['user']=$user;
        $data=['cash_view'=>CashView::data($settings,$user),'maccms'=>['path'=>'/fixture/','path_tpl'=>'/fixture/template/default','site_name'=>'Fixture'],
            'obj'=>['user_id'=>1,'user_name'=>'Ordinary member','user_portrait'=>'','group'=>['group_name'=>'Registered']], 'list'=>[],
            '__PAGING__'=>['record_total'=>0,'page_url'=>'/fixture/page/PAGELINK','page_prev'=>1,'page_next'=>1,'page_current'=>1,'page_total'=>1,'page_num'=>[]]];
        $engine=new \think\Template(['cache_path'=>$temp.'/']);ob_start();
        try{$engine->display($source,$data);$html=ob_get_contents();}finally{ob_end_clean();}
        check($data['cash_view']['maximum']===$maximum&&str_contains($html,$maximum),'Actual '.$file.' must display the bounded single-request allowance without PHP diagnostics');
        check(str_contains($html,'model/cash/rounding_hint')&&str_contains($html,'model/cash/maximum_money'),'Both actual templates must disclose their rounding and single-request scope');
        if(($user['user_points']??null)===0)check(preg_match('/剩余\s*0/u',strip_tags($html))===1&&preg_match('/冻结\s*0/u',strip_tags($html))===1,'Valid zero balances must remain visible as zero');
        check(str_contains($html,'/fixture/static/js/cash-write.js')&&str_contains($html,'/fixture/cash-request-1')
            &&str_contains($html,'/fixture/index.php/user/write_token'),'Rendered cash pages must wire the actual token, write helper and account-scoped pending key');
    }
}
check(CashView::data(['cash_status'=>1,'cash_ratio'=>100,'cash_min'=>2],['user_points'=>100])['maximum']==='0.00','Balance below the configured minimum must not show a feasible withdrawal');
echo 'Cash display: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
