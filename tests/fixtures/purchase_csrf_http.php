<?php
/** Loopback-only router with persistent disposable SQLite and the production Request/Session/controllers. */
declare(strict_types=1);
if(PHP_SAPI!=='cli-server'||!in_array($_SERVER['REMOTE_ADDR']??'', ['127.0.0.1','::1'],true))throw new RuntimeException('Use the local isolated PHP server');
$source=dirname(__DIR__,2);$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if($path==='/health'){echo 'ready';exit;}
if($path==='/jquery.js'){header('Content-Type: application/javascript');readfile($source.'/static/js/jquery.js');exit;}
if($path==='/fixture/client.js'){
    $client=$_GET['client']??'';
    if(!is_string($client)||!preg_match('/^[0-5]$/D',$client)){http_response_code(404);exit;}
    header('Content-Type: application/javascript');readfile(getcwd().'/client-'.$client.'.js');exit;
}
putenv('PURCHASE_CSRF_MYSQL=0');define('PURCHASE_CSRF_HTTP',true);
require __DIR__.'/purchase_csrf.php';
function url($route){return '/fixture/index.php/'.$route;}
if($path==='/fixture/reset'&&$_SERVER['REQUEST_METHOD']==='POST'){
    purchaseCsrfSeed();if(($_POST['balance']??'')==='10')\think\facade\Db::name('User')->where('user_id',1)->update(['user_points'=>10]);header('Content-Type: application/json');echo '{"code":1}';exit;
}
if($path==='/fixture/state'){
    header('Content-Type: application/json');echo json_encode(['balance'=>(int)\think\facade\Db::name('User')->where('user_id',1)->value('user_points'),
        'receipts'=>\think\facade\Db::name('Ulog')->count(),'ledgers'=>\think\facade\Db::name('Plog')->count(),
        'owner'=>(int)\think\facade\Db::name('Ulog')->value('user_id')],JSON_THROW_ON_ERROR);exit;
}
if($path==='/fixture/page'){
    if(!\think\facade\Db::name('User')->count())purchaseCsrfSeed();
    foreach(purchaseCsrfCookies()as $name=>$value)setcookie($name,$value,['path'=>'/','httponly'=>true,'samesite'=>'Lax']);
    $client=is_string($_GET['client']??null)&&preg_match('/^[0-5]$/D',$_GET['client'])?$_GET['client']:'0';
    header('Content-Type: text/html; charset=utf-8');header('Cache-Control: private, no-store');
    echo '<!doctype html><meta charset="utf-8"><script src="/jquery.js"></script><script src="/fixture/client.js?client='.$client.'"></script>';
    if(($_GET['gate']??'')==='1'){
        (new \think\Template(['cache_path'=>getcwd().'/templates/']))->display(file_get_contents($source.'/template/default/html/widget/popedom_upgrade_gate.html'),
            ['maccms'=>['path'=>'/fixture/','path_tpl'=>'/fixture/template/default','mid'=>12],
                'obj'=>['manga_id'=>17],'param'=>['sid'=>2,'nid'=>3],'popedom'=>['points'=>20]]);
    }else{
        echo '<button id="purchase" onclick="MAC.User.BuyPopedom(this)" data-mid="1" data-id="17" data-type="4" data-sid="2" data-nid="3">Buy</button>';
    }
    echo '<script>$(function(){window.fixtureReady=true});</script>';exit;
}
if(!preg_match('~^/fixture/(index|api)\.php/(user/(?:write_token|ajax_buy_popedom)|payment/buy_popedom)(?:\.html)?$~',$path,$match)){
    http_response_code(404);exit;
}
$server=$_SERVER;$server['SCRIPT_NAME']='/fixture/'.$match[1].'.php';$server['SCRIPT_FILENAME']='/isolated/'.$match[1].'.php';$server['PATH_INFO']='/'.$match[2];
$before=purchaseCsrfState();
$result=purchaseCsrfRoute($match[2],$_POST,$_GET,$_COOKIE,getallheaders(),$_SERVER['REQUEST_METHOD'],$server);
$response=$result['response'];
$response->header(['X-Audit-Unchanged'=>purchaseCsrfState()===$before?'yes':'no',
    'X-Audit-Balance'=>(string)\think\facade\Db::name('User')->where('user_id',1)->value('user_points'),
    'X-Audit-Receipts'=>(string)\think\facade\Db::name('Ulog')->count()]);
$response->send();
