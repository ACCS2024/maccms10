<?php
/** Loopback fixture uses actual native setcookie and PHP's HTTP Cookie parsing. */
declare(strict_types=1);
define('MEMBER_COOKIE_HTTP',true);
require __DIR__.'/member_cookie.php';
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if($path==='/health'){$result=['code'=>1];}
elseif($path==='/signin'&&request()->method(true)==='POST'){$result=(new \app\common\model\User())->login(request()->post());}
elseif($path==='/identity'){
    $response=(new \app\common\model\User())->checkLogin(false);$result=['code'=>$response['code']];
    if($result['code']===1)$result+=['user_id'=>$response['info']['user_id'],'user_name'=>$response['info']['user_name']];
}else{http_response_code(404);$result=['code'=>1001];}
header('Content-Type: application/json');header('X-Audit-Write-Count: '.$GLOBALS['member_cookie_writes']);$app->cookie->save();echo json_encode($result,JSON_THROW_ON_ERROR);
