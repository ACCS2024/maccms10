<?php
/** Real TP8 container/route/response contracts, with no application database or external server. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';

class MethodRouteRequest extends \app\Request { public function isCli(): bool { return false; } }
class MethodRouteProbe {
    public function action(\think\Request $request): array { return [$request->method(),$request->post('value')]; }
}
$temporary=audit_temp_dir('request-method');
try {
    mkdir($temporary.'/application');
    copy(dirname(__DIR__).'/application/provider.php',$temporary.'/application/provider.php');
    // A deployment without the ignored app symlink must still bind both request aliases.
    $app=new \app\MacApp($temporary);
    $first=$app->make('request');
    check($first instanceof \app\Request && $first===$app->make(\think\Request::class),
        'Framework request and concrete injection must resolve to the same application request without app symlink');
    $server=['REQUEST_METHOD'=>'POST','HTTP_HOST'=>'fixture.invalid','REQUEST_URI'=>'/method','PATH_INFO'=>'/method'];
    $legacy=(new \think\Request())->withServer($server)->withPost(['_method'=>['post']]);
    $reproduced=false;
    try { $legacy->method(); } catch (\TypeError $error) { $reproduced=true; }
    check($reproduced,'The regression must reproduce the installed framework failure');

    foreach (['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'] as $method) {
        $request=(new MethodRouteRequest())->withServer(array_replace($server,['REQUEST_METHOD'=>$method]));
        $app->instance('request',$request);
        check($request->method()===$method && $request->method(true)===$method,'Ordinary HTTP methods remain unchanged');
        check($app->invokeMethod([new MethodRouteProbe(),'action'])[0]===$method,
            'Typed injection must receive the same active safe request');
    }
    foreach (['get','POST','Put','PATCH','delete','unsupported',''] as $override) {
        $before=(new \think\Request())->withServer($server)->withPost(['_method'=>$override,'value'=>'kept']);
        $request=(new MethodRouteRequest())->withServer($server)->withPost(['_method'=>$override,'value'=>'kept']);
        check($request->method()===$before->method() && $request->param()===$before->param()
            && $request->method(true)==='POST','Valid method overrides retain framework parsing and body behavior');
    }
    $request=(new MethodRouteRequest())->withServer($server+['HTTP_X_HTTP_METHOD_OVERRIDE'=>'PATCH']);
    check($request->method()==='PATCH' && $request->method(true)==='POST','The existing header override remains available');
    $request=(new MethodRouteRequest())->withServer($server)->withGet(['_method'=>['put']]);
    check($request->method()==='POST','A query parameter is not a method override');
    foreach (['body','override','server'] as $source) {
        foreach ([[],['POST'],null,true,false,42,1.5] as $invalid) {
            if ($source!=='body' && $invalid===null) { continue; }
            $request=(new MethodRouteRequest())->withHeader(['accept'=>'application/json'])->withServer($server);
            if ($source==='body') { $request->withPost(['_method'=>$invalid]); }
            else { $request->withServer(array_replace($server,[$source==='server'?'REQUEST_METHOD':'HTTP_X_HTTP_METHOD_OVERRIDE'=>$invalid])); }
            $app->instance('request',$request);
            $called=0;$route=new \think\Route($app);
            $route->rule('method',static function()use(&$called){++$called;return 'unexpected';},'*');
            $response=null;
            try { $route->dispatch($request,false); }
            catch (\think\exception\HttpResponseException $error) { $response=(new \app\ExceptionHandle($app))->render($request,$error); }
            check($response instanceof \think\response\Json && $response->getCode()===400 && $called===0,
                'Malformed '.$source.' method must stop actual route dispatch before any action');
            check($response->getData()===['code'=>1001,'msg'=>'Invalid request method']
                && $response->getHeader('Cache-Control')==='private, no-store',
                'Malformed methods return only the controlled non-cacheable error, without recursive exception rendering');
        }
    }
    echo 'Request method audit: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
} finally { audit_remove_temp($temporary); }
