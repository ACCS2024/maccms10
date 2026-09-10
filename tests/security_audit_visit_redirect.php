<?php
/** Real TP8 request/redirect and reward model; isolate only the frontend constructor/rendering. */
declare(strict_types=1);
namespace app\index\controller { class Base {} }
namespace {
    require __DIR__.'/fixtures/security_audit_visit_db.php';
    $app = new \think\App(audit_temp_dir('visit-redirect'));
    $app->instance('think\\DbManager',$manager);
    $app->config->set($configuration,'database');
    $app->instance('cache',new \MembershipAuditCache());
    function redirect($url) { return \think\Response::create($url,'redirect',302); }
    $controller = (new \ReflectionClass(\app\index\controller\User::class))->newInstanceWithoutConstructor();
    $targets = [
        ['/watch?id=1#part','/watch?id=1#part'],
        ['http://fixture.example/watch?id=1#part','/watch?id=1#part'],
        ['HTTP://FIXTURE.EXAMPLE:80/watch','/watch'],
        ['http://fixture.example?x=1','/?x=1'],
        [null,'/'], [[], '/'], [1,'/'], ['', '/'],
        ['https://other.example/watch','/'], ['//other.example/watch','/'],
        ['http://fixture.example:8000/watch','/'], ['https://fixture.example/watch','/'],
        ['http://fixture.example@other.example/watch','/'], ['http://user@fixture.example/watch','/'],
        ['http://fixture.example//other.example/watch','/'], ["/\\other.example",'/'],
        ["/watch\r\nextra",'/'], ["\t/watch",'/'], ['javascript:fixture','/'],
        ['http://fixture.example:99999/watch','/'], [str_repeat('a',4097),'/'],
    ];
    foreach ($targets as [$target,$expected]) {
        visitSeed();
        $request = (new \think\Request())->withServer(['REQUEST_METHOD'=>'GET','HTTP_HOST'=>'fixture.example',
            'SERVER_PORT'=>'80','REQUEST_URI'=>'/index.php/user/visit','SCRIPT_NAME'=>'/index.php'])
            ->withGet(['uid'=>'1','url'=>$target]);
        \think\Container::getInstance()->instance('request',$request);
        $response = $controller->visit();
        check($response->getCode() === 302 && $response->getHeader('Location') === $expected,
            'Visit did not return a controlled local destination: '.json_encode($target));
        check(memberRow()['user_points'] === 120 && \think\facade\Db::name('Visit')->count() === 1
            && \think\facade\Db::name('Plog')->count() === 1, 'Redirect handling interrupted a normal visit reward');
    }
    foreach ([['fixture.example:8080','http://fixture.example:8080/watch','/watch'],
        ['fixture.example:8080','http://fixture.example/watch','/'],
        ['[::1]:8080','http://[::1]:8080/watch','/watch']] as [$host,$target,$expected]) {
        visitSeed();
        $request = (new \think\Request())->withServer(['REQUEST_METHOD'=>'GET','HTTP_HOST'=>$host,'SERVER_PORT'=>'8080'])
            ->withGet(['uid'=>'1','url'=>$target]);
        \think\Container::getInstance()->instance('request',$request);
        $actual = $controller->visit()->getHeader('Location');
        check($actual === $expected, 'Explicit port or bracketed host changed the origin check: '.$host.' '.$request->domain(true).' '.$actual);
    }
    echo "visit redirect audit: $checks checks passed on PHP ".PHP_VERSION."\n";
}
