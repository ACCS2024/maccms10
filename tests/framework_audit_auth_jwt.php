<?php
/** Actual JWT route, signed tokens and User authentication; no external account or signing key is used. */
declare(strict_types=1);
namespace app\common\model {
    function captcha_check($value) { $GLOBALS['jwt_captcha_calls'][]=$value; return $value==='fixture-captcha'; }
    class Group { public function getCache(...$args) { return [2=>['group_id'=>2,'group_name'=>'Member','group_type'=>'']]; } }
}
namespace app\api\controller { class Base { public function __construct() {} } }
namespace {
    require __DIR__.'/fixtures/framework_audit_user_registration.php';
    function json($data) { return \think\Response::create($data,'json'); }
    function cookie($name,...$args) {
        if ($args!==[]) { throw new \RuntimeException('JWT signing must never set browser cookies'); }
        return null;
    }
    class JwtHttpRequest extends \think\Request { public function isCli(): bool { return false; } }
    $app->instance(\think\exception\Handle::class,new class($app) extends \think\exception\Handle {
        public function render(\think\Request $request, \Throwable $error): \think\Response { throw $error; }
    });
    function jwtSeed(array $userConfig=[],array $jwtConfig=[],array $account=[]): void {
        registrationFixtureSeed($userConfig);
        $GLOBALS['config']['app']=array_replace($GLOBALS['config']['app'],$jwtConfig);
        $GLOBALS['jwt_captcha_calls']=[];
        \think\facade\Db::name('User')->insert($account+['user_id'=>400,'user_name'=>'FixtureUser','user_status'=>1,'group_id'=>'2',
            'user_pwd'=>mac_password_hash('fixture+raw%42&password'),'user_random'=>str_repeat('a',32)]);
    }
    function jwtParam(array $values=[]): array { return $values+['user_name'=>'FixtureUser','user_pwd'=>'fixture+raw%42&password','verify'=>'fixture-captcha']; }
    function jwtRoute(array $body=[],array $query=[],string $method='POST',array $headers=[]): array {
        global $app;
        $app->setNamespace('app\\api'); $app->config->set([],'route');
        $request=(new JwtHttpRequest())->withServer(['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid',
            'SCRIPT_NAME'=>'/api.php','SCRIPT_FILENAME'=>'/isolated/api.php','PATH_INFO'=>'/auth/jwt','REQUEST_URI'=>'/api.php/auth/jwt'])
            ->withPost($body)->withGet($query)->withHeader($headers);
        $app->instance('request',$request);
        $response=(new \think\Route($app))->dispatch($request,false);
        check($response instanceof \think\response\Json && $response->getCode()===200,'JWT route must return a controlled JSON response through actual TP8 dispatch');
        return $response->getData();
    }
    function jwtReject(array $body,array $query,string $label,string $method='POST'): void {
        $before=registrationFixtureState(); $result=jwtRoute($body,$query,$method);
        check(($result['code']??1)>1 && !isset($result['info']['access_token']) && registrationFixtureState()===$before,$label);
    }
    function jwtAuthenticate(string $token): array {
        global $app;
        $app->instance('request',(new JwtHttpRequest())->withHeader(['authorization'=>'Bearer '.$token]));
        return (new \app\common\model\User())->checkLogin();
    }
    jwtSeed();
    $result=jwtRoute(jwtParam(),['user_name'=>'OtherFixture','user_pwd'=>'different-password','verify'=>'wrong']);
    check($result['code']===1 && $result['info']['token_type']==='Bearer','Normal POST credentials must issue a real bearer token without query overrides');
    $token=$result['info']['access_token']; $claims=\app\common\util\JwtService::decodeAndVerify($token);
    $row=\think\facade\Db::name('User')->where('user_id',400)->find();
    check($claims['sub']==='400' && $claims['rnd']===$row['user_random'] && $claims['rnd']!==str_repeat('a',32)
        && $claims['exp']-$claims['iat']===$result['info']['expires_in'],'Issued token claims must match the newly committed login session and configured TTL');
    check(jwtAuthenticate($token)['code']===1,'The issued token must authenticate through the real User JWT path');
    check(array_keys($result['info'])===['token_type','access_token','expires_in'] && !isset($claims['user_pwd']),
        'JWT response must expose only its token contract and omit the password');
    $second=jwtRoute(jwtParam())['info']['access_token'];
    check(jwtAuthenticate($second)['code']===1 && jwtAuthenticate($token)['code']>1,'A new successful JWT login must revoke the previous session token');
    foreach (['GET','PUT','DELETE'] as $method) { jwtSeed(); jwtReject([],jwtParam(),'Only POST may create a JWT session',$method); }
    foreach (['user_name','user_pwd'] as $missing) {
        jwtSeed(); $body=jwtParam(); unset($body[$missing]);
        jwtReject($body,[$missing=>jwtParam()[$missing]],'Query strings cannot supply a required missing '.$missing);
    }
    foreach (['user_name','user_pwd','verify'] as $field) {
        foreach ([[],['ordinary-value'],null,true,1.5,123456] as $invalid) {
            jwtSeed(); jwtReject(jwtParam([$field=>$invalid]),[],'Malformed JWT '.$field.' must not rotate a session or issue a token');
        }
    }
    foreach (['wrong-password',"fixture\0password",str_repeat('p',4097)] as $invalid) {
        jwtSeed(); jwtReject(jwtParam(['user_pwd'=>$invalid]),[],'Invalid password bytes must fail without login mutations');
    }
    jwtSeed(['login_verify'=>1]);
    jwtReject(jwtParam(['verify'=>'']),['verify'=>'fixture-captcha'],'A query captcha cannot satisfy the login challenge');
    jwtReject(jwtParam(['verify'=>'wrong']),[],'A wrong body captcha cannot issue a token');
    $result=jwtRoute(jwtParam(),['verify'=>'wrong']);
    check($result['code']===1 && jwtAuthenticate($result['info']['access_token'])['code']===1,'A correct body captcha must complete normal JWT login');
    check($GLOBALS['jwt_captcha_calls']===['','wrong','fixture-captcha'],'The actual login challenge must receive only POST values');
    foreach (['md5','formatted_md5'] as $legacy) {
        $password='fixture+raw%42&password';
        jwtSeed([],[],['user_pwd'=>md5($legacy==='md5'?$password:htmlspecialchars(urldecode($password)))]);
        $result=jwtRoute(jwtParam());
        check($result['code']===1 && password_verify($password,\think\facade\Db::name('User')->where('user_id',400)->value('user_pwd')),
            'JWT login must retain supported legacy-password upgrade behavior');
    }
    jwtSeed([],[],['user_status'=>0]); jwtReject(jwtParam(),[],'An unavailable account cannot obtain a JWT');
    jwtSeed(); $GLOBALS['registration_fixture_throttle']=false; jwtReject(jwtParam(),[],'JWT login must use the shared login write throttle');
    jwtSeed(); $GLOBALS['registration_fixture_ip']=[]; jwtReject(jwtParam(),[],'An unrepresentable login address must not produce a partially valid token');
    foreach ([['api_jwt_enabled'=>0],['api_jwt_enabled'=>[]],['api_jwt_enabled'=>null],['api_jwt_secret'=>'short'],
        ['api_jwt_secret'=>[]],['api_jwt_secret'=>null],['api_jwt_iss'=>[]],['api_jwt_iss'=>null],['api_jwt_iss'=>"issuer\xff"],
        ['api_jwt_ttl'=>[]],['api_jwt_ttl'=>null],['api_jwt_ttl'=>'invalid'],['api_jwt_ttl'=>true]] as $bad) {
        jwtSeed([],$bad,['user_pwd'=>md5('fixture+raw%42&password')]);
        jwtReject(jwtParam(),[],'Unavailable or malformed JWT configuration must fail before password upgrade or session rotation');
    }
    foreach ([0=>300,120=>300,3600=>3600,9999999=>2592000] as $configured=>$expected) {
        jwtSeed([],['api_jwt_ttl'=>$configured,'api_jwt_iss'=>'fixture-issuer']);
        $result=jwtRoute(jwtParam()); $claims=\app\common\util\JwtService::decodeAndVerify($result['info']['access_token']);
        check($result['info']['expires_in']===$expected && $claims['exp']-$claims['iat']===$expected && $claims['iss']==='fixture-issuer',
            'Valid JWT settings must retain existing TTL bounds and issuer behavior');
    }
    foreach (['i','界','"'] as $unit) {
        $low=1; $high=8193;
        while ($low+1<$high) {
            $middle=intdiv($low+$high,2);
            $GLOBALS['config']['app']['api_jwt_iss']=str_repeat($unit,$middle);
            $preview=\app\common\util\JwtService::encode(4294967295,str_repeat('0',32));
            if (\app\common\util\JwtService::decodeAndVerify($preview)!==null) { $low=$middle; } else { $high=$middle; }
        }
        jwtSeed([],['api_jwt_iss'=>str_repeat($unit,$low)]);
        $result=jwtRoute(jwtParam());
        check($result['code']===1 && strlen($result['info']['access_token'])<=8192
            && jwtAuthenticate($result['info']['access_token'])['code']===1,
            'The largest usable issuer must remain supported, including JSON escaping');
        jwtSeed([],['api_jwt_iss'=>str_repeat($unit,$high)],['user_pwd'=>md5('fixture+raw%42&password')]);
        jwtReject(jwtParam(),[],'An oversized encoded JWT must fail before upgrading a password or rotating its session');
    }
    jwtSeed();
    $result=jwtRoute(jwtParam(['user_id'=>'401','openid'=>'fixture-provider','col'=>'user_openid_qq','trusted_oauth'=>true,'return_meta'=>true]));
    check($result['code']===1 && \app\common\util\JwtService::decodeAndVerify($result['info']['access_token'])['sub']==='400',
        'Normal form extras cannot select another account or grant a provider login exemption');
    jwtSeed([],[],['user_pwd'=>md5('fixture+raw%42&password')]);
    $body=$mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated JWT login write fault'"
        :"BEGIN SELECT RAISE(ABORT, 'Isolated JWT login write fault'); END";
    \think\facade\Db::execute('CREATE TRIGGER audit_jwt_write_failure BEFORE UPDATE ON audit_user '.$body);
    try { jwtReject(jwtParam(),[],'A database login fault must preserve both the old password and session and return no token'); }
    finally { \think\facade\Db::execute('DROP TRIGGER audit_jwt_write_failure'); }
    check(jwtRoute(jwtParam())['code']===1,'A normal JWT retry must work after removing the isolated database fault');
    fwrite(STDOUT,'JWT endpoint audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
}
