<?php
/** Documented recovery aliases through the actual API, real Msg/User storage and isolated delivery. */
declare(strict_types=1);
namespace app\api\controller { class Base { public function __construct() {} } }
namespace {
    require __DIR__.'/fixtures/framework_audit_user_messages.php';
    function json($data) { return \think\Response::create($data,'json'); }
    class RecoveryApiRequest extends \think\Request { public function isCli(): bool { return false; } }
    $app->instance(\think\exception\Handle::class,new class($app) extends \think\exception\Handle {
        public function render(\think\Request $request, \Throwable $error): \think\Response { throw $error; }
    });
    function recoveryApiSeed(): void {
        messageFixtureSeed();
        $GLOBALS['config']['api']['publicapi']=['status'=>1,'charge'=>0];
        $GLOBALS['user']=['user_id'=>0,'user_name'=>''];
    }
    function recoveryApiRoute(array $body=[],array $query=[],string $method='POST'): array {
        global $app;
        $app->setNamespace('app\\api'); $app->config->set([],'route');
        $request=(new RecoveryApiRequest())->withServer(['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid',
            'SCRIPT_NAME'=>'/api.php','SCRIPT_FILENAME'=>'/isolated/api.php','PATH_INFO'=>'/user/find_password','REQUEST_URI'=>'/api.php/user/find_password'])
            ->withPost($body)->withGet($query);
        $app->instance('request',$request);
        $response=(new \think\Route($app))->dispatch($request,false);
        check($response instanceof \think\response\Json && $response->getCode()===200,'Recovery API must return controlled JSON through actual TP8 routing');
        return $response->getData();
    }
    function recoveryApiReject(array $body,array $query,string $label,string $method='POST'): void {
        $before=messageFixtureState(); $sent=$GLOBALS['message_fixture_deliveries'];
        $result=recoveryApiRoute($body,$query,$method);
        check(($result['code']??1)>1 && messageFixtureState()===$before && $GLOBALS['message_fixture_deliveries']===$sent,$label);
    }
    foreach (['email'=>'fixture@example.invalid','phone'=>'13000000000'] as $channel=>$target) {
        foreach ([['user_'.$channel=>$target],['user_'.$channel=>' '.$target.' '],['ac'=>$channel,'to'=>$target],
            ['user_'.$channel=>$target,'ac'=>$channel,'to'=>$target],['user_'.$channel=>$target,'ac'=>$channel],
            ['user_'.$channel=>$target,'to'=>$target]] as $body) {
            recoveryApiSeed(); $before=messageFixtureState()[0];
            check(recoveryApiRoute($body)['code']===1 && $GLOBALS['message_fixture_deliveries']===[[$channel,$target]],
                'Normal documented or canonical '.$channel.' fields must reach isolated recovery delivery');
            $messages=messageFixtureState()[1];
            check(count($messages)===1 && (int)$messages[0]['user_id']===0 && (int)$messages[0]['msg_type']===2
                && (int)$messages[0]['msg_status']===0 && $messages[0]['msg_to']===$target
                && preg_match('/^[0-9]{6}$/D',$messages[0]['msg_code'])===1 && messageFixtureState()[0]===$before,
                'Sending a recovery code must persist its exact recipient, generated code and recovery purpose without changing account credentials');
            $model=new \app\common\model\User();
            $result=$model->findpass_reset(['ac'=>$channel,'to'=>$target,'code'=>$messages[0]['msg_code'],
                'user_pwd'=>'fixture+replacement%42&','user_pwd2'=>'fixture+replacement%42&']);
            check($result['code']===1 && password_verify('fixture+replacement%42&',messageFixtureState()[0][0]['user_pwd'])
                && (int)messageFixtureState()[1][0]['msg_status']===1,'The actual generated recovery code must be accepted by the unchanged reset model');
        }
        recoveryApiSeed();
        check(recoveryApiRoute(['user_'.$channel=>$target],['user_email'=>'other@example.invalid','ac'=>'invalid','to'=>'other@example.invalid'])['code']===1
            && messageFixtureState()[1][0]['msg_to']===$target,'Query parameters cannot change a documented body recovery recipient');
        recoveryApiSeed();
        recoveryApiReject([],['user_'.$channel=>$target],'A query recipient cannot supply a missing POST body');
        foreach (['GET','PUT','DELETE'] as $method) {
            recoveryApiSeed(); recoveryApiReject([],['user_'.$channel=>$target],'Only POST may request recovery delivery',$method);
        }
        recoveryApiSeed();
        recoveryApiReject(['user_'.$channel=>$target,'ac'=>$channel==='email'?'phone':'email'],[],
            'Explicit channel conflicts must fail without sending or recording a code');
        recoveryApiReject(['user_'.$channel=>$target,'to'=>$channel==='email'?'other@example.invalid':'13100000000'],[],
            'Conflicting recipient aliases must fail without sending or recording a code');
        check(recoveryApiRoute(['user_'.$channel=>$target,'type'=>3,'user_id'=>2,'code'=>[],'openid'=>'ignored'])['code']===1
            && (int)messageFixtureState()[1][0]['msg_type']===2 && (int)messageFixtureState()[1][0]['user_id']===0,
            'Unrelated request fields cannot change recovery purpose or message identity');
        recoveryApiReject(['user_'.$channel=>$target],[],'A repeated send in the normal cooldown must not create duplicate delivery');
    }
    foreach (['user_email','user_phone','ac','to'] as $field) {
        foreach ([[],['ordinary-field'],null,true,1.5,123456] as $invalid) {
            recoveryApiSeed(); recoveryApiReject([$field=>$invalid],[],'Structured or mistyped recovery '.$field.' must be controlled before string operations');
        }
    }
    foreach ([[],['user_email'=>''],['user_phone'=>''],['ac'=>'email'],['to'=>'fixture@example.invalid'],['ac'=>'invalid','to'=>'fixture@example.invalid'],
        ['user_email'=>'fixture@example.invalid','user_phone'=>'13000000000'],['user_email'=>'not-an-email'],['user_phone'=>'not-a-phone'],
        ['user_email'=>str_repeat('a',31).'@example.invalid'],['user_phone'=>'130000000001'],
        ['user_email'=>'fixture%40example.invalid'],['user_email'=>"fixture\0@example.invalid"],
        ['ac'=>'phone','to'=>'fixture@example.invalid'],['ac'=>'email','to'=>'13000000000']] as $invalid) {
        recoveryApiSeed(); recoveryApiReject($invalid,[],'Missing, inconsistent or malformed recovery targets must not be reinterpreted or sent');
    }
    recoveryApiSeed(); $GLOBALS['message_fixture_throttle']=false;
    recoveryApiReject(['user_email'=>'fixture@example.invalid'],[],'Recovery delivery must preserve the existing shared send throttle');
    foreach ([['code'=>1001],new \RuntimeException('Isolated provider failure')] as $failure) {
        recoveryApiSeed(); $GLOBALS['message_fixture_delivery']=$failure; $before=messageFixtureState();
        check(recoveryApiRoute(['user_email'=>'fixture@example.invalid'])['code']>1 && messageFixtureState()===$before,
            'An isolated delivery failure must not report a saved recovery message or change credentials');
    }
    recoveryApiSeed(); messageFixtureTrigger('audit_message_insert_failure','audit_msg','INSERT');
    try {
        $before=messageFixtureState();
        check(recoveryApiRoute(['user_phone'=>'13000000000'])['code']>1 && messageFixtureState()===$before,
            'A message audit write failure must return failure while preserving account and verification state');
    } finally { \think\facade\Db::execute('DROP TRIGGER audit_message_insert_failure'); }
    check(recoveryApiRoute(['user_phone'=>'13000000000'])['code']===1,'A valid recovery request must work after removing an isolated message write fault');
    fwrite(STDOUT,'Recovery API audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
}
