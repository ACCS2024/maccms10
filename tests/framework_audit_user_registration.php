<?php
/** Registration input and initial DDL values, using the real User/Msg/Plog ORM. */
declare(strict_types=1);
namespace app\common\model {
    function captcha_check($value) { $GLOBALS['registration_fixture_captchas'][] = $value; return $value === 'fixture-captcha'; }
    class Group {
        public function getCache(...$args) { return [
            1=>['group_id'=>1,'group_name'=>'Guest','group_type'=>''],
            2=>['group_id'=>2,'group_name'=>'Member','group_type'=>''],
        ]; }
    }
}
namespace {
    require __DIR__.'/fixtures/framework_audit_user_registration.php';
    $model = new \app\common\model\User();
    function registrationReject($param, string $label, bool $trusted = false): void {
        global $model;
        $before = registrationFixtureState();
        $result = $model->register($param,$trusted);
        check(is_array($result) && ($result['code'] ?? 1) > 1 && registrationFixtureState() === $before,$label);
    }
    foreach (['fixture+raw%42&password','  fixture+raw%42&password  ',str_repeat('p',6),str_repeat('p',72),
        str_repeat('密',24),"\xffabcde"] as $password) {
        registrationFixtureSeed();
        $param = registrationFixtureParam(['user_pwd'=>$password,'user_pwd2'=>$password]);
        $res = $model->register($param); $rows = registrationFixtureState()[0];
        check($res['code'] === 1 && count($rows) === 1,'A normal password within the byte boundary must register');
        $row = $rows[0];
        check(password_verify(trim($password),$row['user_pwd']), 'The stored modern hash must represent the exact trimmed password bytes');
        check(preg_match('/^[a-f0-9]{32}$/D',$row['user_random']) === 1,'A newly created account must have a cryptographic session secret');
        check((int)$row['user_points'] === 10 && (int)$row['user_status'] === 1 && $row['group_id'] === '2'
            && (string)$row['user_reg_ip'] === '2130706433' && (int)$row['user_reg_time'] > 0,
            'Initial account fields must use validated configuration and representable installation values');
        check($model->login(['user_name'=>'FixtureUser','user_pwd'=>$password],['set_cookie'=>false])['code'] === 1,
            'The normal login path must accept exactly the password that registration stored');
    }
    foreach ([['fixture%41password','fixtureApassword'],['fixture+password','fixture password'],['0e123456','0e654321'],
        ['fixture-password','different-password']] as [$first,$second]) {
        registrationFixtureSeed();
        registrationReject(registrationFixtureParam(['user_pwd'=>$first,'user_pwd2'=>$second]),
            'Different original passwords must not become equal after legacy URL formatting');
    }
    foreach (['',str_repeat('p',5),str_repeat('p',73),str_repeat('密',25),"fixture\0password","\0fixture-password","fixture-password\0"] as $password) {
        registrationFixtureSeed();
        registrationReject(registrationFixtureParam(['user_pwd'=>$password,'user_pwd2'=>$password]),
            'Invalid password bytes must fail before creating any account or ledger');
    }
    foreach (['user_name','user_pwd','user_pwd2','verify','ac','to','code','invite_code','user_openid_qq','user_openid_weixin'] as $field) {
        foreach ([[],['ordinary-field'],null,true,1.5,123456,new \stdClass()] as $invalid) {
            registrationFixtureSeed();
            registrationReject(registrationFixtureParam([$field=>$invalid]),'Structured or mistyped '.$field.' must fail before any write');
        }
    }
    foreach ([[],null,true,1.5,-1,'-1','4294967296','1e2','1.0','invalid'] as $invalid) {
        registrationFixtureSeed();
        registrationReject(registrationFixtureParam(['uid'=>$invalid]),'Invalid referral user ids must not be cast into another account');
    }
    foreach (['short','with-dash','with space','用户名测试',str_repeat('n',31),"Name\xff123",'adminUser'] as $name) {
        registrationFixtureSeed();
        registrationReject(registrationFixtureParam(['user_name'=>$name]),'Username rules and installation length must be enforced before writes');
    }
    foreach (['123456',str_repeat('A',30),'%46ixtureUser'] as $name) {
        registrationFixtureSeed();
        check($model->register(registrationFixtureParam(['user_name'=>$name]))['code'] === 1,
            'Existing alphanumeric username and legacy username normalization must remain usable');
        check(registrationFixtureState()[0][0]['user_name'] === urldecode($name),'The stored username must fit the existing normalization contract');
    }
    registrationFixtureSeed();
    check($model->register(registrationFixtureParam())['code'] === 1,'Duplicate-name fixture must first create its account');
    registrationReject(registrationFixtureParam(),'An already registered name must remain unavailable');
    foreach (['invite_code'=>str_repeat('A',21),'verify'=>str_repeat('v',256),'to'=>str_repeat('t',31),'code'=>'1234567',
        'ac'=>'unsupported','user_openid_qq'=>str_repeat('q',41),'user_openid_weixin'=>str_repeat('w',41)] as $field=>$invalid) {
        registrationFixtureSeed();
        registrationReject(registrationFixtureParam([$field=>$invalid]),'Oversized '.$field.' must fail before database truncation',true);
    }
    foreach (['user_openid_qq','user_openid_weixin'] as $field) {
        foreach (["fixture\0id","fixture\xffid",'fixture😀id',str_repeat(' ',40).'id'] as $invalid) {
            registrationFixtureSeed();
            registrationReject(registrationFixtureParam([$field=>$invalid]),'Trusted provider identifiers must fit the original UTF-8 installation column',true);
        }
    }
    foreach (['email'=>'fixture@example.invalid','phone'=>'13000000000'] as $channel=>$target) {
        registrationFixtureSeed(['reg_'.$channel.'_sms'=>1]);
        \think\facade\Db::name('Msg')->insert(['user_id'=>0,'msg_type'=>3,'msg_status'=>0,'msg_to'=>$target,
            'msg_code'=>'123456','msg_time'=>time(),'msg_content'=>'Fixture registration code']);
        $param = registrationFixtureParam(['ac'=>$channel,'to'=>$target,'code'=>'123456']);
        check($model->register($param)['code'] === 1 && registrationFixtureState()[0][0]['user_'.$channel] === $target,
            'Normal '.$channel.' registration must retain real registration-code validation');
        registrationFixtureSeed(['reg_'.$channel.'_sms'=>1]);
        registrationReject($param,'Registration still requires an existing matching message');
        \think\facade\Db::name('Msg')->insert(['user_id'=>0,'msg_type'=>1,'msg_status'=>0,'msg_to'=>$target,
            'msg_code'=>'123456','msg_time'=>time(),'msg_content'=>'Fixture other purpose']);
        registrationReject($param,'A binding code must not satisfy registration verification');
    }
    registrationFixtureSeed(['reg_verify'=>1]);
    registrationReject(registrationFixtureParam(['verify'=>'wrong-fixture','user_openid_qq'=>'ordinary-id','trusted_oauth'=>true]),
        'Request data must not grant the trusted OAuth captcha exemption');
    check($model->register(registrationFixtureParam())['code'] === 1,'A normal registration with the valid fixture captcha must remain usable');
    registrationFixtureSeed(['reg_verify'=>1,'reg_phone_sms'=>1]);
    check($model->register(registrationFixtureParam(['verify'=>'wrong-fixture','user_openid_qq'=>'verified-provider-id']),true)['code'] === 1
        && registrationFixtureState()[0][0]['user_openid_qq'] === 'verified-provider-id',
        'The existing server-authorized provider callback must preserve its challenge exemption');
    registrationFixtureSeed(['reg_verify'=>1]);
    registrationReject(registrationFixtureParam(['verify'=>'wrong-fixture']),
        'Trusted callback mode without a provider identity must not bypass the challenge',true);
    registrationFixtureSeed();
    check($model->register(registrationFixtureParam(['user_openid_qq'=>'ordinary-id','user_random'=>'request-random',
        'user_points'=>'4294967295','user_status'=>'0','group_id'=>'9']))['code'] === 1,
        'Ordinary registration must remain available when unrelated profile fields are supplied');
    $row = registrationFixtureState()[0][0];
    check($row['user_openid_qq'] === '' && (int)$row['user_points'] === 10 && (int)$row['user_status'] === 1
        && $row['group_id'] === '2' && $row['user_random'] !== 'request-random',
        'Request fields must not override trusted initial account values or provider identity');
    foreach (['status','reg_open','reg_verify','reg_status','reg_phone_sms','reg_email_sms'] as $field) {
        foreach ([[],null,true,1.5,-1,2,'enabled'] as $invalid) {
            registrationFixtureSeed([$field=>$invalid]);
            registrationReject(registrationFixtureParam(),'Invalid '.$field.' configuration must be controlled before any write');
        }
    }
    foreach (['reg_points','reg_num','invite_reg_points','invite_reg_num'] as $field) {
        foreach ([[],null,true,1.5,-1,'4294967296','1e2','1.0'] as $invalid) {
            registrationFixtureSeed([$field=>$invalid]);
            registrationReject(registrationFixtureParam(),'Unrepresentable '.$field.' configuration must not be silently cast or clipped');
        }
    }
    foreach ([[],null,1,"invalid\xff"] as $invalid) {
        registrationFixtureSeed(['filter_words'=>$invalid]);
        registrationReject(registrationFixtureParam(),'Malformed name-filter configuration must not throw PHP type errors');
    }
    foreach ([[], ['user'=>[]], ['user'=>null], ['user'=>'incorrect']] as $configuration) {
        registrationFixtureSeed(); $app->config->set(['maccms'=>$configuration]);
        registrationReject(registrationFixtureParam(),'Missing or malformed registration configuration must return a controlled error');
    }
    foreach ([[],null,true,1.5,-1,'4294967296','not-an-ip'] as $ip) {
        registrationFixtureSeed(); $GLOBALS['registration_fixture_ip'] = $ip;
        registrationReject(registrationFixtureParam(),'Invalid registration IP values must fail before unsigned-column clipping');
    }
    foreach ([[],null,true,1.5,0,65536,'invalid'] as $group) {
        registrationFixtureSeed(); $model->_def_group = $group;
        registrationReject(registrationFixtureParam(),'Invalid default groups must fail before creating an unusable account');
    }
    $model->_def_group = 2;
    foreach ([0, '4294967295'] as $boundary) {
        registrationFixtureSeed(['reg_points'=>$boundary,'reg_status'=>0]); $GLOBALS['registration_fixture_ip'] = $boundary;
        check($model->register(registrationFixtureParam())['code'] === 1,'Representable unsigned boundary values must remain supported');
        $row = registrationFixtureState()[0][0];
        check((string)$row['user_points'] === (string)$boundary && (string)$row['user_reg_ip'] === (string)$boundary
            && (int)$row['user_status'] === 0, 'Boundary account values must survive real storage without truncation');
    }
    foreach (['status','reg_open'] as $field) {
        registrationFixtureSeed([$field=>0]);
        registrationReject(registrationFixtureParam(),'Closed registration must not create an account');
    }
    registrationFixtureSeed(['reg_num'=>1]);
    check($model->register(registrationFixtureParam())['code'] === 1,'Daily registration-limit fixture must first create one account');
    registrationReject(registrationFixtureParam(['user_name'=>'SecondFixture']),'The existing daily successful-registration limit must remain active');
    registrationFixtureSeed(); $GLOBALS['registration_fixture_throttle'] = false;
    registrationReject(registrationFixtureParam(),'Request throttling must run before registration writes');
    registrationFixtureSeed(); $GLOBALS['registration_fixture_hash_failure'] = true;
    registrationReject(registrationFixtureParam(),'A hashing failure must return a controlled response before any write');
    foreach (['invite_reg_points','invite_reg_num'] as $optional) {
        registrationFixtureSeed();
        $configuration = config('maccms'); unset($configuration['user'][$optional]);
        $GLOBALS['config'] = $configuration; $app->config->set($configuration,'maccms');
        check($model->register(registrationFixtureParam())['code'] === 1,
            'Missing optional legacy '.$optional.' configuration must default to disabled rewards');
    }
    registrationFixtureSeed();
    \think\facade\Db::name('User')->insert(['user_id'=>400,'user_name'=>'FixtureInviter','user_invite_code'=>'ABCDE',
        'user_status'=>1,'user_pid'=>0,'user_pid_2'=>0,'user_points'=>0]);
    check($model->register(registrationFixtureParam(['invite_code'=>' ABCDE ','uid'=>'0']))['code'] === 1,
        'A normal generated invitation code must remain usable after early input validation');
    $created = \think\facade\Db::name('User')->where('user_name','FixtureUser')->find();
    check((int)$created['user_pid'] === 400,'Normal referral lookup must still select the existing inviter');
    $random = $created['user_random'];
    check($model->register(registrationFixtureParam(['user_name'=>'SecondFixture','uid'=>'0000000400']))['code'] === 1,
        'A decimal uid referral must retain its normal registration path');
    check(\think\facade\Db::name('User')->where('user_name','SecondFixture')->value('user_random') !== $random,
        'Different new accounts must receive independent session secrets');
    fwrite(STDOUT,'Registration input audit passed ('.$checks.' checks; '.($mysql ? 'MySQL non-strict' : 'SQLite').")\n");
}
