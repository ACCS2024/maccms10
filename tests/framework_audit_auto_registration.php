<?php
/** Combined login/signup and normal login against actual installation fields and TP8 routes. */
declare(strict_types=1);
namespace app\common\model {
    function captcha_check($value) { $GLOBALS['auto_captcha_calls'][]=$value; return $value==='fixture-captcha'; }
    class Group { public function getCache(...$args) {
        if (!empty($GLOBALS['auto_group_failure'])) { throw new \RuntimeException('Isolated group metadata failure'); }
        return [2=>['group_id'=>2,'group_name'=>'Member','group_type'=>'']];
    } }
}
namespace app\api\controller { class Base { public function __construct() {} } }
namespace app\index\controller {
    class Base { public function __construct() {} public function assign($key,$value) {} public function fetch($name) { return \json(['template'=>$name]); } }
}
namespace {
    require __DIR__.'/fixtures/framework_audit_user_registration.php';
    $app->instance(\think\exception\Handle::class,new class($app) extends \think\exception\Handle {
        public function render(\think\Request $request, \Throwable $error): \think\Response { throw $error; }
    });
    function json($data) { return \think\Response::create($data,'json'); }
    function redirect($target) { return \think\Response::create($target,'redirect',302); }
    function cookie($name,...$args) {
        if ($args!==[]) { $GLOBALS['auto_cookies'][$name]=(string)$args[0]; }
        return $GLOBALS['auto_cookies'][$name]??null;
    }
    function cache($key,...$args) {
        if ($args!==[]) { $GLOBALS['auto_cache'][$key]=$args[0]; }
        return $GLOBALS['auto_cache'][$key]??null;
    }
    function mac_get_user_portrait($uid) { return '/fixture-portrait.png'; }
    function autoSeed(array $overrides=[]): void {
        registrationFixtureSeed($overrides);
        $GLOBALS['config']['api']['publicapi']=['status'=>1,'charge'=>0];
        $GLOBALS['auto_cookies']=$GLOBALS['auto_cache']=$GLOBALS['auto_captcha_calls']=[];
        $GLOBALS['auto_group_failure']=false;
    }
    function autoAccount(array $fields=[]): void {
        \think\facade\Db::name('User')->insert($fields+['user_id'=>400,'user_name'=>'abc','user_status'=>1,'group_id'=>'2',
            'user_pwd'=>mac_password_hash('fixture+raw%42&password'),'user_random'=>str_repeat('a',32),'user_invite_code'=>'ABCDE']);
    }
    function autoParam(array $fields=[]): array { return $fields+['user_name'=>'abc','user_pwd'=>'fixture+raw%42&password','verify'=>'fixture-captcha']; }
    function autoReject($param,string $label,string $method='loginOrRegister'): void {
        global $model;
        $before=registrationFixtureState(); $cookies=$GLOBALS['auto_cookies'];
        $result=$model->$method($param);
        check(($result['code']??1)>1 && registrationFixtureState()===$before && $GLOBALS['auto_cookies']===$cookies,$label);
    }
    function autoRow(): array { return \think\facade\Db::name('User')->order('user_id')->find(); }
    function autoFault(string $condition='1=1',string $table='user',string $event='UPDATE'): void {
        global $mysql;
        $body=$mysql?"FOR EACH ROW BEGIN IF ".$condition." THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated auto registration fault'; END IF; END"
            :"WHEN ".$condition." BEGIN SELECT RAISE(ABORT, 'Isolated auto registration fault'); END";
        \think\facade\Db::execute('CREATE TRIGGER audit_auto_failure BEFORE '.$event.' ON audit_'.$table.' '.$body);
    }
    $model=new \app\common\model\User();
    foreach (['abc','abcde','FixtureUser',str_repeat('A',30)] as $name) {
        autoSeed(); $param=autoParam(['user_name'=>$name]);
        $result=$model->loginOrRegister($param); check($result['code']===1, 'Normal automatic signup must succeed: '.json_encode($result)); $row=autoRow();
        check($result['code']===1 && $result['action']==='register' && $result['info']['user_name']===$name,
            'A normal one-password signup must support the existing 3..30-character account contract');
        check(password_verify($param['user_pwd'],$row['user_pwd']) && (int)$row['user_login_num']===1 && (int)$row['user_points']===10
            && (int)\think\facade\Db::name('Plog')->sum('plog_points')===10,'New signup must atomically persist its exact password, login state and signup ledger');
        check($model->checkLogin()['code']===1,'The normal signup response must install a cookie accepted by actual authentication');
        foreach (['user_pwd','user_random','user_answer','user_openid_qq'] as $hidden) { check(!array_key_exists($hidden,$result['info']),'Login response must omit internal '.$hidden); }
        $first=$row['user_random']; $result=$model->loginOrRegister($param);
        check($result['code']===1 && $result['action']==='login' && (int)autoRow()['user_login_num']===2
            && autoRow()['user_random']!==$first && \think\facade\Db::name('User')->count()===1,
            'Repeating a normal combined form must log in the existing account without creating another one');
    }
    foreach (['user_name','user_pwd','verify','invite_code'] as $field) {
        foreach ([[],null,true,1.5] as $invalid) { autoSeed(); autoReject(autoParam([$field=>$invalid]),'Malformed '.$field.' must return a controlled response before writes'); }
    }
    foreach (['ab',str_repeat('n',31),'invalid-name'] as $name) { autoSeed(); autoReject(autoParam(['user_name'=>$name]),'An unavailable automatic-signup name must not create partial state'); }
    foreach (['short',str_repeat('p',73),"fixture\0password"] as $password) { autoSeed(); autoReject(autoParam(['user_pwd'=>$password]),'Automatic signup must preserve the normal raw-password byte limits'); }
    foreach (['status','reg_open'] as $flag) { autoSeed([$flag=>0]); autoReject(autoParam(),'Closed automatic registration must not create an account'); }
    autoSeed(['reg_open'=>0]); autoAccount();
    check($model->loginOrRegister(autoParam())['code']===1,'Closing new registrations must not disable an existing account login');
    autoSeed();
    $emailName='member@example.invalid';
    autoAccount(['user_name'=>$emailName]);
    \think\facade\Db::name('User')->insert(['user_id'=>401,'user_name'=>'OtherFixture','user_email'=>$emailName,
        'user_status'=>1,'group_id'=>'2','user_pwd'=>mac_password_hash('different-password'),'user_random'=>str_repeat('b',32)]);
    $result=$model->loginOrRegister(autoParam(['user_name'=>$emailName]));
    check($result['code']===1 && (int)$result['info']['user_id']===400
        && (int)\think\facade\Db::name('User')->where('user_id',401)->value('user_login_num')===0,
        'An existing username shaped like an email must stay on the username identity column');
    autoReject(autoParam(['user_name'=>$emailName,'user_pwd'=>'different-password']),
        'Another account bound to the same email text cannot supply credentials for that existing username');
    autoSeed(['reg_status'=>0]); $result=$model->loginOrRegister(autoParam());
    check($result['code']===1 && $result['pending_approval']===1 && !isset($result['info']) && $GLOBALS['auto_cookies']===[]
        && (int)autoRow()['user_status']===0 && (int)autoRow()['user_login_num']===0,
        'Approval-required signup must commit a pending account and award ledger without creating a login session');
    autoReject(autoParam(),'A pending account must remain unable to log in');
    foreach (['reg_verify','reg_email_sms','reg_phone_sms'] as $flag) {
        autoSeed([$flag=>1]); $before=registrationFixtureState();
        $result=$model->loginOrRegister(autoParam());
        check($result['code']>1 && $result['registration_required']===1 && registrationFixtureState()===$before && $GLOBALS['auto_cookies']===[],
            'Enabled '.$flag.' must direct new accounts to the complete existing verification form');
        autoAccount(); check($model->loginOrRegister(autoParam())['code']===1,'Registration challenges must not be imposed on already existing users');
    }
    autoSeed(['login_verify'=>1]); autoReject(autoParam(['verify'=>'wrong']),'New automatic signup must honor an enabled login challenge');
    check($model->loginOrRegister(autoParam())['code']===1 && count(array_filter($GLOBALS['auto_captcha_calls'],fn($value)=>$value==='fixture-captcha'))===1,
        'A valid login captcha must be checked once and allow normal automatic signup');
    autoSeed(['login_verify'=>1]); autoAccount(); autoReject(autoParam(['verify'=>'wrong']),'Existing combined login must honor the same login challenge');
    check($model->loginOrRegister(autoParam())['code']===1,'The valid existing-account captcha must remain usable');
    foreach (['md5','formatted_md5','bcrypt'] as $format) {
        autoSeed(); $password='fixture+raw%42&password';
        $hash=$format==='md5'?md5($password):($format==='formatted_md5'?md5(htmlspecialchars(urldecode($password))):mac_password_hash($password));
        autoAccount(['user_pwd'=>$hash]);
        check($model->loginOrRegister(autoParam())['code']===1 && password_verify($password,autoRow()['user_pwd']),
            'Combined login must share raw and historical MD5 compatibility and upgrade to the original raw password');
    }
    autoSeed(); $long=str_repeat('p',80); autoAccount(['user_pwd'=>md5($long)]);
    check($model->loginOrRegister(autoParam(['user_pwd'=>$long]))['code']===1 && autoRow()['user_pwd']===md5($long),
        'An exact long legacy MD5 password may log in without a lossy bcrypt upgrade');
    autoSeed(); autoAccount(['user_pwd'=>mac_password_hash(str_repeat('p',72))]);
    autoReject(autoParam(['user_pwd'=>str_repeat('p',73)]),'Modern hashes must reject a password that differs beyond bcrypt byte 72');
    foreach ([['user_login_num'=>'4294967295'],['group_id'=>''],['group_id'=>'0'],['group_id'=>'32768']] as $bad) {
        autoSeed(); autoAccount($bad); autoReject(autoParam(),'Unrepresentable login state must not rotate a session or partly update the account');
    }
    foreach (['hash','group','login_write','ledger'] as $failure) {
        autoSeed();
        if ($failure==='hash') { $GLOBALS['registration_fixture_hash_failure']=true; }
        if ($failure==='group') { $GLOBALS['auto_group_failure']=true; }
        if ($failure==='login_write') { autoFault('NEW.user_login_num <> OLD.user_login_num'); }
        if ($failure==='ledger') { autoFault('1=1','plog','INSERT'); }
        try { autoReject(autoParam(),'An automatic-signup '.$failure.' failure must roll back the new account, ledger and cookie'); }
        finally { if (in_array($failure,['login_write','ledger'],true)) { \think\facade\Db::execute('DROP TRIGGER audit_auto_failure'); } }
    }
    foreach (['hash','group','write'] as $failure) {
        autoSeed(); autoAccount(['user_pwd'=>md5('fixture+raw%42&password')]);
        if ($failure==='hash') { $GLOBALS['registration_fixture_hash_failure']=true; }
        if ($failure==='group') { $GLOBALS['auto_group_failure']=true; }
        if ($failure==='write') { autoFault(); }
        try { autoReject(autoParam(),'Existing-account '.$failure.' failure must preserve the legacy hash and previous session together'); }
        finally { if ($failure==='write') { \think\facade\Db::execute('DROP TRIGGER audit_auto_failure'); } }
    }
    class AutoHttpRequest extends \think\Request { public function isCli(): bool { return false; } }
    function autoRoute(string $action,array $body=[],array $query=[],string $method='POST',string $module='api'): array {
        global $app;
        $app->setNamespace('app\\'.$module); $app->config->set([],'route');
        $file=$module==='api'?'api.php':'index.php';
        $request=(new AutoHttpRequest())->withServer(['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid',
            'SCRIPT_NAME'=>'/fixture/'.$file,'SCRIPT_FILENAME'=>'/isolated/'.$file,'PATH_INFO'=>'/user/'.$action,
            'REQUEST_URI'=>'/fixture/'.$file.'/user/'.$action])->withPost($body)->withGet($query);
        $app->instance('request',$request);
        $response=(new \think\Route($app))->dispatch($request,false);
        if ($response instanceof \think\response\Redirect) { return ['redirect'=>$response->getData(),'http_status'=>$response->getCode()]; }
        check($response instanceof \think\response\Json && $response->getCode()===200,'Actual login route must return a controlled JSON response');
        return $response->getData();
    }
    foreach (['login_or_register','login'] as $action) {
        autoSeed(); autoAccount();
        check(autoRoute($action,autoParam(),['user_pwd'=>'wrong','user_name'=>'different'])['code']===1,
            'Normal '.$action.' POST must use its body and return usable account information');
        check($model->checkLogin()['code']===1,'Successful API login must create a session recognized by real authentication');
        autoSeed(); autoAccount(); $before=registrationFixtureState();
        check(autoRoute($action,[],autoParam())['code']>1 && registrationFixtureState()===$before,'Query fields cannot supply missing API login credentials');
        check(autoRoute($action,[],autoParam(),'GET')['code']>1 && registrationFixtureState()===$before,'GET cannot log in or automatically create an account');
        autoSeed(['login_verify'=>1]); autoAccount();
        check(autoRoute($action,autoParam())['code']===1,'The API must pass the normal login captcha to the model');
    }
    autoSeed(); autoAccount(['user_email'=>'fixture@example.invalid','user_phone'=>'13000000000']);
    foreach (['email'=>'fixture@example.invalid','phone'=>'13000000000','name'=>'abc'] as $type=>$name) {
        check(autoRoute('login',autoParam(['type'=>$type,'user_name'=>$name]))['code']===1,'The documented '.$type.' login identity must be supported explicitly');
    }
    autoReject(autoParam(['identity_field'=>'user_id','user_name'=>'400']),'Request fields cannot select arbitrary identity columns','login');
    autoSeed(['reg_email_sms'=>1]);
    $result=autoRoute('login_or_register',autoParam(['invite_code'=>'ABCDE']));
    check($result['registration_required']===1 && $result['registration_url']==='/fixture/index.php/user/reg?invite_code=ABCDE',
        'The real API must provide a same-site registration path preserving only a validated invitation code');
    autoSeed(['reg_status'=>0]);
    $result=autoRoute('login_or_register',autoParam());
    check($result['code']===1 && $result['pending_approval']===1 && !isset($result['info']),
        'The pending API response must not access absent login information');
    autoSeed(); autoAccount();
    check(autoRoute('login',autoParam(),['user_pwd'=>'wrong'],'POST','index')['code']===1,'The existing index login form must use POST credentials');
    autoSeed(); autoAccount(); $before=registrationFixtureState();
    check(autoRoute('login',[],autoParam(),'POST','index')['code']>1 && registrationFixtureState()===$before,
        'Index login must not borrow credentials from query strings');
    autoSeed(); autoAccount();
    $GLOBALS['auto_cookies']=['user_id'=>'400','user_name'=>'abc'];
    check($model->checkLogin()['code']>1 && autoRoute('login',[],[],'GET','index')['template']==='user/login',
        'Display-only cookies must not bypass the login page or create a redirect loop');
    check($model->login(autoParam())['code']===1,'Verified login-page fixture must authenticate through the actual model');
    $GLOBALS['user']=$model->checkLogin()['info'];
    $view=autoRoute('login',[],[],'GET','index');
    check($view['http_status']===302 && $view['redirect']==='user/index',
        'The login page may redirect only after trusted request identity contains the authenticated account');
    foreach ([0,[], -1,'4294967296'] as $invalid) {
        $GLOBALS['user']=['user_id'=>$invalid];
        check(autoRoute('login',[],[],'GET','index')['template']==='user/login',
            'A missing or unrepresentable trusted user id must keep the login page available');
    }
    foreach (['status','reg_open','reg_verify','reg_phone_sms','reg_email_sms','login_verify'] as $field) {
        foreach ([[],null,'invalid'] as $invalid) {
            autoSeed([$field=>$invalid]); autoReject(autoParam(),'Malformed automatic-login configuration '.$field.' must not create state');
        }
    }
    autoSeed(['status'=>0]); autoAccount(); autoReject(autoParam(),'Closed membership must also reject the normal login method','login');
    autoSeed(['reg_verify'=>1]);
    $result=$model->loginOrRegister(autoParam(['trusted_oauth'=>true,'user_openid_qq'=>'untrusted-provider-id']));
    check($result['registration_required']===1 && registrationFixtureState()[0]===[],
        'Request OAuth flags must never suppress automatic registration challenges');
    autoSeed(); autoAccount();
    $result=$model->login(autoParam(),['set_cookie'=>false,'return_meta'=>true]);
    check($result['code']===1 && $GLOBALS['auto_cookies']===[] && $result['meta']['user_random']===autoRow()['user_random'],
        'Existing JWT callers must retain the explicit metadata contract without browser cookies');
    if ($mysql) {
        foreach (['user','msg','plog','group'] as $table) {
            autoSeed(); \think\facade\Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
            try { autoReject(autoParam(),'Automatic creation must fail closed on nontransactional '.$table); }
            finally { \think\facade\Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB'); }
        }
        autoSeed(); autoAccount(['user_pwd'=>md5('fixture+raw%42&password')]);
        \think\facade\Db::execute('ALTER TABLE audit_user MODIFY user_random varchar(16) NOT NULL DEFAULT ""');
        try { autoReject(autoParam(),'Silent session-secret clipping must roll back legacy password upgrade and login together'); }
        finally { \think\facade\Db::execute('ALTER TABLE audit_user MODIFY user_random varchar(32) NOT NULL DEFAULT ""'); }
        autoSeed(); autoAccount();
        \think\facade\Db::execute('ALTER TABLE audit_user ENGINE=MyISAM');
        try { autoReject(autoParam(),'An existing login must also reject a nontransactional account table'); }
        finally { \think\facade\Db::execute('ALTER TABLE audit_user ENGINE=InnoDB'); }
        function autoConcurrent(array $jobs): array {
            $barrier=audit_temp_dir('registration-concurrency'); $processes=[]; $streams=[];
            try {
                foreach ($jobs as $slot=>$job) {
                    $job['slot']=$slot;
                    $command=[PHP_BINARY,__DIR__.'/fixtures/framework_audit_auto_registration_worker.php',base64_encode(json_encode($job,JSON_THROW_ON_ERROR)),$barrier];
                    $processes[$slot]=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
                    if (!is_resource($processes[$slot])) { throw new \RuntimeException('Cannot start isolated registration worker'); }
                    fclose($pipes[0]); $streams[$slot]=$pipes;
                }
                $deadline=microtime(true)+20;
                while (count(glob($barrier.'/ready-*'))!==count($jobs)) {
                    if (microtime(true)>$deadline) { throw new \RuntimeException('Concurrent registration setup timed out'); }
                    usleep(10000);
                }
                file_put_contents($barrier.'/go','go');
                $results=[];
                foreach ($processes as $slot=>$process) {
                    $output=stream_get_contents($streams[$slot][1]); $error=stream_get_contents($streams[$slot][2]);
                    fclose($streams[$slot][1]); fclose($streams[$slot][2]);
                    $exit=proc_close($process); unset($processes[$slot]);
                    check($exit===0 && $error==='', 'Isolated concurrent worker must finish without an exception: '.$error);
                    $results[]=json_decode(trim($output),true,32,JSON_THROW_ON_ERROR);
                }
                return $results;
            } finally {
                foreach ($processes as $process) { proc_terminate($process); proc_close($process); }
                audit_remove_temp($barrier);
            }
        }
        foreach (['quota','same_name','invitation','reset'] as $scenario) {
            $settings=$scenario==='quota'?['reg_num'=>1]:[];
            if ($scenario==='invitation') { $settings=['invite_reg_points'=>7,'invite_reward_status'=>1,
                'invite_reward'=>[1=>['group_id'=>0,'points'=>3,'long'=>'day'],2=>['group_id'=>0,'points'=>4,'long'=>'day']]]; }
            autoSeed($settings);
            if (in_array($scenario,['invitation','reset'],true)) { autoAccount(['user_name'=>'FixtureInviter','user_email'=>'parent@example.invalid']); }
            $first=autoParam(['user_name'=>'FixtureUser']);
            $second=registrationFixtureParam(['user_name'=>$scenario==='same_name'?'FixtureUser':'SecondFixture']);
            if ($scenario==='invitation') { $first['uid']=400; $second['uid']=400; }
            $jobs=[['action'=>'loginOrRegister','param'=>$first,'configuration'=>$settings],['action'=>'register','param'=>$second,'configuration'=>$settings]];
            if ($scenario==='reset') {
                \think\facade\Db::name('Msg')->insert(['user_id'=>0,'msg_type'=>2,'msg_status'=>0,'msg_to'=>'parent@example.invalid','msg_code'=>'123456','msg_time'=>time(),'msg_content'=>'Isolated reset']);
                $jobs=[['action'=>'loginOrRegister','param'=>autoParam(['user_name'=>'FixtureInviter']),'configuration'=>$settings],
                    ['action'=>'findpass_reset','param'=>['ac'=>'email','to'=>'parent@example.invalid','code'=>'123456','user_pwd'=>'replacement-password','user_pwd2'=>'replacement-password'],'configuration'=>$settings]];
            }
            $results=autoConcurrent($jobs);
            if ($scenario==='invitation') {
                check($results[0]['code']===1 && $results[1]['code']===1 && \think\facade\Db::name('User')->count()===3
                    && (int)\think\facade\Db::name('User')->where('user_id',400)->value('user_invite_count')===2
                    && (int)\think\facade\Db::name('User')->where('user_id',400)->value('user_points')===21,
                    'Combined and normal registration must share one exactly-once invitation transaction contract');
            } elseif ($scenario==='reset') {
                check($results[1]['code']===1 && password_verify('replacement-password',autoRow()['user_pwd'])
                    && (int)\think\facade\Db::name('Msg')->value('msg_status')===1 && \think\facade\Db::name('User')->count()===1,
                    'A simultaneous login and password reset must keep the reset credentials and one consumed code');
            } else {
                check(\think\facade\Db::name('User')->count()===1 && \think\facade\Db::name('Plog')->count()===1,
                    'Combined and normal registration must not duplicate a name, IP quota slot or signup ledger');
                check(count(array_filter($results,fn($result)=>$result['code']===1))>=1,'At least one normal concurrent registration must complete');
            }
        }
    }
    fwrite(STDOUT,'Automatic registration/login audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
}
