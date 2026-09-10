<?php
/** Real registration/User/Msg/Plog/Group storage; fault injection never uses real contacts or deliveries. */
declare(strict_types=1);
namespace app\common\model {
    function captcha_check($value) { return $value === 'fixture-captcha'; }
    class Group { public function getCache(...$args) { return [2=>['group_id'=>2,'group_name'=>'Member','group_type'=>'']]; } }
}
namespace app\api\controller { class Base { public function __construct() {} } }
namespace app\index\controller {
    class Base {
        protected array $assigned = [];
        public function __construct() {}
        public function assign($key,$value) { $this->assigned[$key] = $value; }
        public function fetch($template) { return \json(['template'=>$template]+$this->assigned); }
    }
}
namespace {
    require __DIR__.'/fixtures/framework_audit_user_registration.php';
    function json($data) { return \think\Response::create($data,'json'); }
    function cookie($name, ...$args) {
        if ($args !== []) { $GLOBALS['registration_cookies'][$name] = $args[0]; }
        return $GLOBALS['registration_cookies'][$name] ?? null;
    }
    function mac_get_user_portrait($uid) { return '/fixture-portrait.png'; }
    function atomicSeed(array $configuration = [], array $inviter = []): void {
        registrationFixtureSeed($configuration);
        $GLOBALS['registration_cookies'] = [];
        $GLOBALS['config']['api']['publicapi'] = ['status'=>1,'charge'=>0];
        \think\facade\Db::name('User')->insert($inviter + ['user_id'=>400,'user_name'=>'FixtureInviter',
            'user_status'=>1,'group_id'=>'2','user_invite_code'=>'ABCDE','user_points'=>100,
            'user_pwd'=>mac_password_hash('fixture-password'),'user_random'=>str_repeat('a',32)]);
    }
    function atomicMessage(string $channel = 'email', array $overrides = []): array {
        $to = $channel === 'email' ? 'fixture@example.invalid' : '13000000000';
        \think\facade\Db::name('Msg')->insert($overrides+['user_id'=>0,'msg_type'=>3,'msg_status'=>0,
            'msg_to'=>$to,'msg_code'=>'123456','msg_time'=>time(),'msg_content'=>'Isolated normal verification code']);
        return ['ac'=>$channel,'to'=>$to,'code'=>'123456'];
    }
    function atomicReject(array $param, string $label): void {
        global $model;
        $before = registrationFixtureState();
        $result = $model->register($param);
        check(($result['code'] ?? 1) > 1 && registrationFixtureState() === $before, $label);
    }
    function atomicUser(int $uid = 400): array { return \think\facade\Db::name('User')->where('user_id',$uid)->find(); }
    function atomicChild(): array { return \think\facade\Db::name('User')->where('user_name','FixtureUser')->find(); }
    function atomicFault(string $table, string $event, string $condition = '1=1'): void {
        global $mysql;
        $body = $mysql ? "FOR EACH ROW BEGIN IF ".$condition." THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated registration fixture fault'; END IF; END"
            : "WHEN ".$condition." BEGIN SELECT RAISE(ABORT, 'Isolated registration fixture fault'); END";
        \think\facade\Db::execute('CREATE TRIGGER audit_registration_fault BEFORE '.$event.' ON audit_'.$table.' '.$body);
    }
    $model = new \app\common\model\User();
    foreach (['email','phone'] as $channel) {
        atomicSeed(['reg_'.$channel.'_sms'=>1,'invite_reg_points'=>7]);
        $param = registrationFixtureParam(atomicMessage($channel)+['uid'=>400]);
        $GLOBALS['user'] = ['user_id'=>400,'user_name'=>'FixtureInviter'];
        check($model->register($param)['code'] === 1,'Registration codes must remain guest-scoped even with an existing login context');
        $child = atomicChild();
        check((int)$child['user_pid'] === 400 && $child['user_'.$channel] === $param['to'] && (int)$child['user_points'] === 10,
            'New account, verified contact, parent relationship and signup points must commit together');
        check((int)atomicUser()['user_points'] === 107 && (int)atomicUser()['user_invite_count'] === 1,
            'One fresh child must award exactly one direct bonus and invitation count');
        check((int)\think\facade\Db::name('Msg')->value('msg_status') === 1,'Successful registration must consume its verification code');
        $logs = \think\facade\Db::name('Plog')->where('user_id',$child['user_id'])->select()->toArray();
        check(count($logs) === 2 && array_sum(array_column($logs,'plog_points')) === 10
            && count(array_filter($logs,fn($log)=>$log['plog_remarks']==='注册推荐确认：400' && (int)$log['plog_points']===0)) === 1,
            'The new child must hold a zero-amount, fixed registration provenance receipt');
        $after = registrationFixtureState();
        check($model->addInviteCount(400,$child['user_id'])['code'] > 1 && $model->addInviteCount(400)['code'] > 1
            && $model->processInviteReward(400)['code'] > 1 && registrationFixtureState() === $after,
            'Public invitation wrappers cannot replay old registrations without private new-insert context');
        atomicReject(registrationFixtureParam(['user_name'=>'SecondFixture'] + atomicMessage($channel,['msg_status'=>1])),
            'An already consumed verification code cannot register another account');
        atomicSeed(['reg_'.$channel.'_sms'=>1]);
        atomicReject(registrationFixtureParam(atomicMessage($channel,['user_id'=>400])),
            'A code belonging to an existing account cannot replace guest registration verification');
    }
    atomicSeed(['reg_points'=>0,'invite_reg_points'=>0]);
    check($model->register(registrationFixtureParam(['uid'=>400]))['code']===1,'A zero-bonus registration must remain usable');
    check(\think\facade\Db::name('Plog')->count()===3 && (int)atomicUser()['user_invite_count']===1,
        'Disabled bonuses must still persist provenance and one count without manufacturing points');
    foreach ([['uid'=>401],['invite_code'=>'MISSING']] as $invalid) {
        atomicSeed(); atomicReject(registrationFixtureParam($invalid),'Unavailable referral identity must not silently create an unrelated account');
    }
    atomicSeed();
    \think\facade\Db::name('User')->insert(['user_id'=>401,'user_name'=>'DuplicateInviter','user_invite_code'=>'ABCDE']);
    atomicReject(registrationFixtureParam(['invite_code'=>'ABCDE']),'Ambiguous historical invitation codes must fail without creating or rewarding an account');
    foreach ([['user_status'=>0],['user_pid'=>400],['user_pid'=>401],['user_pid_2'=>400]] as $bad) {
        atomicSeed([],$bad); atomicReject(registrationFixtureParam(['uid'=>400]),'Unavailable or inconsistent referral ancestry must fail atomically');
    }
    foreach ([32768,65535,6] as $group) {
        atomicSeed(); $model->_def_group=$group;
        atomicReject(registrationFixtureParam(),'Default group must exist, be enabled and fit the signed installation identifier');
    }
    $model->_def_group=2;
    atomicSeed(); \think\facade\Db::name('Group')->where('group_id',2)->update(['group_status'=>0]);
    atomicReject(registrationFixtureParam(),'Disabled default membership cannot create an unusable account');
    atomicSeed(); \think\facade\Db::name('Group')->insert(['group_id'=>32767,'group_status'=>1,'group_name'=>'Largest group','group_type'=>'','group_popedom'=>'']);
    $model->_def_group=32767;
    check($model->register(registrationFixtureParam())['code']===1 && atomicChild()['group_id']==='32767','The largest valid enabled group must remain supported');
    $model->_def_group=2;
    $tiers = [1=>['group_id'=>5,'points'=>3,'long'=>'day'],2=>['group_id'=>3,'points'=>4,'long'=>'week'],3=>['group_id'=>0,'points'=>5,'long'=>'day']];
    $configuration = ['invite_reward_status'=>1,'invite_reward'=>$tiers,'invite_reg_points'=>7];
    $end = time()+10000;
    atomicSeed($configuration,['user_invite_count'=>2,'user_end_time'=>$end]);
    check($model->register(registrationFixtureParam(['uid'=>400]))['code']===1,'All newly crossed invitation tiers must commit in one registration');
    $parent = atomicUser();
    check((int)$parent['user_points']===119 && (int)$parent['user_invite_count']===3
        && (int)$parent['user_invite_reward_level']===3 && $parent['group_id']==='2,5'
        && (int)$parent['user_end_time']===$end+86400+604800,'Cumulative tiers must retain the highest granted group and extend the working expiry once per tier');
    check(\think\facade\Db::name('Plog')->where('user_id',400)->sum('plog_points')==19
        && \think\facade\Db::name('Plog')->where('plog_type','<>',2)->count()===0,'Signup and invitation awards must use income ledger type with exact balances');
    foreach ([['invite_reward_status'=>null],['invite_reward_status'=>[]],['invite_reward_status'=>1,'invite_reward'=>null],
        ['invite_reward_status'=>1,'invite_reward'=>['bad'=>$tiers[1]]],
        ['invite_reward_status'=>1,'invite_reward'=>[1=>['group_id'=>32768,'points'=>1,'long'=>'day']]],
        ['invite_reward_status'=>1,'invite_reward'=>[1=>['group_id'=>3,'points'=>'4294967296','long'=>'day']]],
        ['invite_reward_status'=>1,'invite_reward'=>[1=>['group_id'=>3,'points'=>1,'long'=>'invalid']]],
        ['invite_reward_status'=>1,'invite_reward'=>[100=>['group_id'=>6,'points'=>1,'long'=>'day']]],
        ['invite_reward_status'=>1,'invite_reward'=>[1=>$tiers[1],'01'=>$tiers[1]]]] as $bad) {
        atomicSeed($bad); atomicReject(registrationFixtureParam(['uid'=>400]),'Malformed or unavailable configured tiers must fail before any state is committed');
    }
    foreach ([['user_points'=>'4294967295'],['user_invite_count'=>'4294967295'],['user_end_time'=>'4294967295']] as $boundary) {
        atomicSeed($configuration,$boundary); atomicReject(registrationFixtureParam(['uid'=>400]),'Invitation balance, count or expiry overflow must roll back the entire registration');
    }
    $faults = [['msg','UPDATE'],['user','INSERT'],['user','UPDATE','NEW.user_id <> 400'],
        ['user','UPDATE','NEW.user_invite_count <> OLD.user_invite_count'],
        ['user','UPDATE','NEW.user_id = 400 AND NEW.user_points <> OLD.user_points'],
        ['user','UPDATE','NEW.user_invite_reward_level <> OLD.user_invite_reward_level'],
        ['plog','INSERT',"NEW.plog_remarks = '注册赠分'"],['plog','INSERT',"NEW.plog_remarks LIKE '注册推荐确认：%'"],
        ['plog','INSERT',"NEW.plog_remarks LIKE '注册推荐积分：%'"],['plog','INSERT',"NEW.plog_remarks LIKE '邀请阶梯：%'" ]];
    foreach ($faults as $fault) {
        atomicSeed($configuration+['reg_email_sms'=>1]);
        $param=registrationFixtureParam(atomicMessage()+['uid'=>400]);
        atomicFault(...$fault);
        try { atomicReject($param,'A '.implode('/',$fault).' fault must roll back user, code, all balances, counts and ledgers'); }
        finally { \think\facade\Db::execute('DROP TRIGGER audit_registration_fault'); }
        check($model->register($param)['code']===1,'The same valid form and code must work after removing an isolated transaction fault');
    }
    class RegistrationHttpRequest extends \think\Request { public function isCli(): bool { return false; } }
    function atomicRoute(string $module, string $action, array $body=[], array $query=[], string $method='POST'): array {
        global $app;
        $app->setNamespace('app\\'.$module); $app->config->set([],'route');
        $request = (new RegistrationHttpRequest())->withServer(['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid',
            'SCRIPT_NAME'=>'/index.php','SCRIPT_FILENAME'=>'/isolated/index.php','PATH_INFO'=>'/user/'.$action,
            'REQUEST_URI'=>'/index.php/user/'.$action])->withPost($body)->withGet($query);
        $app->instance('request',$request);
        $response=(new \think\Route($app))->dispatch($request,false);
        check($response instanceof \think\response\Json && $response->getCode()===200,'Registration route must produce a controlled response through TP8 dispatch');
        return $response->getData();
    }
    foreach (['index'=>'reg','api'=>'register'] as $module=>$action) {
        atomicSeed();
        check(atomicRoute($module,$action,registrationFixtureParam(),registrationFixtureParam(['user_name'=>'QueryFixture','uid'=>400]))['code']===1,
            'Normal POST must remain reachable through the actual '.$module.' registration route');
        check(atomicChild()['user_pid']==0 && \think\facade\Db::name('User')->where('user_name','QueryFixture')->count()===0,
            'Query parameters cannot supply or override registration credentials or referral identity');
        atomicSeed(); $before=registrationFixtureState();
        check(atomicRoute($module,$action,[],registrationFixtureParam())['code']>1 && registrationFixtureState()===$before,
            'A POST body missing required fields cannot borrow them from the URL');
        if ($module==='api') {
            check(atomicRoute($module,$action,[],registrationFixtureParam(),'GET')['code']>1 && registrationFixtureState()===$before,
                'A GET API registration request cannot create state');
        }
    }
    atomicSeed(); $GLOBALS['registration_cookies']['uid']='400';
    check(atomicRoute('index','reg',registrationFixtureParam(['uid'=>0]))['code']===1 && atomicChild()['user_pid']==0,
        'Explicit POST referral choice must take precedence over a historical cookie');
    atomicSeed(); $GLOBALS['registration_cookies']['uid']='400';
    check(atomicRoute('index','reg',registrationFixtureParam())['code']===1 && atomicChild()['user_pid']==400,
        'A valid normal referral cookie remains usable when POST omits referral identity');
    atomicSeed(); $GLOBALS['registration_cookies']['uid']=[]; $before=registrationFixtureState();
    check(atomicRoute('index','reg',registrationFixtureParam())['code']>1 && registrationFixtureState()===$before,
        'Malformed referral cookies must not be integer-cast into a different account');
    atomicSeed(['reg_status'=>0]);
    $result=atomicRoute('index','reg',registrationFixtureParam());
    check($result['code']===1 && $result['pending_approval']===1 && atomicChild()['user_status']==0,
        'Approval-required registration must report successful account creation without a false failed-login message');
    atomicSeed(); $view=atomicRoute('index','reg',[],['invite_code'=>'ABCDE','uid'=>'400'],'GET');
    check($view['template']==='user/reg' && $view['param']['invite_code']==='ABCDE' && cookie('uid')==='400',
        'Normal invitation links must still reach the registration form');
    foreach ([['invite_code'=>[]],['invite_code'=>'invalid code'],['uid'=>[]],['uid'=>'4294967296']] as $invalid) {
        check(atomicRoute('index','reg',[],$invalid,'GET')['code']>1,'Malformed invitation links must produce a controlled form response');
    }
    foreach (['email','phone'] as $channel) {
        atomicSeed(['reg_'.$channel.'_sms'=>1]);
        $GLOBALS['registration_fixture_allow_delivery']=true;
        $GLOBALS['user']=['user_id'=>400,'user_name'=>'FixtureInviter'];
        $GLOBALS['config']['email']['tpl']=['user_reg_title'=>'Fixture registration','user_reg_body'=>'Fixture verification'];
        $GLOBALS['config']['sms']=['content'=>'Fixture [验证码]'];
        $app->instance('view',new class { public function assign($data) { return $this; } public function display($text) { return $text; } });
        $target=$channel==='email'?'fixture@example.invalid':'13000000000';
        check(atomicRoute('index','reg_msg',['ac'=>$channel,'to'=>$target])['code']===1
            && $GLOBALS['registration_fixture_deliveries']===[[$channel,$target]],'Normal registration message route must use isolated delivery');
        $message=\think\facade\Db::name('Msg')->order('msg_id')->find();
        check((int)$message['user_id']===0 && (int)$message['msg_type']===3 && preg_match('/^[0-9]{6}$/D',$message['msg_code'])===1,
            'Registration delivery must save its real generated code in the same guest scope later consumed by registration');
        check($model->register(registrationFixtureParam(['ac'=>$channel,'to'=>$target,'code'=>$message['msg_code']]))['code']===1
            && (int)\think\facade\Db::name('Msg')->value('msg_status')===1,'The actual delivered fixture code must complete normal registration once');
    }
    if ($mysql) {
        foreach (['user','msg','plog','group'] as $table) {
            atomicSeed(['reg_email_sms'=>1]); $param=registrationFixtureParam(atomicMessage()+['uid'=>400]);
            \think\facade\Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
            try { atomicReject($param,'A nontransactional '.$table.' table must reject registration without touching any state'); }
            finally { \think\facade\Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB'); }
        }
        $narrow = [
            ['user','user_pwd','varchar(32)','varchar(255)',[],[]],
            ['user','user_random','varchar(16)','varchar(32)',[],[]],
            ['user','user_invite_code','varchar(5)','varchar(20)',[],[]],
            ['user','user_points','smallint unsigned','int unsigned',['reg_points'=>70000],[]],
            ['plog','plog_points','smallint unsigned','int unsigned',['reg_points'=>70000],[]],
            ['plog','plog_remarks','varchar(5)','varchar(100)',[],[]],
            ['user','user_invite_count','tinyint unsigned','int unsigned',[],['user_invite_count'=>255]],
            ['user','group_id','varchar(1)','varchar(255)',$configuration,[]],
            ['user','user_invite_reward_level','tinyint unsigned','int unsigned',
                ['invite_reward_status'=>1,'invite_reward'=>[256=>['group_id'=>0,'points'=>0,'long'=>'day']]],['user_invite_count'=>255]],
        ];
        foreach ($narrow as [$table,$field,$small,$actual,$config,$parent]) {
            atomicSeed($config+['reg_email_sms'=>1],$parent);
            $param=registrationFixtureParam(atomicMessage()+['uid'=>400]);
            \think\facade\Db::execute('ALTER TABLE audit_'.$table.' MODIFY '.$field.' '.$small." NOT NULL DEFAULT '0'");
            try { atomicReject($param,'Non-strict clipping of '.$table.'.'.$field.' must be detected and roll back the entire transaction'); }
            finally { \think\facade\Db::execute('ALTER TABLE audit_'.$table.' MODIFY '.$field.' '.$actual." NOT NULL DEFAULT '0'"); }
        }
        atomicSeed(['reg_email_sms'=>1]); $param=registrationFixtureParam(atomicMessage()+['uid'=>400]);
        $connection=\think\facade\Db::connect()->getConfig();
        $holder=new \PDO('mysql:host='.$connection['hostname'].';dbname=maccms_audit_user_registration;charset=utf8mb4','root',$connection['password']);
        $name=hash('sha256','maccms_audit_user_registration|audit_user|email|fixture@example.invalid');
        $statement=$holder->prepare('SELECT GET_LOCK(?,0)'); $statement->execute([$name]);
        check((int)$statement->fetchColumn()===1,'Independent fixture connection must own the shared contact lock');
        try { atomicReject($param,'A busy contact lock must time out with every registration field and code unchanged'); }
        finally { $statement=$holder->prepare('SELECT RELEASE_LOCK(?)'); $statement->execute([$name]); }
        check($model->register($param)['code']===1,'Releasing the contact lock must allow the same valid registration to retry');
        // Separate PHP processes and writer connections, synchronized immediately before normal model calls.
        function atomicConcurrent(array $jobs): array {
            $barrier=audit_temp_dir('registration-concurrency'); $processes=[]; $streams=[];
            try {
                foreach ($jobs as $slot=>$job) {
                    $job['slot']=$slot;
                    $command=[PHP_BINARY,__DIR__.'/fixtures/framework_audit_registration_worker.php',base64_encode(json_encode($job,JSON_THROW_ON_ERROR)),$barrier];
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
        foreach (['name','quota','contact','tiers','bind_contact','reset_inviter'] as $scenario) {
            $scenarioConfiguration = $scenario==='quota' ? ['reg_num'=>1] : [];
            if (in_array($scenario,['contact','bind_contact'],true)) { $scenarioConfiguration['reg_email_sms']=1; }
            if ($scenario==='tiers') { $scenarioConfiguration=$configuration; }
            atomicSeed($scenarioConfiguration, $scenario==='reset_inviter' ? ['user_email'=>'parent@example.invalid'] : []);
            $first=registrationFixtureParam(['uid'=>400]);
            $second=registrationFixtureParam(['user_name'=>'SecondFixture','uid'=>400]);
            if ($scenario==='name') { $second=$first; }
            if (in_array($scenario,['contact','bind_contact'],true)) { $message=atomicMessage(); $first=array_replace($first,$message); $second=array_replace($second,$message); }
            $jobs=[['action'=>'register','param'=>$first,'configuration'=>$scenarioConfiguration],['action'=>'register','param'=>$second,'configuration'=>$scenarioConfiguration]];
            if ($scenario==='bind_contact') {
                atomicMessage('email',['user_id'=>400,'msg_type'=>1]);
                $jobs[1]=['action'=>'bind','param'=>$message,'configuration'=>$scenarioConfiguration];
            }
            if ($scenario==='reset_inviter') {
                atomicMessage('email',['msg_type'=>2,'msg_to'=>'parent@example.invalid']);
                $jobs[1]=['action'=>'findpass_reset','param'=>['ac'=>'email','to'=>'parent@example.invalid','code'=>'123456',
                    'user_pwd'=>'replacement-password','user_pwd2'=>'replacement-password'],'configuration'=>$scenarioConfiguration];
            }
            $results=atomicConcurrent($jobs);
            $success=count(array_filter($results,fn($result)=>($result['code']??0)===1));
            if (in_array($scenario,['tiers','reset_inviter'],true)) { check($success===2,'Independent '.$scenario.' operations must both finish successfully without lock cycles'); }
            else { check($success===1,'Concurrent '.$scenario.' submissions must commit exactly one competing operation: '.json_encode($results)); }
            $expected=$scenario==='tiers'?2:1;
            if ($scenario==='bind_contact' && $results[1]['code']===1) { $expected=0; }
            check(\think\facade\Db::name('User')->count()===1+$expected && (int)atomicUser()['user_invite_count']===$expected,
                'Concurrent '.$scenario.' must leave exact account and invitation counts');
            if ($scenario==='bind_contact') {
                check(\think\facade\Db::name('User')->where('user_email',$message['to'])->count()===1
                    && \think\facade\Db::name('Msg')->where('msg_status',1)->count()===1,
                    'Binding and registration must share recipient serialization and consume only the winning code');
            }
            if ($scenario==='tiers') {
                check((int)atomicUser()['user_points']===121 && (int)atomicUser()['user_invite_reward_level']===2,
                    'Concurrent children must credit each direct bonus and crossed tier once');
            }
            if ($scenario==='reset_inviter') {
                check(password_verify('replacement-password',atomicUser()['user_pwd']) && atomicUser()['user_random']!==str_repeat('a',32),
                    'Password reset and referral rewards must preserve both independent committed results');
            }
        }
    }
    fwrite(STDOUT,'Registration transaction audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict':'SQLite').")\n");
}
