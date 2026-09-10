<?php
/** Contact lifecycle through real authentication, ORM and TP8 routes; only delivery/UI metadata are fixtures. */
declare(strict_types=1);
namespace { require dirname(__DIR__) . '/vendor/autoload.php'; }
namespace app\common\model {
    class Group {
        public function getCache(...$args) { return [
            1=>['group_id'=>1, 'group_name'=>'Guest', 'group_type'=>''],
            2=>['group_id'=>2, 'group_name'=>'Member', 'group_type'=>''],
        ]; }
    }
}
namespace app\api\controller { class Base { public function __construct() {} } }
namespace app\index\controller {
    class Base {
        protected array $assigned = [];
        public function __construct() { $this->assigned['param'] = ['wd'=>'', 'sid'=>0, 'nid'=>0]; }
        public function assign($key, $value) { $this->assigned[$key] = $value; }
        public function fetch($template) { return \json(['template'=>$template] + $this->assigned); }
        public function error($message) { return \json(['code'=>1001, 'msg'=>$message]); }
    }
}
namespace {
    require __DIR__ . '/fixtures/framework_audit_user_messages.php';
    function json($data) { return \think\Response::create($data, 'json'); }
    function cookie($key, ...$args) { return $GLOBALS['binding_fixture_cookies'][$key] ?? null; }
    function mac_filter_xss($value) { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    function mac_password_verify($password, $hash) {
        return strlen($hash) === 32 && ctype_xdigit($hash)
            ? hash_equals(strtolower($hash), md5($password)) : password_verify($password, $hash);
    }
    $app->config->set([], 'route');
    $app->instance('session', new class {
        public function get($key) { return $GLOBALS['binding_fixture_session'][$key] ?? null; }
    });
    if (!$mysql) {
        foreach (['group_id TEXT DEFAULT "2"', 'user_end_time INTEGER DEFAULT 0', 'user_nick_name TEXT DEFAULT ""',
            'user_qq TEXT DEFAULT ""'] as $field) { \think\facade\Db::execute('ALTER TABLE audit_user ADD COLUMN '.$field); }
    }
    class BindingHttpRequest extends \think\Request { public function isCli(): bool { return false; } }
    function bindingRequest(array $post = [], array $query = [], string $method = 'POST', string $action = 'bind'): \think\Request {
        global $app;
        $request = (new BindingHttpRequest())->withServer([
            'REQUEST_METHOD'=>$method, 'HTTP_HOST'=>'example.invalid', 'SCRIPT_NAME'=>'/index.php',
            'SCRIPT_FILENAME'=>'/isolated/index.php', 'PATH_INFO'=>'/user/'.$action, 'REQUEST_URI'=>'/index.php/user/'.$action,
        ])->withPost($post)->withGet($query);
        if ($GLOBALS['binding_fixture_jwt'] !== '') { $request = $request->withHeader(['authorization'=>'Bearer '.$GLOBALS['binding_fixture_jwt']]); }
        $app->instance('request', $request);
        return $request;
    }
    function bindingAuthenticate(int $uid = 1): void {
        $row = \think\facade\Db::name('User')->where('user_id', $uid)->find();
        $GLOBALS['binding_fixture_jwt'] = \app\common\util\JwtService::encode($uid, $row['user_random']);
        $GLOBALS['user'] = $row;
        bindingRequest();
    }
    function bindingSeed(string $channel = 'email', bool $bound = false): array {
        messageFixtureSeed();
        $GLOBALS['config']['site'] = ['install_dir'=>'/'];
        $GLOBALS['config']['api']['publicapi'] = ['status'=>1, 'charge'=>0];
        $GLOBALS['config']['app'] += ['api_jwt_enabled'=>'1', 'api_jwt_secret'=>str_repeat('fixture-secret-',4)];
        $GLOBALS['binding_fixture_cookies'] = [];
        $GLOBALS['binding_fixture_session'] = ['__csrf_token__'=>'fixture-session-csrf'];
        $target = $channel === 'email' ? 'fixture+tag@example.invalid' : '13000000000';
        \think\facade\Db::name('User')->where('user_id',1)->update([
            'group_id'=>'2', 'user_pwd'=>password_hash('fixture+password%42&', PASSWORD_BCRYPT, ['cost'=>4]),
            'user_nick_name'=>'Original nickname', 'user_email'=>'', 'user_phone'=>'', 'user_'.$channel=>$bound ? $target : '',
        ]);
        bindingAuthenticate();
        return ['ac'=>$channel, 'to'=>$target, 'code'=>'123456'];
    }
    function bindingCode(array $param, array $overrides = []): void {
        \think\facade\Db::name('Msg')->insert(messageFixtureRow($overrides + [
            'user_id'=>1, 'msg_type'=>1, 'msg_to'=>$param['to'],
        ]));
    }
    function bindingRoute(string $module, string $action, array $post = [], array $query = [], string $method = 'POST'): array {
        global $app;
        $app->setNamespace('app\\'.$module);
        $request = bindingRequest($post, $query, $method, $action);
        $response = (new \think\Route($app))->dispatch($request, false);
        check($response instanceof \think\response\Json && $response->getCode() === 200, 'Contact route must return a controlled response');
        return $response->getData();
    }
    function bindingOtherAccount(array $fields = []): void {
        \think\facade\Db::name('User')->insert($fields + ['user_id'=>2, 'user_name'=>'second-fixture',
            'group_id'=>'2', 'user_status'=>1, 'user_email'=>'', 'user_phone'=>'',
            'user_random'=>str_repeat('a',32), 'user_pwd'=>password_hash('second-fixture-password', PASSWORD_BCRYPT, ['cost'=>4])]);
    }
    $model = new \app\common\model\User();
    foreach (['index','api'] as $module) {
        foreach (['email','phone'] as $channel) {
            $param = bindingSeed($channel);
            check($model->checkLogin()['code'] === 1, 'Enabled fixture account must authenticate before binding');
            $res = bindingRoute($module, 'bindmsg', $param + ['user_id'=>'2', 'type'=>'2']);
            $state = messageFixtureState();
            check($res['code'] === 1 && count($GLOBALS['message_fixture_deliveries']) === 1, 'Normal binding must reach isolated delivery');
            check(count($state[1]) === 1 && (int)$state[1][0]['user_id'] === 1 && (int)$state[1][0]['msg_type'] === 1
                && $state[1][0]['msg_to'] === $param['to'] && preg_match('/^[0-9]{6}$/D', $state[1][0]['msg_code']) === 1,
                'Binding message must use authenticated identity, actual recipient and binding purpose');
            $param['code'] = $state[1][0]['msg_code'];
            $res = bindingRoute($module, 'bind', $param + ['user_id'=>'2']);
            $after = messageFixtureState();
            check($res['code'] === 1 && $res['reauthenticate'] === 1 && $after[0][0]['user_'.$channel] === $param['to'],
                'A valid '.$module.' '.$channel.' form must bind the authenticated account');
            check((int)$after[1][0]['msg_status'] === 1 && $after[0][0]['user_random'] !== $state[0][0]['user_random'],
                'Binding must consume the code and revoke prior sessions together');
            check($model->checkLogin()['code'] === 1003, 'The real login path must reject the previous JWT after binding');
            check($model->bind($param)['code'] > 1 && messageFixtureState() === $after, 'Repeating with the old session must not mutate state');
            bindingAuthenticate();
            check($model->bind($param)['code'] > 1 && messageFixtureState() === $after, 'A fresh session must still require unbinding first');
            $res = bindingRoute($module, 'unbind', ['ac'=>$channel, 'user_pwd'=>'fixture+password%42&', 'user_id'=>'2']);
            $unbound = messageFixtureState();
            check($res['code'] === 1 && $unbound[0][0]['user_'.$channel] === '' && $unbound[1] === $after[1],
                'The normal password-confirmed unbind route must clear only the selected contact');
            check($model->checkLogin()['code'] === 1003, 'Unbinding must revoke the previous JWT');
            bindingAuthenticate();
            check($model->unbind(['ac'=>$channel, 'user_pwd'=>'fixture+password%42&'])['code'] === 1
                && messageFixtureState() === $unbound, 'Repeated explicit unbinding with fresh authentication must be idempotent');
        }
    }
    foreach ([['user_id'=>0], ['user_id'=>2], ['msg_to'=>'other@example.invalid'], ['msg_type'=>2], ['msg_type'=>3],
        ['msg_status'=>1], ['msg_time'=>time()-3600], ['msg_time'=>time()+60], ['msg_code'=>'654321']] as $mismatch) {
        $param = bindingSeed(); bindingCode($param, $mismatch); $before = messageFixtureState();
        check($model->bind($param)['code'] > 1 && messageFixtureState() === $before,
            'A nonmatching binding message must neither consume a code nor update contacts');
    }
    foreach (['email','phone'] as $channel) {
        $param = bindingSeed($channel); bindingCode($param);
        bindingOtherAccount(['user_'.$channel=>$param['to']]); $before = messageFixtureState();
        check($model->bind($param)['code'] > 1 && messageFixtureState() === $before,
            'Binding must never clear another account contact to obtain the target');
        check($model->bindmsg($param)['code'] > 1 && $GLOBALS['message_fixture_deliveries'] === [],
            'Already occupied destinations must not receive binding messages');
        $param = bindingSeed($channel, true); bindingOtherAccount(['user_'.$channel=>$param['to']]);
        $before = messageFixtureState();
        check($model->unbind(['ac'=>$channel,'user_pwd'=>'fixture+password%42&','user_id'=>'2'])['code'] === 1
            && messageFixtureState()[0][1] === $before[0][1], 'Unbinding a duplicate legacy contact must leave every other account untouched');
    }
    foreach (['bind','bindmsg','unbind'] as $action) {
        foreach ([[], ['ordinary'], null, true, 1.5] as $invalid) {
            foreach ($action === 'unbind' ? ['ac','user_pwd'] : ($action === 'bind' ? ['ac','to','code'] : ['ac','to']) as $field) {
                $param = bindingSeed(); bindingCode($param); $before = messageFixtureState();
                $param = ($action === 'unbind' ? ['ac'=>'email','user_pwd'=>'fixture+password%42&'] : $param);
                $param[$field] = $invalid;
                check($model->$action($param)['code'] > 1 && messageFixtureState() === $before,
                    'Structured or mistyped '.$action.' '.$field.' must return a controlled error');
            }
        }
        foreach (['index','api'] as $module) {
            $param = bindingSeed('email', $action === 'unbind'); bindingCode($param); $before = messageFixtureState();
            $post = $action === 'unbind' ? ['ac'=>'email','user_pwd'=>'fixture+password%42&'] : $param;
            $res = bindingRoute($module,$action,[], $post);
            check($res['code'] > 1 && messageFixtureState() === $before, 'Query parameters must not supply a contact write body');
            if ($module === 'api' || $action === 'bindmsg') {
                check(bindingRoute($module,$action,[], $post,'GET')['code'] > 1 && messageFixtureState() === $before,
                    'Mutation-only contact routes must reject GET');
            }
        }
    }
    $param = bindingSeed(); bindingCode($param); bindingOtherAccount();
    $GLOBALS['user'] = \think\facade\Db::name('User')->where('user_id',2)->find();
    check($model->bind($param)['code'] === 1 && messageFixtureState()[0][0]['user_email'] === $param['to']
        && messageFixtureState()[0][1]['user_email'] === '', 'Mutable global display identity must not select the binding account');
    foreach (['', 'wrong-fixture-password'] as $password) {
        bindingSeed('email',true); $before = messageFixtureState();
        check($model->unbind(['ac'=>'email','user_pwd'=>$password])['code'] > 1 && messageFixtureState() === $before,
            'Unbinding must preserve the contact without current password confirmation');
    }
    foreach (['md5','md5_formatted'] as $legacy) {
        bindingSeed('email',true);
        $password = 'fixture+password%42&';
        \think\facade\Db::name('User')->where('user_id',1)->update(['user_pwd'=>md5($legacy === 'md5' ? $password : htmlspecialchars(urldecode($password)))]);
        check($model->unbind(['ac'=>'email','user_pwd'=>$password])['code'] === 1, 'Historically supported passwords must support normal unbinding');
    }
    foreach (['bind','unbind'] as $action) {
        $param = bindingSeed('email', $action === 'unbind'); bindingCode($param); $before = messageFixtureState();
        $GLOBALS['message_fixture_throttle'] = false;
        $data = $action === 'unbind' ? ['ac'=>'email','user_pwd'=>'fixture+password%42&'] : $param;
        check($model->$action($data)['code'] > 1 && messageFixtureState() === $before,
            'Contact verification and password confirmation must respect the write throttle');
        foreach (['audit_user','audit_msg'] as $table) {
            if ($action === 'unbind' && $table === 'audit_msg') { continue; }
            $param = bindingSeed('email', $action === 'unbind'); bindingCode($param); $before = messageFixtureState();
            $body = $mysql ? "FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Fixture contact write failure'"
                : "BEGIN SELECT RAISE(ABORT, 'Fixture contact write failure'); END";
            \think\facade\Db::execute('CREATE TRIGGER audit_binding_write_failure BEFORE UPDATE ON '.$table.' '.$body);
            try {
                $data = $action === 'unbind' ? ['ac'=>'email','user_pwd'=>'fixture+password%42&'] : $param;
                check($model->$action($data)['code'] > 1 && messageFixtureState() === $before,
                    'A '.$table.' write failure must roll back contact, session secret and verification state together');
            } finally { \think\facade\Db::execute('DROP TRIGGER audit_binding_write_failure'); }
            check($model->$action($data)['code'] === 1, 'A normal retry must work after removing the isolated database fault');
        }
    }
    foreach (['user_email','user_phone'] as $field) {
        bindingSeed(); $before = messageFixtureState();
        $value = $field === 'user_email' ? 'fixture@example.invalid' : '13000000000';
        check(bindingRoute('api','update_info',[$field=>$value,'user_nick_name'=>'Changed nickname'])['code'] > 1
            && messageFixtureState() === $before, 'Profile update must reject unverified contact changes without partial writes');
        check($model->updateAccountProfile(1,[$field=>$value])['code'] > 1 && messageFixtureState() === $before,
            'The shared profile helper must not offer a contact-verification bypass');
    }
    bindingSeed('email',true);
    check(bindingRoute('api','update_info',['user_email'=>'fixture+tag@example.invalid','user_phone'=>'','user_nick_name'=>'Changed nickname'])['code'] === 1
        && messageFixtureState()[0][0]['user_nick_name'] === 'Changed nickname', 'Unchanged contact echoes must not break a normal full profile form');
    foreach (['bind','unbind'] as $action) {
        bindingSeed('email',true);
        $view = bindingRoute('index',$action,[],['ac'=>'email'],'GET');
        check($view['template'] === 'user/'.$action && $view['ac'] === 'email', 'Authenticated GET must reach the actual contact page');
        check($view['param'] === ['wd'=>'','sid'=>0,'nid'=>0], 'Contact pages must preserve inherited shared layout parameters');
        if ($action === 'unbind') { check($view['contact'] === 'fixture+tag@example.invalid', 'The confirmation page must display the current authenticated contact'); }
        check(bindingRoute('index',$action,[],['ac'=>[]],'GET')['code'] > 1, 'An invalid page channel must return a controlled response');
    }
    foreach (['bindmsg','bind','unbind'] as $action) {
        $param = bindingSeed('email',$action === 'unbind'); bindingCode($param);
        $row = messageFixtureState()[0][0];
        $GLOBALS['binding_fixture_jwt'] = '';
        $GLOBALS['binding_fixture_cookies'] = ['user_id'=>'1','user_name'=>$row['user_name'],
            'user_check'=>md5($row['user_random'].'-'.$row['user_name'].'-1-')];
        bindingRequest();
        check($model->checkLogin()['code'] === 1, 'Real cookie authentication must succeed before CSRF checks');
        $before = messageFixtureState();
        $data = $action === 'unbind' ? ['ac'=>'email','user_pwd'=>'fixture+password%42&'] : $param;
        check($model->$action($data)['code'] > 1 && messageFixtureState() === $before, 'Cookie-authenticated contact writes require a session CSRF token');
        foreach ([[], 'wrong-fixture-token'] as $token) {
            check($model->$action($data + ['csrf_token'=>$token])['code'] > 1 && messageFixtureState() === $before,
                'Malformed or mismatched CSRF tokens must leave all account state unchanged');
        }
        if ($action === 'bindmsg') { \think\facade\Db::name('Msg')->where('user_id',1)->delete(); }
        check($model->$action($data + ['csrf_token'=>'fixture-session-csrf'])['code'] === 1,
            'Normal browser forms must work with real cookie authentication and the session token');
    }
    if ($mysql) {
        foreach (['audit_user','audit_msg'] as $table) {
            \think\facade\Db::execute('ALTER TABLE '.$table.' ENGINE=MyISAM');
            try {
                foreach (['bind','bindmsg','unbind'] as $action) {
                    $param = bindingSeed('email',$action === 'unbind'); bindingCode($param); $before = messageFixtureState();
                    $data = $action === 'unbind' ? ['ac'=>'email','user_pwd'=>'fixture+password%42&'] : $param;
                    check($model->$action($data)['code'] > 1 && messageFixtureState() === $before && $GLOBALS['message_fixture_deliveries'] === [],
                        'A nontransactional '.$table.' must fail before sending messages or changing state');
                }
            } finally { \think\facade\Db::execute('ALTER TABLE '.$table.' ENGINE=InnoDB'); }
        }
        $param = bindingSeed(); bindingCode($param); $before = messageFixtureState();
        $lock = hash('sha256','maccms_audit_user_messages|audit_user|email|'.strtolower($param['to']));
        $pdo = new \PDO('mysql:host='.(getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1').';dbname=maccms_audit_user_messages', 'root', getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '');
        $statement = $pdo->prepare('SELECT GET_LOCK(?, 0)'); $statement->execute([$lock]);
        check((int)$statement->fetchColumn() === 1, 'Independent fixture connection must hold the target contact lock');
        try { check($model->bind($param)['code'] > 1 && messageFixtureState() === $before, 'A concurrent target lock must fail without consuming its verification'); }
        finally { $statement = $pdo->prepare('SELECT RELEASE_LOCK(?)'); $statement->execute([$lock]); }
        check($model->bind($param)['code'] === 1, 'A normal retry must work after the target contact lock is released');
        $statement = $pdo->prepare('SELECT GET_LOCK(?, 0)'); $statement->execute([$lock]);
        check((int)$statement->fetchColumn() === 1, 'Successful binding must release its advisory lock');
        $statement = $pdo->prepare('SELECT RELEASE_LOCK(?)'); $statement->execute([$lock]);
    }
    fwrite(STDOUT, 'User binding audit passed ('.$checks.' checks; '.($mysql ? 'MySQL' : 'SQLite').")\n");
}
