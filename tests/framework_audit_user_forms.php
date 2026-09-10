<?php
/** TP8 routes and real User model with SQLite; message delivery and captcha are fixture boundaries. */
declare(strict_types=1);
namespace { require dirname(__DIR__) . '/vendor/autoload.php'; }
namespace app\index\controller {
    class Base {
        protected array $assigned = [];
        public function __construct() {}
        public function assign($key, $value) { $this->assigned[$key] = $value; }
        public function fetch($template) { return \json(['template'=>$template] + $this->assigned); }
    }
}
namespace app\common\model {
    function captcha_check($code) { $GLOBALS['form_captcha_calls'][] = $code; return $code === 'fixture-captcha'; }

}
namespace {
    require __DIR__ . '/fixtures/security_audit_test_helpers.php';
    function lang($key, $vars = []) { return $key; }
    function request() { return \think\Container::getInstance()->make('request'); }
    function json($data) { return \think\Response::create($data, 'json'); }
    function url($path, $param = []) { return '/index.php/' . $path . ($param ? '?' . http_build_query($param) : ''); }
    function redirect($path) { return \think\Response::create($path, 'redirect', 302); }
    function mac_fe_write_throttle(...$args) { return true; }
    function mac_get_rndstr(...$args) { return '123456'; }
    function mac_validate($name) { $class = 'app\\common\\validate\\'.$name; return new $class(); }
    function mac_password_hash($password) { return password_hash($password, PASSWORD_BCRYPT); }
    function mac_send_mail($to, $title, $body) {
        if ($to !== 'fixture@example.invalid') { throw new \RuntimeException('Unexpected fixture recipient'); }
        $GLOBALS['form_deliveries'][] = ['email', $to];
        return ['code'=>1, 'msg'=>'fixture'];
    }
    function mac_send_sms($to, ...$args) {
        if ($to !== '13000000000') { throw new \RuntimeException('Unexpected fixture recipient'); }
        $GLOBALS['form_deliveries'][] = ['phone', $to];
        return ['code'=>1, 'msg'=>'fixture'];
    }
    $temp = audit_temp_dir('user-forms');
    $app = new \think\App($temp);
    $app->setNamespace('app\\index');
    $app->config->set([], 'route');
    $configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
        'type'=>'sqlite', 'database'=>':memory:', 'prefix'=>'audit_', 'trigger_sql'=>false, 'fields_cache'=>false,
    ]]];
    $app->config->set($configuration, 'database');
    $manager = new \think\DbManager();
    $manager->setConfig($configuration);
    $app->instance('think\\DbManager', $manager);
    $app->instance('view', new class {
        public function assign($data) { return $this; }
        public function display($text) { return $text; }
    });
    $GLOBALS['config'] = [
        'site'=>['install_dir'=>'/'], 'user'=>[],
        'email'=>['time'=>'5', 'tpl'=>[
            'user_reg_title'=>'Fixture registration', 'user_reg_body'=>'Fixture code',
            'user_findpass_title'=>'Fixture reset', 'user_findpass_body'=>'Fixture code',
        ]], 'sms'=>['content'=>'Fixture [类型] [验证码]'],
    ];
    $GLOBALS['user'] = ['user_id'=>0, 'user_name'=>''];
    $GLOBALS['form_deliveries'] = $GLOBALS['form_captcha_calls'] = [];
    \think\facade\Db::execute('CREATE TABLE audit_user (user_id INTEGER PRIMARY KEY, user_name TEXT, user_email TEXT,
        user_phone TEXT, user_question TEXT, user_answer TEXT, user_pwd TEXT, user_random TEXT DEFAULT "27a3cdfa9e70e883209a8dd590321657")');
    \think\facade\Db::name('User')->insert(['user_id'=>1, 'user_name'=>'fixture-user', 'user_email'=>'fixture@example.invalid',
        'user_phone'=>'13000000000', 'user_question'=>'Fixture question', 'user_answer'=>'Fixture answer', 'user_pwd'=>'initial-fixture']);
    \think\facade\Db::execute('CREATE TABLE audit_msg (msg_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER DEFAULT 0,
        msg_type INTEGER DEFAULT 0, msg_status INTEGER DEFAULT 0, msg_to TEXT, msg_code TEXT, msg_content TEXT, msg_time INTEGER)');
    class FormHttpRequest extends \think\Request {
        public function isCli(): bool { return false; }
    }
    function formRequest(string $action, array $params = [], string $method = 'POST'): \think\Response {
        global $app;
        $request = (new FormHttpRequest())->withServer([
            'REQUEST_METHOD'=>$method, 'HTTP_HOST'=>'example.invalid', 'SCRIPT_NAME'=>'/index.php',
            'SCRIPT_FILENAME'=>'/isolated/index.php', 'PATH_INFO'=>'/user/'.$action,
            'REQUEST_URI'=>'/index.php/user/'.$action,
        ]);
        $request = $method === 'POST' ? $request->withPost($params) : $request->withGet($params);
        $app->instance('request', $request);
        return (new \think\Route($app))->dispatch($request, false);
    }
    function formCall(string $action, array $params = [], string $method = 'POST'): array {
        $response = formRequest($action, $params, $method);
        check($response->getCode() === 200 && $response instanceof \think\response\Json, $action.' did not return controlled JSON');
        return $response->getData();
    }
    function formPassword(): string { return (string)\think\facade\Db::name('User')->where('user_id',1)->value('user_pwd'); }
    try {
        check(formCall('regcheck', ['t'=>'user_name', 'str'=>'unused-fixture'], 'GET')['code'] === 1,
            'Guest registration availability route must be reachable');
        check(formCall('regcheck', ['t'=>'user_name', 'str'=>'fixture-user'], 'GET')['code'] === 1001,
            'An existing registration must return its model error in JSON');
        check(formCall('regcheck', ['t'=>'user_email', 'str'=>'fixture@example.invalid'], 'GET')['code'] === 1001,
            'Existing email must retain availability validation');
        check(formCall('regcheck', ['t'=>'verify', 'str'=>'wrong-fixture'], 'GET')['code'] === 1002,
            'Captcha rejection must remain enforced');
        foreach ([[], ['t'=>'unknown', 'str'=>'fixture'], ['t'=>'user_name'], ['str'=>'fixture']] as $params) {
            check(formCall('regcheck', $params, 'GET')['code'] > 1, 'Incomplete availability form must fail');
        }
        $redirect = formRequest('findpass_msg', [], 'GET');
        check($redirect->getCode() === 302 && $redirect->getHeader('Location') === '/index.php/user/findpass_msg?ac=email',
            'Missing recovery channel must redirect to an explicit template channel');
        check(formCall('findpass', [], 'GET')['template'] === 'user/findpass', 'Security-question form must remain guest accessible');
        foreach (['email'=>'email', 'phone'=>'mobile'] as $channel=>$label) {
            $page = formCall('findpass_msg', ['ac'=>$channel], 'GET');
            check($page['template'] === 'user/findpass_msg' && $page['param']['ac_text'] === $label,
                'Recovery form must preserve the selected channel');
        }
        $find = ['user_name'=>'fixture-user', 'user_question'=>'Fixture question', 'user_answer'=>'Fixture answer',
            'user_pwd'=>'fixture-new-password', 'user_pwd2'=>'fixture-new-password', 'verify'=>'wrong-fixture'];
        check(formCall('findpass', $find)['code'] === 1002 && formPassword() === 'initial-fixture',
            'Normal recovery form must retain captcha validation');
        $find['verify'] = 'fixture-captcha';
        check(formCall('findpass', $find)['code'] === 1 && password_verify('fixture-new-password', formPassword()),
            'Valid fixture question/captcha must use the real password update path');
        foreach (['reg_msg', 'findpass_msg'] as $action) {
            foreach (['email'=>'fixture@example.invalid', 'phone'=>'13000000000'] as $channel=>$target) {
                $before = \think\facade\Db::name('Msg')->count();
                check(formCall($action, ['ac'=>$channel, 'to'=>$target, 'verify'=>'fixture-captcha'])['code'] === 1
                    && \think\facade\Db::name('Msg')->count() === $before + 1,
                    'Normal message form without code must reach isolated delivery');
            }
            foreach ([[], ['ac'=>'email'], ['to'=>'fixture@example.invalid'], ['ac'=>'email','to'=>'mistyped-address'],
                ['ac'=>'phone','to'=>'123']] as $params) {
                $before = count($GLOBALS['form_deliveries']);
                check(formCall($action, $params)['code'] > 1 && count($GLOBALS['form_deliveries']) === $before,
                    'Invalid message form must not deliver');
            }
        }
        $reset = ['ac'=>'email', 'to'=>'fixture@example.invalid', 'code'=>'123456',
            'user_pwd'=>'fixture-reset-password', 'user_pwd2'=>'fixture-reset-password'];
        \think\facade\Db::name('Msg')->where('user_id',0)->delete();
        $before = formPassword();
        check(formCall('findpass_reset', $reset)['code'] === 9002 && formPassword() === $before,
            'A missing message record must prevent password changes');
        \think\facade\Db::name('Msg')->insert(['user_id'=>0, 'msg_type'=>2, 'msg_status'=>0,
            'msg_to'=>'fixture@example.invalid', 'msg_code'=>'123456', 'msg_content'=>'Fixture reset', 'msg_time'=>time()]);
        check(formCall('findpass_reset', $reset)['code'] === 1 && password_verify('fixture-reset-password', formPassword()),
            'Normal reset form without optional user_email must use its verified destination');
        foreach (['findpass', 'findpass_reset'] as $action) {
            check(formCall($action)['code'] > 1, 'Absent recovery fields must produce a model error');
        }
        foreach (['reg_msg', 'findpass_reset'] as $action) {
            $before = count($GLOBALS['form_deliveries']);
            check(formCall($action, $reset, 'GET')['code'] > 1 && count($GLOBALS['form_deliveries']) === $before,
                'GET must not invoke a message or password mutation');
        }
        $forms = [
            'regcheck'=>['t'=>'user_name', 'str'=>'fixture-user'],
            'findpass'=>$find,
            'findpass_msg'=>['ac'=>'email', 'to'=>'fixture@example.invalid', 'code'=>'', 'verify'=>'fixture-captcha'],
            'reg_msg'=>['ac'=>'email', 'to'=>'fixture@example.invalid', 'code'=>'', 'verify'=>'fixture-captcha'],
            'findpass_reset'=>$reset + ['user_email'=>''],
        ];
        foreach ($forms as $action=>$valid) {
            foreach (array_keys($valid) as $field) {
                foreach ([[], ['ordinary-field'], null, true, 1.5] as $invalid) {
                    $params = $valid;
                    $params[$field] = $invalid;
                    $before = [formPassword(), count($GLOBALS['form_deliveries'])];
                    check(formCall($action, $params)['code'] > 1
                        && [formPassword(), count($GLOBALS['form_deliveries'])] === $before,
                        $action.' must reject a non-text '.$field.' without side effects');
                }
            }
        }
        check((new \ReflectionMethod(\app\index\controller\User::class, 'userFormParameters'))->isPrivate()
            && (new \ReflectionMethod(\app\index\controller\User::class, 'userMessageTargetIsValid'))->isPrivate(),
            'Form helpers must not become public routes');
        echo 'framework_audit_user_forms: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
    } finally {
        audit_remove_temp($temp);
    }
}
