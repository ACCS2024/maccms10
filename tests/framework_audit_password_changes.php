<?php
/** Existing-account password changes through real models/controllers; auth uses a signed fixture JWT. */
declare(strict_types=1);
namespace { require dirname(__DIR__) . '/vendor/autoload.php'; }
namespace app\common\model {
    function captcha_check($code) { return $code === 'fixture-captcha'; }
    class Group {
        public function getCache(...$args) { return [
            1=>['group_id'=>1, 'group_name'=>'Guest', 'group_type'=>''],
            2=>['group_id'=>2, 'group_name'=>'Member', 'group_type'=>''],
        ]; }
    }
}
namespace app\api\controller { class Base {} }
namespace app\index\controller {
    class Base {
        public function success($message) { throw new \PasswordFormResult(['code'=>1, 'msg'=>$message]); }
        public function error($message) { throw new \PasswordFormResult(['code'=>1001, 'msg'=>$message]); }
    }
}
namespace {
    require __DIR__ . '/fixtures/framework_audit_user_messages.php';
    class PasswordFormResult extends \RuntimeException {
        public function __construct(public array $result) { parent::__construct('Fixture form response'); }
    }
    function json($data) { return \think\Response::create($data, 'json'); }
    function mac_filter_xss($value) { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
    function mac_get_ip_long() { return 2130706433; }
    function mac_password_need_rehash($hash) { return (strlen($hash) === 32 && ctype_xdigit($hash)) || password_needs_rehash($hash, PASSWORD_DEFAULT); }
    function mac_password_verify($password, $hash) {
        $valid = strlen($hash) === 32 && ctype_xdigit($hash)
            ? hash_equals(strtolower($hash), md5($password)) : password_verify($password, $hash);
        $hook = $GLOBALS['password_fixture_verified_hook'] ?? null;
        $GLOBALS['password_fixture_verified_hook'] = null;
        if ($hook) { $hook(); }
        return $valid;
    }
    if (!$mysql) {
        foreach (['group_id TEXT DEFAULT "2"', 'user_end_time INTEGER DEFAULT 0', 'user_nick_name TEXT DEFAULT ""', 'user_qq TEXT DEFAULT ""', 'user_login_ip INTEGER DEFAULT 0',
            'user_login_time INTEGER DEFAULT 0', 'user_login_num INTEGER DEFAULT 0', 'user_last_login_time INTEGER DEFAULT 0',
            'user_last_login_ip INTEGER DEFAULT 0'] as $field) {
            \think\facade\Db::execute('ALTER TABLE audit_user ADD COLUMN '.$field);
        }
    }
    class PasswordHttpRequest extends \think\Request { public function isCli(): bool { return false; } }
    function passwordChangeSeed(string $hashType = 'bcrypt'): string {
        global $app;
        messageFixtureSeed();
        $GLOBALS['password_fixture_verified_hook'] = null;
        $old = 'fixture+old%42&password';
        $hash = match ($hashType) {
            'md5'=>md5($old), 'md5_formatted'=>md5(htmlspecialchars(urldecode($old))),
            default=>password_hash($old, PASSWORD_BCRYPT),
        };
        \think\facade\Db::name('User')->where('user_id',1)->update(['user_pwd'=>$hash, 'user_nick_name'=>'Original nick', 'user_qq'=>'123456', 'group_id'=>2]);
        $GLOBALS['user'] = \think\facade\Db::name('User')->where('user_id',1)->find();
        $GLOBALS['config']['user']['login_verify'] = 0;
        $GLOBALS['config']['app'] += ['api_jwt_enabled'=>'1', 'api_jwt_secret'=>str_repeat('fixture-secret-',4)];
        $GLOBALS['password_fixture_jwt'] = \app\common\util\JwtService::encode(1, $GLOBALS['user']['user_random']);
        passwordChangeRequest([]);
        return $old;
    }
    function passwordChangeRequest(array $params, string $method = 'POST'): \think\Request {
        global $app;
        $request = (new PasswordHttpRequest())->withServer(['REQUEST_METHOD'=>$method])
            ->withHeader(['authorization'=>'Bearer '.$GLOBALS['password_fixture_jwt']]);
        $request = $method === 'POST' ? $request->withPost($params) : $request->withGet($params);
        $app->instance('request',$request);
        return $request;
    }
    function passwordChangeCall(string $path, array $params): array {
        if ($path === 'api') {
            $request = passwordChangeRequest($params);
            $controller = (new \ReflectionClass(\app\api\controller\User::class))->newInstanceWithoutConstructor();
            return $controller->update_info($request)->getData();
        }
        if ($path === 'frontend') {
            passwordChangeRequest($params);
            $controller = (new \ReflectionClass(\app\index\controller\User::class))->newInstanceWithoutConstructor();
            try { $controller->info(); }
            catch (PasswordFormResult $result) { return $result->result; }
            throw new \RuntimeException('Frontend form did not return a controlled response');
        }
        $model = new \app\common\model\User();
        return $path === 'recovery' ? $model->findpass($params) : $model->saveData($params);
    }
    function passwordChangeParams(string $path, string $old, string $new): array {
        if ($path === 'api') { return ['user_old_pwd'=>$old, 'user_new_pwd'=>$new]; }
        if ($path === 'frontend') { return ['user_pwd'=>$old, 'user_pwd1'=>$new, 'user_pwd2'=>$new]; }
        if ($path === 'recovery') { return ['user_name'=>'fixture-user', 'user_question'=>'Fixture question',
            'user_answer'=>'Fixture answer', 'user_pwd'=>$new, 'user_pwd2'=>$new, 'verify'=>'fixture-captcha']; }
        return ['user_id'=>1, 'user_name'=>'fixture-user', 'user_pwd'=>$new];
    }
    $model = new \app\common\model\User();
    foreach (['api', 'frontend', 'recovery', 'admin'] as $path) {
        foreach (in_array($path, ['api','frontend'], true) ? ['md5', 'md5_formatted', 'bcrypt'] : ['md5', 'bcrypt'] as $hashType) {
            $old = passwordChangeSeed($hashType);
            check($model->checkLogin()['code'] === 1, 'Signed fixture must authenticate before password modification');
            $before = messageFixtureState();
            $new = 'fixture+new%42&password';
            $res = passwordChangeCall($path, passwordChangeParams($path,$old,$new));
            $after = messageFixtureState();
            check($res['code'] === 1 && password_verify($new,$after[0][0]['user_pwd']),
                $path.' must support '.$hashType.' and store the literal new password with a modern hash');
            check($after[0][0]['user_random'] !== $before[0][0]['user_random'] && strlen($after[0][0]['user_random']) === 32,
                $path.' must revoke prior sessions in the same credential update');
            check($model->checkLogin()['code'] === 1003, $path.' must make the actual login path reject the old JWT');
            foreach (['user_question','user_answer','user_qq','user_nick_name'] as $field) {
                check($after[0][0][$field] === $before[0][0][$field], $path.' password-only form must preserve absent '.$field);
            }
        }
        foreach (['short', str_repeat('p',73)] as $invalidPassword) {
            $old = passwordChangeSeed();
            $before = messageFixtureState();
            check(passwordChangeCall($path,passwordChangeParams($path,$old,$invalidPassword))['code'] > 1
                && messageFixtureState() === $before, $path.' must reject invalid new-password lengths without partial changes');
        }
        $old = passwordChangeSeed();
        $before = messageFixtureState();
        $GLOBALS['message_fixture_password_write_failure'] = true;
        check(passwordChangeCall($path,passwordChangeParams($path,$old,'fixture-valid-password'))['code'] > 1
            && messageFixtureState() === $before, $path.' database failure must preserve the previous password and session');
    }
    foreach (['api','frontend'] as $path) {
        $old = passwordChangeSeed('md5_formatted');
        $login = $model->login(['user_name'=>'fixture-user', 'user_pwd'=>$old], ['set_cookie'=>false, 'return_meta'=>true]);
        check($login['code'] === 1, 'A historical formatted-MD5 account must complete real password login');
        $loggedIn = messageFixtureState()[0][0];
        check(password_verify($old, $loggedIn['user_pwd']), 'Legacy login must upgrade to a modern hash of the original password');
        $GLOBALS['user'] = $loggedIn;
        $GLOBALS['password_fixture_jwt'] = \app\common\util\JwtService::encode(1, $login['meta']['user_random']);
        $new = 'post-login+fixture%42&password';
        check(passwordChangeCall($path,passwordChangeParams($path,$old,$new))['code'] === 1
            && password_verify($new,messageFixtureState()[0][0]['user_pwd']),
            'The same historical account must be able to change its password after real login');
        check($model->checkLogin()['code'] === 1003, 'A historical account password change must invalidate its actual login token');

        $old = passwordChangeSeed();
        \think\facade\Db::name('User')->where('user_id',1)->update([
            'user_pwd'=>password_hash(htmlspecialchars(urldecode($old)), PASSWORD_BCRYPT),
        ]);
        $before = messageFixtureState();
        check($model->login(['user_name'=>'fixture-user', 'user_pwd'=>$old], ['set_cookie'=>false])['code'] > 1
            && messageFixtureState() === $before, 'Modern password login must not accept historical encoding aliases');
        check(passwordChangeCall($path,passwordChangeParams($path,$old,'fixture-new-password'))['code'] > 1
            && messageFixtureState() === $before, 'Modern password changes must not accept historical encoding aliases');
    }
    foreach (['api','frontend'] as $path) {
        $old = passwordChangeSeed();
        $params = passwordChangeParams($path,'incorrect-fixture','fixture-valid-password') + ['user_nick_name'=>'Changed nick'];
        $before = messageFixtureState();
        check(passwordChangeCall($path,$params)['code'] > 1 && messageFixtureState() === $before,
            $path.' incorrect old password must not allow a partial profile update');
        $old = passwordChangeSeed();
        $before = messageFixtureState();
        check(passwordChangeCall($path,['user_nick_name'=>'Updated fixture'])['code'] === 1,
            $path.' ordinary profile-only form must remain usable');
        $after = messageFixtureState();
        check($after[0][0]['user_pwd'] === $before[0][0]['user_pwd'] && $after[0][0]['user_random'] === $before[0][0]['user_random']
            && $after[0][0]['user_question'] === $before[0][0]['user_question'],
            $path.' profile-only form must preserve credentials and absent security questions');
        $params = passwordChangeParams($path,$old,'fixture-valid-password') + ['user_nick_name'=>'Changed nick'];
        foreach (array_keys($params) as $field) {
            foreach ([[],['ordinary-field'],null,true,1.5] as $invalid) {
                passwordChangeSeed();
                $typed = $params;
                $typed[$field] = $invalid;
                $before = messageFixtureState();
                check(passwordChangeCall($path,$typed)['code'] > 1 && messageFixtureState() === $before,
                    $path.' non-text '.$field.' must return a controlled response without updates');
            }
        }
    }
    foreach (['api','frontend'] as $path) {
        $old = passwordChangeSeed();
        $before = messageFixtureState();
        check(passwordChangeCall($path,passwordChangeParams($path,$old,'fixture-valid-password') + ['user_qq'=>str_repeat('1',17)])['code'] > 1
            && messageFixtureState() === $before,
            $path.' oversized profile data must not truncate fields or partially change credentials');
    }
    foreach (['api','frontend'] as $path) {
        $old = passwordChangeSeed();
        $newerState = null;
        $GLOBALS['password_fixture_verified_hook'] = static function () use (&$newerState): void {
            \think\facade\Db::name('User')->where('user_id',1)->update([
                'user_pwd'=>password_hash('newer-fixture-password', PASSWORD_BCRYPT), 'user_random'=>str_repeat('f',32),
            ]);
            $newerState = messageFixtureState();
        };
        check(passwordChangeCall($path,passwordChangeParams($path,$old,'stale-fixture-password'))['code'] > 1
            && messageFixtureState() === $newerState,
            $path.' must not overwrite a password changed after its old-hash verification');
    }
    foreach ([['user_old_pwd'=>'fixture+old%42&password'], ['user_new_pwd'=>'fixture-valid-password']] as $incomplete) {
        passwordChangeSeed();
        $before = messageFixtureState();
        check(passwordChangeCall('api',$incomplete + ['user_nick_name'=>'Changed nick'])['code'] > 1
            && messageFixtureState() === $before, 'API incomplete password form must not partially update the profile');
    }
    passwordChangeSeed();
    $before = messageFixtureState();
    $controller = (new \ReflectionClass(\app\api\controller\User::class))->newInstanceWithoutConstructor();
    check($controller->update_info(passwordChangeRequest(['user_nick_name'=>'Changed nick'],'GET'))->getData()['code'] > 1
        && messageFixtureState() === $before, 'API profile changes must require POST');
    $old = passwordChangeSeed();
    $before = messageFixtureState();
    $request = passwordChangeRequest([])->withGet(passwordChangeParams('api',$old,'query-fixture-password') + ['user_nick_name'=>'Query nick']);
    check($controller->update_info($request)->getData()['code'] > 1 && messageFixtureState() === $before,
        'POST with query-only credentials/profile must not modify the account');
    $old = passwordChangeSeed();
    $before = messageFixtureState();
    $request = passwordChangeRequest(['user_nick_name'=>'Body nick'])->withGet(
        passwordChangeParams('api',$old,'query-fixture-password') + ['user_nick_name'=>'Query nick']);
    check($controller->update_info($request)->getData()['code'] === 1
        && messageFixtureState()[0][0]['user_nick_name'] === 'Body nick'
        && messageFixtureState()[0][0]['user_pwd'] === $before[0][0]['user_pwd']
        && messageFixtureState()[0][0]['user_random'] === $before[0][0]['user_random'],
        'Query credentials must not complete a profile-only POST body or replace its fields');
    $old = passwordChangeSeed();
    $request = passwordChangeRequest(passwordChangeParams('api',$old,'body-fixture-password') + ['user_nick_name'=>'Body nick'])
        ->withGet(passwordChangeParams('api','incorrect-query-password','query-fixture-password') + ['user_nick_name'=>['ordinary-query']]);
    check($controller->update_info($request)->getData()['code'] === 1
        && password_verify('body-fixture-password',messageFixtureState()[0][0]['user_pwd'])
        && messageFixtureState()[0][0]['user_nick_name'] === 'Body nick',
        'A normal POST body must succeed independently of conflicting query fields');
    foreach (['user_old_pwd','user_new_pwd'] as $queryField) {
        $old = passwordChangeSeed();
        $body = passwordChangeParams('api',$old,'body-fixture-password');
        $query = [$queryField=>$body[$queryField]];
        unset($body[$queryField]);
        $before = messageFixtureState();
        check($controller->update_info(passwordChangeRequest($body)->withGet($query))->getData()['code'] > 1
            && messageFixtureState() === $before, 'Query values must not supply missing POST '.$queryField);
    }
    foreach (['api','frontend'] as $path) {
        passwordChangeSeed();
        $before = messageFixtureState();
        check(passwordChangeCall($path,['user_nick_name'=>"\xC3\x28"])['code'] > 1
            && messageFixtureState() === $before, 'Invalid UTF-8 profile text must fail without data loss');
    }
    passwordChangeSeed();
    $GLOBALS['password_fixture_jwt'] = '';
    $request = passwordChangeRequest(['user_nick_name'=>'Changed nick']);
    // An invalid signed-looking token enters the JWT validation branch without cookie fallback.
    $request->withHeader(['authorization'=>'Bearer fixture-invalid-token']);
    $before = messageFixtureState();
    check($controller->update_info($request)->getData()['code'] > 1 && messageFixtureState() === $before,
        'An unauthenticated API request must preserve the account');
    passwordChangeSeed();
    $before = messageFixtureState();
    check(passwordChangeCall('admin',['user_id'=>1,'user_name'=>'fixture-user','user_pwd'=>''])['code'] === 1
        && messageFixtureState() === $before, 'An empty administrative password must keep the existing credentials');
    passwordChangeSeed();
    $before = messageFixtureState();
    $params = passwordChangeParams('recovery','unused','fixture-valid-password');
    $params['verify'] = 'wrong-fixture';
    check(passwordChangeCall('recovery',$params)['code'] > 1 && messageFixtureState() === $before,
        'Security-question recovery must still require its captcha');
    $params['verify'] = 'fixture-captcha';
    $params['user_answer'] = 'Different fixture answer';
    check(passwordChangeCall('recovery',$params)['code'] > 1 && messageFixtureState() === $before,
        'Security-question recovery must still require the matching answer');
    echo 'framework_audit_password_changes: '.$checks.' checks passed on PHP '.PHP_VERSION.' ('.($mysql ? 'MySQL non-strict' : 'SQLite').')'.PHP_EOL;
}
