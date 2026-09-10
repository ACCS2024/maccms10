<?php
/** Normal password-recovery lifecycle and database failure recovery, using isolated fixture accounts. */
declare(strict_types=1);
namespace app\common\model {
    // Group metadata is peripheral; User authentication and account/message queries are real.
    class Group {
        public function getCache(...$args) { return [
            1=>['group_id'=>1, 'group_name'=>'Guest', 'group_type'=>''],
            2=>['group_id'=>2, 'group_name'=>'Member', 'group_type'=>''],
        ]; }
    }
}
namespace {
require __DIR__ . '/fixtures/framework_audit_user_messages.php';
if (!$mysql) {
    \think\facade\Db::execute('ALTER TABLE audit_user ADD COLUMN group_id TEXT DEFAULT "2"');
    \think\facade\Db::execute('ALTER TABLE audit_user ADD COLUMN user_end_time INTEGER DEFAULT 0');
}
$model = new \app\common\model\User();
function resetFixtureParam(array $overrides = []): array {
    return $overrides + ['ac'=>'email', 'to'=>'fixture@example.invalid', 'code'=>'123456',
        'user_pwd'=>'fixture+%42&password', 'user_pwd2'=>'fixture+%42&password'];
}
function resetFixtureSeed(string $channel = 'email'): void {
    messageFixtureSeed();
    \think\facade\Db::name('User')->where('user_id',1)->update(['group_id'=>'2']);
    \think\facade\Db::name('Msg')->insert(messageFixtureRow([
        'msg_to'=>$channel === 'email' ? 'fixture@example.invalid' : '13000000000',
    ]));
}
foreach (['email'=>'fixture@example.invalid', 'phone'=>'13000000000'] as $channel=>$target) {
    resetFixtureSeed($channel);
    $before = messageFixtureState();
    $GLOBALS['config']['app'] += ['api_jwt_enabled'=>'1', 'api_jwt_secret'=>str_repeat('fixture-secret-', 4)];
    $oldToken = \app\common\util\JwtService::encode(1, $before[0][0]['user_random']);
    check(\app\common\util\JwtService::decodeAndVerify($oldToken) !== null, 'Fixture session token must be validly signed');
    $app->instance('request', (new \think\Request())->withHeader(['authorization'=>'Bearer '.$oldToken]));
    check($model->checkLogin()['code'] === 1, 'The enabled fixture account must authenticate using its old JWT before reset');
    $param = resetFixtureParam(['ac'=>$channel, 'to'=>$target]);
    $res = $model->findpass_reset($param);
    $after = messageFixtureState();
    check($res['code'] === 1 && password_verify($param['user_pwd'], $after[0][0]['user_pwd']),
        'Normal '.$channel.' reset must preserve literal password characters');
    check($after[0][0]['user_random'] !== $before[0][0]['user_random']
        && is_string($after[0][0]['user_random']) && strlen($after[0][0]['user_random']) === 32,
        'A successful reset must rotate the existing session secret');
    $app->instance('request', (new \think\Request())->withHeader(['authorization'=>'Bearer '.$oldToken]));
    check(\app\common\util\JwtService::bearerFromRequest() === $oldToken, 'Fixture authorization header must enter the real JWT login branch');
    check($model->checkLogin()['code'] === 1003, 'The real login path must reject a previously issued JWT after reset');
    check((int)$after[1][0]['msg_status'] === 1 && $after[1][0]['msg_to'] === $target,
        'A successful reset must consume the matching fixture code');
    $res = $model->findpass_reset($param);
    check($res['code'] > 1 && messageFixtureState() === $after,
        'An already completed reset must not update the account a second time');
}
foreach ([[], ['ac'=>'email'], ['to'=>'fixture@example.invalid'], resetFixtureParam(['code'=>'']),
    resetFixtureParam(['user_pwd'=>'short', 'user_pwd2'=>'short']), resetFixtureParam(['user_pwd2'=>'different-fixture']),
    resetFixtureParam(['user_email'=>'different@example.invalid'])] as $invalid) {
    resetFixtureSeed();
    $before = messageFixtureState();
    $res = $model->findpass_reset($invalid);
    check(is_array($res) && ($res['code'] ?? 1) > 1 && messageFixtureState() === $before,
        'Invalid recovery input must leave both password and code unchanged');
}
foreach ([str_repeat('p', 73), '密'.str_repeat('p', 70)] as $tooLong) {
    resetFixtureSeed();
    $before = messageFixtureState();
    check($model->findpass_reset(resetFixtureParam(['user_pwd'=>$tooLong, 'user_pwd2'=>$tooLong]))['code'] > 1
        && messageFixtureState() === $before, 'Passwords exceeding bcrypt byte capacity must not be silently truncated');
}
resetFixtureSeed();
$maximumPassword = str_repeat('p', 72);
check($model->findpass_reset(resetFixtureParam(['user_pwd'=>$maximumPassword, 'user_pwd2'=>$maximumPassword]))['code'] === 1
    && password_verify($maximumPassword, messageFixtureState()[0][0]['user_pwd']),
    'A password at the bcrypt byte limit must remain usable');
foreach (['ac', 'to', 'user_email', 'code', 'user_pwd', 'user_pwd2'] as $field) {
    foreach ([[], ['ordinary-field'], null, true, 1.5] as $invalid) {
        resetFixtureSeed();
        $before = messageFixtureState();
        $res = $model->findpass_reset(resetFixtureParam([$field=>$invalid]));
        check(is_array($res) && ($res['code'] ?? 1) > 1 && messageFixtureState() === $before,
            'Structured or mistyped recovery field '.$field.' must return a controlled error');
    }
}
resetFixtureSeed();
$before = messageFixtureState();
$GLOBALS['message_fixture_throttle'] = false;
check($model->findpass_reset(resetFixtureParam())['code'] > 1 && messageFixtureState() === $before,
    'The existing reset throttle must continue preventing password changes');
resetFixtureSeed();
\think\facade\Db::name('Msg')->where('user_id', 0)->delete();
$before = messageFixtureState();
check($model->findpass_reset(resetFixtureParam())['code'] > 1 && messageFixtureState() === $before,
    'Recovery without a matching message record must not change the account');
resetFixtureSeed();
\think\facade\Db::name('User')->where('user_id', 1)->delete();
$before = messageFixtureState();
check($model->findpass_reset(resetFixtureParam())['code'] > 1 && messageFixtureState() === $before,
    'A missing destination account must not consume a valid code');
resetFixtureSeed();
\think\facade\Db::name('User')->insert(['user_id'=>2, 'user_name'=>'duplicate-fixture',
    'user_email'=>'fixture@example.invalid', 'user_phone'=>'', 'user_pwd'=>'second-fixture-password',
    'user_random'=>'abcdef0123456789abcdef0123456789']);
$before = messageFixtureState();
check($model->findpass_reset(resetFixtureParam())['code'] > 1 && messageFixtureState() === $before,
    'A legacy duplicate email must require data repair and must not choose or update multiple accounts');
resetFixtureSeed();
$before = messageFixtureState();
$GLOBALS['message_fixture_password_write_failure'] = true;
$res = $model->findpass_reset(resetFixtureParam());
check(is_array($res) && ($res['code'] ?? 1) > 1 && messageFixtureState() === $before,
    'A real password UPDATE failure must roll back code consumption and secret rotation');
resetFixtureSeed();
messageFixtureTrigger('audit_message_consume_failure', 'audit_msg', 'UPDATE');
try {
    $before = messageFixtureState();
    $res = $model->findpass_reset(resetFixtureParam());
    check(is_array($res) && ($res['code'] ?? 1) > 1 && messageFixtureState() === $before,
        'A real message UPDATE failure must roll back any password or secret changes');
} finally {
    \think\facade\Db::execute('DROP TRIGGER audit_message_consume_failure');
}
resetFixtureSeed();
$res = $model->findpass_reset(resetFixtureParam(['user_email'=>'fixture@example.invalid']));
check($res['code'] === 1 && password_verify('fixture+%42&password', messageFixtureState()[0][0]['user_pwd']),
    'A consistent legacy email alias must remain usable');
check($GLOBALS['message_fixture_deliveries'] === [], 'Reset tests must never invoke even the isolated delivery fixture');
if ($mysql) {
    foreach (['user', 'msg'] as $table) {
        resetFixtureSeed();
        \think\facade\Db::execute('ALTER TABLE audit_'.$table.' ENGINE=MyISAM');
        try {
            $before = messageFixtureState();
            check($model->findpass_reset(resetFixtureParam())['code'] > 1 && messageFixtureState() === $before,
                'Recovery must reject a nontransactional '.$table.' table without consuming or changing data');
        } finally {
            \think\facade\Db::execute('ALTER TABLE audit_'.$table.' ENGINE=InnoDB');
        }
    }
}
echo 'framework_audit_password_reset: '.$checks.' checks passed on PHP '.PHP_VERSION.' ('.($mysql ? 'MySQL non-strict' : 'SQLite').')'.PHP_EOL;
}
