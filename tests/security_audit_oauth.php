<?php
// No application boot, database, provider request or live session is used.
namespace app\common\model {
    class Base {
        public function where(...$args) { $GLOBALS['oauth_fixture_query_reached'] = true; throw new \QueryReached(); }
    }
}
namespace {
    final class QueryReached extends RuntimeException {}
    $sessionData = [];
    $checks = 0;
    function session($key, $value = null) {
        global $sessionData;
        if (func_num_args() === 1) { return $sessionData[$key] ?? null; }
        if ($value === null) { unset($sessionData[$key]); } else { $sessionData[$key] = $value; }
    }
    function lang($key) { return $key; }
    function config($key) { return ['user' => ['status' => 1, 'reg_open' => 1, 'reg_verify' => 1]]; }
    function mac_fe_write_throttle(...$args) { return true; }
    function captcha_check($value) { return false; }
    function check($condition, $label) {
        global $checks;
        if (!$condition) { throw new RuntimeException('FAIL: ' . $label); }
        ++$checks;
    }
    function reachesQuery(callable $call, $label) {
        $GLOBALS['oauth_fixture_query_reached'] = false;
        try { $call(); } catch (QueryReached $e) {}
        check($GLOBALS['oauth_fixture_query_reached'], $label);
    }
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    require dirname(__DIR__) . '/application/common/util/OAuthState.php';
    require dirname(__DIR__) . '/application/common/util/PointsBalance.php';
    require dirname(__DIR__) . '/application/common/model/User.php';
    $model = new \app\common\model\User();
    foreach ([[], ['col' => 'user_openid_qq', 'openid' => 'victim-id'],
        ['col' => 'user_openid_qq', 'openid' => 'victim-id', 'trusted_oauth' => true],
        ['user_name' => ['admin'], 'user_pwd' => 'test'], ['openid' => ['victim-id']]] as $input) {
        check($model->login($input)['code'] !== 1, 'untrusted password-free login rejected before database');
    }
    reachesQuery(static fn() => $model->login(['col' => 'user_openid_qq', 'openid' => 'verified-id'],
        ['trusted_oauth' => true]), 'verified server-side OAuth flow retains access');
    check($model->login(['col' => 'user_name', 'openid' => 'admin'], ['trusted_oauth' => true])['code'] !== 1,
        'server-side OAuth still requires allowlisted identity column');
    $registration = ['user_name' => 'member123', 'user_pwd' => 'secret', 'user_pwd2' => 'secret',
        'user_openid_qq' => 'forged-id', 'trusted_oauth' => true];
    check($model->register($registration)['code'] === 1003, 'raw openid does not bypass registration captcha');
    reachesQuery(static fn() => $model->register($registration, true), 'verified OAuth registration remains supported');
    check($model->register(['user_name' => []])['code'] !== 1, 'malformed registration returns validation error');

    $state = \app\common\util\OAuthState::issue('qq', 7);
    check(strlen($state) === 64, 'state has 256 bits of randomness');
    check(!\app\common\util\OAuthState::consume('qq', '', 7), 'missing state rejected');
    check(!\app\common\util\OAuthState::consume('qq', [$state], 7), 'array state rejected');
    check(!\app\common\util\OAuthState::consume('qq', str_repeat('0', 64), 7), 'wrong state rejected');
    check(!\app\common\util\OAuthState::consume('weixin', $state, 7), 'provider mismatch rejected');
    check(!\app\common\util\OAuthState::consume('qq', $state, 8), 'local identity change rejected');
    check(\app\common\util\OAuthState::consume('qq', $state, 7), 'valid state accepted');
    check(!\app\common\util\OAuthState::consume('qq', $state, 7), 'replayed state rejected');
    $state = \app\common\util\OAuthState::issue('qq', 0);
    $sessionData['oauth_state_qq']['expires'] = time() - 1;
    check(!\app\common\util\OAuthState::consume('qq', $state, 0), 'expired state rejected');
    $state = \app\common\util\OAuthState::issue('weixin', 0);
    $sessionData = [];
    check(!\app\common\util\OAuthState::consume('weixin', $state, 0), 'another session rejected');
    foreach (['unknown', '../qq', ['qq'], null] as $provider) {
        check(!\app\common\util\OAuthState::supports($provider), 'provider allowlist enforced');
    }
    echo "OAuth identity boundary: {$checks} checks passed on PHP " . PHP_VERSION . "\n";
}
