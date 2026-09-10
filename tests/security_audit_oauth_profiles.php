<?php
namespace login {
    function config($key) { return ['qq'=>['key'=>'fixture','secret'=>'fixture'], 'weixin'=>['key'=>'fixture','secret'=>'fixture']]; }
    function curl_init() { return new \stdClass(); }
    function curl_setopt_array($handle, $options) { return true; }
    function curl_exec($handle) {
        if (!empty($GLOBALS['profile_throw'])) { throw new \TypeError('private fixture credential'); }
        return json_encode($GLOBALS['profile_response']);
    }
    function curl_error($handle) { return ''; }
    function curl_close($handle) {}
}
namespace {
    require __DIR__ . '/fixtures/security_audit_test_helpers.php';
    require dirname(__DIR__) . '/vendor/autoload.php';
    $event = new app\index\event\LoginEvent();
    $token = ['access_token'=>'fixture-token','openid'=>'fixture-identity'];
    foreach (['qq','weixin'] as $provider) {
        $base = ['nickname'=>'Test 名称', 'openid'=>'fixture-identity'];
        if ($provider === 'qq') { $base['ret'] = 0; }
        $GLOBALS['profile_response'] = $base;
        $result = $event->$provider($token);
        check($result['code'] === 1 && $result['info']['openid'] === 'fixture-identity'
            && $result['info']['name'] === 'Test 名称' && $result['info']['head'] === '', 'Valid profile with optional avatar missing failed');
        foreach ([null, [], 'bad', true, ['nickname'=>[]], array_replace($base,['openid'=>'other-identity']),
            array_replace($base,[$provider === 'qq' ? 'ret' : 'errcode'=>40001]),
            array_replace($base,[$provider === 'qq' ? 'ret' : 'errcode'=>false]),
            array_replace($base,[$provider === 'qq' ? 'figureurl_2' : 'headimgurl'=>[]])] as $response) {
            $GLOBALS['profile_response'] = $response;
            check($event->$provider($token)['code'] === 0, 'Malformed provider profile was accepted');
        }
        $GLOBALS['profile_response'] = $base;
        foreach ([null, [], ['access_token'=>[]], ['access_token'=>'']] as $badToken) {
            check($event->$provider($badToken)['code'] === 0, 'Malformed provider token was accepted');
        }
        $GLOBALS['profile_throw'] = true;
        $result = $event->$provider($token);
        check($result['code'] === 0 && !str_contains($result['msg'], 'private'), 'Upstream failure was not contained/redacted');
        $GLOBALS['profile_throw'] = false;
    }
    $sdk = new login\sdk\WeixinSDK(['access_token'=>'fixture']);
    try { $sdk->openid(); throw new LogicException('Missing identity accepted'); }
    catch (think\Exception $expected) { check(true, 'Missing WeChat identity is catchable'); }
    foreach ([new login\sdk\QqSDK(), new login\sdk\WeixinSDK()] as $sdk) {
        try { (new ReflectionMethod($sdk, 'parseToken'))->invoke($sdk, 'private-fixture-token', null); throw new LogicException('Invalid token response accepted'); }
        catch (think\Exception $error) { check(!str_contains($error->getMessage(), 'private-fixture'), 'Token parsing error exposed raw response'); }
    }
    echo "OAuth profiles: {$checks} assertions passed on PHP " . PHP_VERSION . "\n";
}
