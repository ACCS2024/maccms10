<?php
/** WeChat callback signature, XML and unsupported message regressions. */
require __DIR__ . "/fixtures/security_audit_test_helpers.php";
require dirname(__DIR__) . '/application/common/util/WechatPublic.php';
$wechat = new \app\common\util\WechatPublic(['token' => '3', 'guanzhu' => 'welcome']);
$signature = new \ReflectionMethod($wechat, 'checkSignature');
$_GET = [];
check(!$signature->invoke($wechat), 'Missing callback signature accepted');
ob_start(); $wechat->responseMsg(); $denied = ob_get_clean();
check(http_response_code() === 403 && $denied === 'forbidden', 'Unsigned POST reached XML handler');
$_GET = ['timestamp' => '10', 'nonce' => '2', 'signature' => sha1('10' . '2' . '3')];
check($signature->invoke($wechat), 'Valid lexical signature rejected');
$_GET['nonce'] = [];
check(!$signature->invoke($wechat), 'Array callback parameter accepted');
$reply = new \ReflectionMethod($wechat, 'replyToMessage');
foreach (['image', 'voice', 'video', 'location', 'unknown'] as $type) {
    $xml = '<xml><FromUserName>visitor</FromUserName><ToUserName>site</ToUserName><MsgType>' . $type . '</MsgType></xml>';
    check($reply->invoke($wechat, $xml) === 'success', 'Unsupported message caused a missing-method error');
}
foreach (['', '<xml>', '<xml></xml>', '<!DOCTYPE xml [<!ENTITY e SYSTEM "file:///nonexistent">]><xml>&e;</xml>', str_repeat('x', 1048577)] as $invalid) {
    check($reply->invoke($wechat, $invalid) === 'invalid request', 'Malformed or oversized XML accepted');
}
$payload = 'button]]><script>example</script>';
$xml = '<xml><FromUserName>visitor</FromUserName><ToUserName>site</ToUserName><MsgType>event</MsgType><Event>CLICK</Event><EventKey>'
    . htmlspecialchars($payload, ENT_XML1 | ENT_QUOTES, 'UTF-8') . '</EventKey></xml>';
$parsed = simplexml_load_string($reply->invoke($wechat, $xml), 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
check($parsed !== false && str_contains((string)$parsed->Content, $payload), 'Reply CDATA broke XML or lost click text');
echo 'WeChat regressions: ' . $checks . " assertions passed\n";
