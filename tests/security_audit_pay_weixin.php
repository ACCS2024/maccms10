<?php
/** WeChat V2 notification contract: https://pay.wechatpay.cn/doc/v2/merchant/4011937152 */
require __DIR__ . '/fixtures/security_audit_pay_stubs.php';
require dirname(__DIR__) . '/application/common/extend/pay/Weixin.php';
$base = ['appid' => 'fixture-app', 'mch_id' => 'fixture-merchant', 'out_trade_no' => 'fixture-order',
    'transaction_id' => 'fixture-trade', 'return_code' => 'SUCCESS', 'result_code' => 'SUCCESS',
    'total_fee' => '1000', 'fee_type' => 'CNY', 'nonce_str' => 'fixture-nonce', 'coupon_count' => '0', 'attach' => ''];
$valid = pay_sign('weixin', $base);
$success = '<xml><return_code><![CDATA[SUCCESS]]></return_code><return_msg><![CDATA[OK]]></return_msg></xml>';
check(pay_capture('weixin', $valid) === $success, 'Valid signed payment was not acknowledged');
check($GLOBALS['pay_calls'] === [['fixture-order', 'weixin', '10.00']], 'Fen was not converted exactly to yuan');
pay_failures('weixin', $valid, $success);
foreach (['sign', 'total_fee', 'out_trade_no', 'transaction_id', 'appid', 'mch_id', 'result_code'] as $missing) {
    $payload = $base;
    unset($payload[$missing]);
    $payload = pay_sign('weixin', $payload);
    if ($missing === 'sign') { unset($payload['sign']); }
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('weixin', $payload) !== $success && $GLOBALS['pay_calls'] === [], 'Incomplete notification reached order processing');
}
foreach (['', '0', '-1', '1.01', '1e3', '1000oops', '99999999999999999999999'] as $amount) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('weixin', pay_sign('weixin', array_replace($base, ['total_fee' => $amount]))) !== $success
        && $GLOBALS['pay_calls'] === [], 'Invalid fen amount reached order processing');
}
foreach (['appid' => 'other-app', 'mch_id' => 'other-merchant', 'fee_type' => 'USD',
    'result_code' => 'FAIL', 'return_code' => 'FAIL', 'sign_type' => 'unsupported'] as $field => $value) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('weixin', pay_sign('weixin', array_replace($base, [$field => $value]))) !== $success
        && $GLOBALS['pay_calls'] === [], 'Wrong merchant, currency or payment status reached order processing');
}
$payload = $valid;
$payload['sign'] = str_repeat('0', 32);
$GLOBALS['pay_calls'] = [];
check(pay_capture('weixin', $payload) !== $success && $GLOBALS['pay_calls'] === [], 'Invalid signature was accepted');
foreach (['', '<xml>', '<!DOCTYPE xml [<!ENTITY x SYSTEM "file:///fixture">]><xml>&x;</xml>',
    '<xml><total_fee><nested>1000</nested></total_fee></xml>', str_repeat('x', 1048577)] as $xml) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('weixin', [], $xml) !== $success && $GLOBALS['pay_calls'] === [], 'Invalid XML reached order processing');
}
$GLOBALS['pay_result'] = ['code' => 1];
check(pay_capture('weixin', pay_sign('weixin', array_replace($base, ['sign_type' => 'HMAC-SHA256']))) === $success, 'Documented HMAC-SHA256 notification was rejected');
$GLOBALS['pay_config']['weixin']['appkey'] = '';
$GLOBALS['pay_calls'] = [];
check(pay_capture('weixin', pay_sign('weixin', $base)) !== $success && $GLOBALS['pay_calls'] === [], 'Empty configured key accepted a forged notification');
echo 'Weixin notification regressions: ' . $checks . " assertions passed\n";
