<?php
/** Alipay acknowledgement: https://help.alipay.com/support/help_detail.htm?help_id=491081 */
require __DIR__ . '/fixtures/security_audit_pay_stubs.php';
require dirname(__DIR__) . '/application/common/extend/pay/Alipay.php';
$base = ['out_trade_no' => 'fixture-order', 'trade_no' => 'fixture-trade', 'total_fee' => '10.00',
    'trade_status' => 'TRADE_SUCCESS', 'sign_type' => 'MD5'];
$valid = pay_sign('alipay', $base);
check(pay_capture('alipay', $valid) === 'success', 'Alipay requires the exact success response without a suffix');
check($GLOBALS['pay_calls'] === [['fixture-order', 'alipay', '10.00']], 'Signed payment amount was not passed to the order');
pay_failures('alipay', $valid, 'success');
foreach (['sign', 'total_fee', 'out_trade_no', 'trade_no', 'trade_status'] as $missing) {
    $payload = $base;
    unset($payload[$missing]);
    $payload = pay_sign('alipay', $payload);
    if ($missing === 'sign') { unset($payload['sign']); }
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('alipay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Missing payment fields reached the order');
}
foreach (['', '0', '-1', '1e1', '10.001', 'NaN'] as $amount) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('alipay', pay_sign('alipay', array_replace($base, ['total_fee' => $amount]))) === 'fail'
        && $GLOBALS['pay_calls'] === [], 'Invalid payment amount reached the order');
}
$GLOBALS['pay_calls'] = [];
$payload = $valid;
$payload['total_fee'] = ['10.00'];
check(pay_capture('alipay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Nested notification fields caused unsafe coercion');
foreach (['WAIT_BUYER_PAY', 'TRADE_CLOSED'] as $status) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('alipay', pay_sign('alipay', array_replace($base, ['trade_status' => $status]))) === 'success'
        && $GLOBALS['pay_calls'] === [], 'Known unpaid notifications must be acknowledged without crediting');
}
check(pay_capture('alipay', pay_sign('alipay', array_replace($base, ['trade_status' => 'TRADE_FINISHED']))) === 'success', 'Completed payment notification was lost');
$payload = $base;
unset($payload['total_fee']);
$payload['total_amount'] = '10.00';
check(pay_capture('alipay', pay_sign('alipay', $payload)) === 'success', 'Existing total_amount compatibility was lost');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_COOKIE = $_REQUEST = ['out_trade_no' => 'cookie-order', 'sign' => 'cookie-sign'];
check(pay_capture('alipay', $valid) === 'success', 'Signed browser return was contaminated by cookies');
$alipay = new app\common\extend\pay\Alipay();
check(!$alipay->md5Verify('24061070', '0e830400451993494058024219903391', '8'), 'Numeric-looking MD5 digests compared equal');
$GLOBALS['pay_config']['alipay']['appkey'] = '';
$GLOBALS['pay_calls'] = [];
check(pay_capture('alipay', pay_sign('alipay', $base)) === 'fail' && $GLOBALS['pay_calls'] === [], 'Empty key accepted a forged notification');
echo 'Alipay notification regressions: ' . $checks . " assertions passed\n";
