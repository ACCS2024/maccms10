<?php
/** Epay V1 notification contract: https://pay.xr876.cn/doc/v1_legacy_api.html */
require __DIR__ . '/fixtures/security_audit_pay_stubs.php';
require dirname(__DIR__) . '/application/common/extend/pay/Epay.php';
$base = ['pid' => 'fixture-app', 'out_trade_no' => 'fixture-order', 'trade_no' => 'fixture-trade',
    'money' => '10.00', 'trade_status' => 'TRADE_SUCCESS', 'sign_type' => 'MD5'];
$valid = pay_sign('epay', $base);
check(pay_capture('epay', $valid) === 'success', 'Valid notification failed');
check($GLOBALS['pay_calls'] === [['fixture-order', 'epay', '10.00']], 'Amount was not passed to the order');
pay_failures('epay', $valid, 'success');
foreach (['sign', 'money', 'out_trade_no', 'trade_no', 'pid', 'trade_status'] as $missing) {
    $payload = $base;
    unset($payload[$missing]);
    $payload = pay_sign('epay', $payload);
    if ($missing === 'sign') { unset($payload['sign']); }
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('epay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Incomplete signed notification reached the order');
}
foreach (['', '0', '-1', '1e1', '10.001', 'NaN'] as $amount) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('epay', pay_sign('epay', array_replace($base, ['money' => $amount]))) === 'fail'
        && $GLOBALS['pay_calls'] === [], 'Invalid amount reached the order');
}
foreach (['trade_status' => 'WAIT_BUYER_PAY', 'pid' => 'other-merchant', 'sign_type' => 'RSA2'] as $field => $value) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('epay', pay_sign('epay', array_replace($base, [$field => $value]))) === 'fail'
        && $GLOBALS['pay_calls'] === [], 'Wrong state, merchant or algorithm reached the order');
}
$payload = $valid;
$payload['sign'] = ['not-a-signature'];
$GLOBALS['pay_calls'] = [];
check(pay_capture('epay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Nested signature caused unsafe coercion');
$_SERVER['REQUEST_METHOD'] = 'GET';
$_COOKIE = $_REQUEST = ['money' => '1.00', 'sign' => 'cookie-signature'];
check(pay_capture('epay', $valid) === 'success', 'GET notification was contaminated by cookie parameters');
$_GET = [];
$GLOBALS['pay_calls'] = [];
check(pay_capture('epay') === 'fail' && $GLOBALS['pay_calls'] === [], 'Cookie-only notification was accepted');
$GLOBALS['pay_config']['epay']['appkey'] = '';
check(pay_capture('epay', pay_sign('epay', $base)) === 'fail', 'Empty configured key accepted a forged signature');
echo 'Epay notification regressions: ' . $checks . " assertions passed\n";
