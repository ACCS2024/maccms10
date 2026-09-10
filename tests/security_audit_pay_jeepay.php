<?php
/** Jeepay payment notification contract: https://docs.jeequan.com/docs/jeepay/payment_api */
require __DIR__ . '/fixtures/security_audit_pay_stubs.php';
require dirname(__DIR__) . '/application/common/extend/pay/Jeepay.php';
$base = ['appId' => 'fixture-app', 'mchNo' => 'fixture-merchant', 'mchOrderNo' => 'fixture-order',
    'payOrderId' => 'fixture-trade', 'amount' => '1000', 'currency' => 'cny', 'state' => '2'];
$valid = pay_sign('jeepay', $base);
check(pay_capture('jeepay', $valid) === 'SUCCESS', 'Valid Jeepay notification failed');
check($GLOBALS['pay_calls'] === [['fixture-order', 'jeepay', '10.00']], 'Verified fen amount was not passed to the order');
pay_failures('jeepay', $valid, 'SUCCESS');
foreach (['sign', 'amount', 'currency', 'state', 'mchOrderNo', 'appId', 'mchNo'] as $missing) {
    $payload = $base;
    unset($payload[$missing]);
    $payload = pay_sign('jeepay', $payload);
    if ($missing === 'sign') { unset($payload['sign']); }
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('jeepay', $payload) !== 'SUCCESS' && $GLOBALS['pay_calls'] === [], 'Incomplete notification reached the order');
}
foreach (['', '0', '-1', '1000.01', '1000suffix', '1e3', '99999999999999999999999', '999', '1001'] as $amount) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('jeepay', pay_sign('jeepay', array_replace($base, ['amount' => $amount]))) !== 'SUCCESS'
        && $GLOBALS['pay_calls'] === [], 'Invalid or mismatched amount reached the order');
}
foreach (['state' => '2suffix', 'appId' => 'other-app', 'mchNo' => 'other-merchant', 'currency' => 'USD'] as $field => $value) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('jeepay', pay_sign('jeepay', array_replace($base, [$field => $value]))) !== 'SUCCESS'
        && $GLOBALS['pay_calls'] === [], 'Wrong state, merchant or currency reached the order');
}
$payload = $valid;
$payload['state'] = ['2'];
$GLOBALS['pay_calls'] = [];
check(pay_capture('jeepay', $payload) !== 'SUCCESS' && $GLOBALS['pay_calls'] === [], 'Nested state caused unsafe coercion');
foreach ([null, new RuntimeException('fixture query failure')] as $order) {
    $GLOBALS['pay_order'] = $order;
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('jeepay', $valid) !== 'SUCCESS' && $GLOBALS['pay_calls'] === [], 'Missing or unavailable order was acknowledged');
}
$GLOBALS['pay_order'] = ['order_price' => '10.00'];
check(pay_capture('jeepay', pay_sign('jeepay', $base + ['ZfutureField' => 'fixture', 'afutureField' => 'fixture'])) === 'SUCCESS', 'Future signed fields did not use documented ASCII ordering');
$GLOBALS['pay_config']['jeepay']['appkey'] = '';
check(pay_capture('jeepay', pay_sign('jeepay', $base)) !== 'SUCCESS', 'Empty key accepted a forged notification');
echo 'Jeepay notification regressions: ' . $checks . " assertions passed\n";
