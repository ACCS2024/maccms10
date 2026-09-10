<?php
/** Preserve Zhapay's existing yuan contract; gateway unit documentation still needs confirmation. */
require __DIR__ . '/fixtures/security_audit_pay_stubs.php';
require dirname(__DIR__) . '/application/common/extend/pay/Zhapay.php';
$base = ['out_trade_no' => 'fixture-order', 'transaction_id' => 'fixture-trade', 'total_fee' => '10.00'];
$valid = pay_sign('zhapay', $base);
check(pay_capture('zhapay', $valid) === 'success', 'Valid legacy Zhapay notification failed');
check($GLOBALS['pay_calls'] === [['fixture-order', 'zhapay', '10.00']], 'Existing yuan amount contract changed');
pay_failures('zhapay', $valid, 'success');
foreach (['out_trade_no', 'transaction_id', 'total_fee', 'sign'] as $missing) {
    $payload = $base;
    unset($payload[$missing]);
    $payload = pay_sign('zhapay', $payload);
    if ($missing === 'sign') { unset($payload['sign']); }
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('zhapay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Incomplete notification reached the order');
}
foreach (['', '0', '-1', '1e1', '10.001', 'NaN'] as $amount) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('zhapay', pay_sign('zhapay', array_replace($base, ['total_fee' => $amount]))) === 'fail'
        && $GLOBALS['pay_calls'] === [], 'Invalid amount reached the order');
}
$payload = $valid;
$payload['total_fee'] = ['10.00'];
$GLOBALS['pay_calls'] = [];
check(pay_capture('zhapay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Nested amount was accepted');
$payload = $valid;
$payload['out_trade_no'] = 'tampered-order';
check(pay_capture('zhapay', $payload) === 'fail', 'Tampered signed order was accepted');
$payload = $base;
unset($payload['total_fee']);
$payload['money'] = '10.00';
check(pay_capture('zhapay', pay_sign('zhapay', $payload)) === 'success', 'Existing money alias was lost');
$GLOBALS['pay_config']['zhapay']['appkey'] = '';
check(pay_capture('zhapay', pay_sign('zhapay', $base)) === 'fail', 'Empty key accepted a forged notification');
echo 'Zhapay notification regressions: ' . $checks . " assertions passed\n";
