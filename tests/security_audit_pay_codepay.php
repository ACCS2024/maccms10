<?php
/** Preserve the legacy Codepay protocol while refusing missing amounts and false acknowledgements. */
require __DIR__ . '/fixtures/security_audit_pay_stubs.php';
require dirname(__DIR__) . '/application/common/extend/pay/Codepay.php';
$base = ['pay_id' => 'fixture-order', 'pay_no' => 'fixture-trade', 'money' => '10.00'];
$valid = pay_sign('codepay', $base);
check(pay_capture('codepay', $valid) === 'success', 'Valid legacy Codepay notification failed');
check($GLOBALS['pay_calls'] === [['fixture-order', 'codepay', '10.00']], 'Signed money was not passed to the order');
pay_failures('codepay', $valid, 'success');
foreach (['pay_id', 'pay_no', 'money', 'sign'] as $missing) {
    $payload = $base;
    unset($payload[$missing]);
    $payload = pay_sign('codepay', $payload);
    if ($missing === 'sign') { unset($payload['sign']); }
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('codepay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Incomplete notification reached the order');
}
foreach (['', '0', '-1', '1e1', '10.001', 'NaN'] as $amount) {
    $GLOBALS['pay_calls'] = [];
    check(pay_capture('codepay', pay_sign('codepay', array_replace($base, ['money' => $amount]))) === 'fail'
        && $GLOBALS['pay_calls'] === [], 'Invalid amount reached the order');
}
$payload = $valid;
$payload['pay_id'] = ['fixture-order'];
$GLOBALS['pay_calls'] = [];
check(pay_capture('codepay', $payload) === 'fail' && $GLOBALS['pay_calls'] === [], 'Nested order identifier was accepted');
$payload = $valid;
$payload['money'] = '100.00';
check(pay_capture('codepay', $payload) === 'fail', 'Tampered signed amount was accepted');
$GLOBALS['pay_config']['codepay']['appkey'] = '';
check(pay_capture('codepay', pay_sign('codepay', $base)) === 'fail', 'Empty key accepted a forged notification');
echo 'Codepay notification regressions: ' . $checks . " assertions passed\n";
