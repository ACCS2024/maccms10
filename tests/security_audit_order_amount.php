<?php
/** Exact arithmetic regressions, independent of database/app initialization. */
require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
use app\common\util\OrderAmount;
foreach ([['0001.01000000','1.01'],['0.00000001','0.00000001'],['9999999999.99999999','9999999999.99999999'],[0.5,'0.5'],[100,'100']] as [$input,$expected]) {
    check(OrderAmount::rateDecimal($input)===$expected,'Exchange rate text must retain all exact configured digits');
}
foreach ([['0.29','100','0.29',29], ['2.3','100','2.30',230], ['1.25','2.4','1.25',3],
    ['167772.15','100','167772.15',16777215], ['16777215.99','1','16777215.99',16777215],
    ['9999999999.99','0.00000001','9999999999.99',99], ['0002.30','000100.00','2.30',230]] as [$price,$scale,$decimal,$points]) {
    check(OrderAmount::recharge($price, $scale) === ['order_price'=>$decimal, 'order_points'=>$points],
        'Recharge lost a point to floating point or changed its floor rule');
}
foreach ([['1','3','0.33'], ['1','6','0.17'], ['1','8','0.13'], ['1','200','0.01'], ['1','199.99999999','0.01'],
    ['1','0.1','10.00'], ['1','0.00000001','100000000.00'], ['20','3','6.67'], [16777215,'1','16777215.00']] as [$points,$scale,$decimal]) {
    check(OrderAmount::membership($points, $scale) === ['order_price'=>$decimal, 'order_points'=>(int)$points],
        'Membership price must round half up while retaining its point snapshot');
}
check(OrderAmount::membership(0, '100', true) === ['order_price'=>'0.00', 'order_points'=>0]
    && OrderAmount::membership(0, null, true) === ['order_price'=>'0.00', 'order_points'=>0]
    && OrderAmount::membership(0, '100') === null && OrderAmount::membership(0, null) === null,
    'Free display quotes became payable zero-amount orders or required a cash configuration');
foreach ([['0.01','1'], ['167772.16','100'], ['9999999999.99','9999999999.99999999']] as [$price,$scale]) {
    check(OrderAmount::recharge($price, $scale) === null, 'Zero or overflowing recharge points were accepted');
}
foreach ([[1,'201'], [1,'200.00000001'], [100,'0.00000001'], [16777216,'100'], ['1.5','100']] as [$points,$scale]) {
    check(OrderAmount::membership($points, $scale) === null, 'Unpayable or unrepresentable membership quote was accepted');
}
foreach ([null, '', 0, -1, '0', '-1', '+1', '1e2', ' 100', '100 ', '0x64', [], true, false, INF, -INF, NAN,
    '0.000000001', '10000000000', 1.00000000001] as $scale) {
    check(OrderAmount::recharge('10', $scale) === null && OrderAmount::membership(100, $scale) === null,
        'Malformed exchange rate was truncated, defaulted, or converted to a float');
}
foreach ([null, '', 0, -1, '0', '0.00', '-1', '+1', '1e2', ' 1', '1 ', '1.001', '1.000', '10000000000',
    [], true, false, INF, -INF, NAN, 1.00000000001] as $price) {
    check(OrderAmount::recharge($price, '100') === null, 'Malformed money input was rounded or coerced');
}
check(OrderAmount::recharge(0.29, 100.0) === ['order_price'=>'0.29','order_points'=>29], 'Exact legacy numeric arguments stopped working');
check(OrderAmount::minimum('0.29') === 29 && OrderAmount::minimum(null) === 0 && OrderAmount::minimum('') === 0
    && OrderAmount::minimum('0') === 0 && OrderAmount::minimum('-1') === null, 'Minimum recharge configuration was not interpreted exactly');
echo "order amount audit: $checks checks passed on PHP " . PHP_VERSION . "\n";
