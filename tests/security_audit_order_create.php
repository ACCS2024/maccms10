<?php
/** Real persisted orders: both recharge entry points and fixed-point member plans. */
require __DIR__ . '/fixtures/security_audit_order_create.php';
use think\facade\Db;
function mac_extends_list($kind) { return ['ext_list'=>[]]; }

// Input guards must also protect databases configured to truncate overflowing values.
if ($mysql) { Db::execute("SET SESSION sql_mode=''"); }

function createRecharge(string $entry, $price, array $extra = [], string $method = 'POST'): array {
    $action = $entry === 'api' ? 'create' : 'buy';
    $request = creationRequest(['price'=>$price] + $extra, $action, $entry === 'api' ? '/api.php' : '/index.php', $method);
    return $entry === 'api' ? creationController(\app\api\controller\Order::class)->create($request)
        : creationController(\app\index\controller\User::class)->buy();
}
foreach (['api', 'index'] as $entry) {
    foreach ([['0.29', '100', 29], ['2.30','100',230], ['1.25','2.4',3], ['167772.15','100',16777215],
        ['9999999999.99','0.00000001',99]] as [$price,$scale,$points]) {
        creationSeed(['scale'=>$scale,'min'=>'0']);
        $result = createRecharge($entry, $price, ['user_id'=>2,'order_points'=>99999999,'order_status'=>1]);
        check($result['code'] === 1, 'Valid recharge quote failed at the ' . $entry . ' controller');
        $row = Db::name('Order')->order('order_id')->find();
        check((int)$row['order_points'] === $points && (int)$row['user_id'] === 1 && (int)$row['order_status'] === 0,
            'Stored recharge quantity/owner/status came from floats or client overrides');
        check(\app\common\util\OrderAmount::minorUnits($row['order_price']) === \app\common\util\OrderAmount::minorUnits($price)
            && Db::name('Order')->count() === 1 && memberRow()['user_points'] === 100 && Db::name('Plog')->count() === 0,
            'Order creation changed money precision or credited points before payment');
    }
    foreach ([null, '', 0, -1, '1.001', '1e2', '10000000000', ['1'], true, INF, NAN, 0.29000000000000004] as $price) {
        creationSeed();
        check(createRecharge($entry, $price)['code'] !== 1 && Db::name('Order')->count() === 0,
            'Malformed ' . $entry . ' recharge created an order');
    }
    foreach ([null, '', 0, -1, '1e2', [], true, '10000000000', '0.000000001'] as $scale) {
        creationSeed(['scale'=>$scale,'min'=>'0']);
        check(createRecharge($entry, '10.00')['code'] !== 1 && Db::name('Order')->count() === 0,
            'Invalid server multiplier produced an order at ' . $entry);
    }
    foreach ([['0.01','1'], ['167772.16','100'], ['9999999999.99','9999999999.99999999']] as [$price,$scale]) {
        creationSeed(['scale'=>$scale,'min'=>'0']);
        check(createRecharge($entry, $price)['code'] !== 1 && Db::name('Order')->count() === 0,
            'Zero or overflowing points reached the database at ' . $entry);
    }
    creationSeed(['scale'=>'100','min'=>'0.30']);
    check(createRecharge($entry, '0.29')['code'] === 1002 && Db::name('Order')->count() === 0,
        'Minimum recharge comparison accepted one cent too little');
    check(createRecharge($entry, '0.30')['code'] === 1, 'Exact minimum recharge was rejected');
    creationSeed(['scale'=>'100','min'=>'not-a-price']);
    check(createRecharge($entry, '10.00')['code'] !== 1 && Db::name('Order')->count() === 0, 'Malformed server minimum silently disabled the check');
}
creationSeed();
check(createRecharge('api', '10', [], 'GET')['code'] !== 1 && Db::name('Order')->count() === 0, 'GET created a recharge order');
$GLOBALS['creation_logged_in'] = false;
check(createRecharge('api', '10')['code'] === 1401 && Db::name('Order')->count() === 0, 'Recharge creation bypassed authentication');

$member = creationController(\app\api\controller\User::class);
foreach ([[1,'3','0.33'], [1,'8','0.13'], [20,'3','6.67'], [1,'0.1','10.00'], [16777215,'1','16777215.00']] as [$points,$scale,$price]) {
    creationSeed(['scale'=>$scale,'min'=>'0']);
    $GLOBALS['member_groups'][3]['group_points_day'] = $points;
    $result = $member->upgrade_order_create(creationRequest(['group_id'=>3,'long'=>'day','price'=>'0.01',
        'order_points'=>1,'upgrade_points'=>1,'user_id'=>2], 'upgrade_order_create'));
    check($result['code'] === 1 && $result['data']['order_price'] === $price && $result['data']['order_points'] === $points,
        'Member order quote changed its configured snapshot or accepted client pricing');
    $row = Db::name('Order')->order('order_id')->find();
    $remarks = json_decode($row['order_remarks'], true);
    check((int)$row['order_points'] === $points && $remarks['upgrade_points'] === $points && $remarks['biz'] === 'member_upgrade'
        && (int)$row['user_id'] === 1, 'Member order remarks and credited points did not use the same server snapshot');
}
foreach ([[0,'100'], [1,'201'], [100,'0.00000001'], [16777216,'100'], ['1.5','100'], [20,'0'], [20,null], [20,'1e2'],
    [20,'0.000000001'], [20,[]]] as [$points,$scale]) {
    creationSeed(['scale'=>$scale,'min'=>'0']);
    $GLOBALS['member_groups'][3]['group_points_day'] = $points;
    check($member->upgrade_order_create(creationRequest(['group_id'=>3,'long'=>'day'], 'upgrade_order_create'))['code'] !== 1
        && Db::name('Order')->count() === 0, 'Invalid/unpayable member plan created an order');
}
foreach ([['group_id'=>[3],'long'=>'day'], ['group_id'=>3,'long'=>[]], ['group_id'=>'3x','long'=>'day'], ['group_id'=>3,'long'=>' day ']] as $parameters) {
    creationSeed();
    check($member->upgrade_order_create(creationRequest($parameters, 'upgrade_order_create'))['code'] !== 1
        && Db::name('Order')->count() === 0, 'Malformed member plan selector was coerced into a payable order');
}
creationSeed(['scale'=>'2.4','min'=>'0.29']);
$display = $member->ajax_upgrade_data(creationRequest([], 'ajax_upgrade_data', '/api.php', 'GET'));
check($display['code'] === 1 && $display['data']['groups'][0]['price_day'] === 8.33,
    'Displayed member price truncated a fractional exchange rate');
$GLOBALS['member_groups'][3]['group_points_day'] = 0;
$display = $member->ajax_upgrade_data(creationRequest([], 'ajax_upgrade_data', '/api.php', 'GET'));
check($display['data']['groups'][0]['price_day'] === 0.0, 'Explicit free membership display was disabled');
$payment = creationController(\app\api\controller\Payment::class);
$configuration = $payment->get_config(creationRequest([], 'get_config', '/api.php', 'GET'));
check($configuration['code'] === 1 && $configuration['info']['scale'] === '2.4' && $configuration['info']['min'] === '0.29',
    'Payment configuration returned a truncated multiplier or minimum');
creationSeed(['scale'=>'201','min'=>'0']);
$GLOBALS['member_groups'][3]['group_points_day'] = 1;
$display = $member->ajax_upgrade_data(creationRequest([], 'ajax_upgrade_data', '/api.php', 'GET'));
check($display['data']['groups'][0]['price_day'] === null, 'An unpayable cash plan was advertised as free');
creationSeed(['scale'=>'invalid','min'=>'0']);
$display = $member->ajax_upgrade_data(creationRequest([], 'ajax_upgrade_data', '/api.php', 'GET'));
check($display['code'] === 1 && $display['data']['groups'][0]['price_day'] === null
    && $payment->get_config(creationRequest([], 'get_config', '/api.php', 'GET'))['code'] !== 1,
    'Invalid server multiplier disabled point-balance plans or advertised a fabricated cash quote');
$GLOBALS['member_groups'][3]['group_points_day'] = 0;
$display = $member->ajax_upgrade_data(creationRequest([], 'ajax_upgrade_data', '/api.php', 'GET'));
check($display['data']['groups'][0]['price_day'] === 0.0, 'A free balance plan was coupled to cash payment configuration');
echo "order creation audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL installation schema' : ' / SQLite') . "\n";
