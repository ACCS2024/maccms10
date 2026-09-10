<?php
/** Paid membership must link to the frontend entry, using real order persistence and TP8 URL building. */
require __DIR__ . '/fixtures/security_audit_order_create.php';
$controller = creationController(\app\api\controller\User::class);
foreach (['/api.php', '/subsite/api.php'] as $script) {
    creationSeed();
    $request = creationRequest(['group_id'=>3, 'long'=>'day'], 'upgrade_order_create', $script);
    $response = $controller->upgrade_order_create($request);
    check($response['code'] === 1, 'Paid membership order creation failed before generating its URL');
    $stored = \think\facade\Db::name('Order')->where('order_code', $response['data']['order_code'])->find();
    check($stored && (int)$stored['order_id'] === $response['data']['order_id'], 'Payment URL did not refer to the persisted order');
    $parts = parse_url($response['data']['pay_url']);
    parse_str($parts['query'] ?? '', $query);
    $base = rtrim(str_replace('\\', '/', dirname($script)), '/');
    check(($parts['path'] ?? '') === $base . '/index.php/user/pay', 'Membership link targets the API entry instead of frontend checkout');
    check(($query['order_code'] ?? '') === $stored['order_code'], 'Checkout link lost the exact order code');
}
echo "member order URL audit: $checks checks passed on PHP " . PHP_VERSION . "\n";
