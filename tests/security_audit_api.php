<?php
/** API authorization helper, category restriction and year filter regressions. */
require __DIR__ . "/fixtures/security_audit_controller_stubs.php";
require dirname(__DIR__) . '/application/api/controller/Base.php';
require dirname(__DIR__) . '/application/api/controller/PublicApi.php';
require dirname(__DIR__) . '/application/api/controller/Seacms.php';
require dirname(__DIR__) . '/application/api/controller/Provide.php';
function mac_get_client_ip() { return '127.0.0.1'; }
function mac_string_is_ip($value) { return filter_var($value, FILTER_VALIDATE_IP) !== false; }
$seacms = (new \ReflectionClass(\app\api\controller\Seacms::class))->newInstanceWithoutConstructor();
$authorize = new \ReflectionMethod($seacms, 'checkDomainAuth');
check($authorize->isPrivate(), 'SeaCMS authorization helper became a route');
$authorize->invoke($seacms, '127.0.0.1');
check(true, 'SeaCMS authorized client completed without missing method');
$category = new \ReflectionMethod(\app\api\controller\Base::class, 'categoryIsAllowed');
foreach ([['2', '12,13'], [['12'], '12'], ['12,13', '12'], ['0', '']] as [$requested, $allowed]) {
    check(!$category->invoke(null, $requested, $allowed), 'Category allowlist accepted a substring or malformed ID');
}
foreach ([['12', '12,13'], [13, '12, 13'], ['12', '']] as [$requested, $allowed]) {
    check($category->invoke(null, $requested, $allowed), 'Complete allowed category ID rejected');
}
$years = new \ReflectionMethod(\app\api\controller\Provide::class, 'yearFilter');
check($years->invoke(null, '2020') === [2020], 'Single year filter failed');
check($years->invoke(null, '2022-2020') === [2020, 2021, 2022], 'Reversed year range failed');
foreach (['20', '2020x2022', '0000', '9999', ['2020']] as $bad) {
    check($years->invoke(null, $bad) === null, 'Malformed year accepted');
}
echo 'API compatibility regressions: ' . $checks . " assertions passed\n";
