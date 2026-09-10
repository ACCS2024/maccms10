<?php
/** Bulk forms reject incomplete batches before writes and return their result. */
require __DIR__ . '/fixtures/security_audit_runtime_stubs.php';
require dirname(__DIR__) . '/application/admin/controller/Link.php';
require dirname(__DIR__) . '/application/admin/controller/Type.php';
$link = (new ReflectionClass(app\admin\controller\Link::class))->newInstanceWithoutConstructor();
$type = (new ReflectionClass(app\admin\controller\Type::class))->newInstanceWithoutConstructor();
foreach ([$link, $type] as $controller) {
    foreach ([[], ['ids' => []], ['ids' => '1'], ['ids' => [[1]]], ['ids' => [1]]] as $input) {
        $GLOBALS['runtime_saves'] = [];
        think\facade\Request::$input = $input;
        check($controller->batch()['ok'] === false, 'Invalid bulk form accepted');
        check($GLOBALS['runtime_saves'] === [], 'Invalid bulk form performed a partial write');
    }
}
$validLink = ['ids' => [1, 2], 'link_name' => ['one', 'two'], 'link_sort' => [0, 1],
    'link_url' => ['https://example.com/one', 'https://example.com/two'], 'link_type' => [0, 0], 'link_logo' => ['', '']];
$GLOBALS['runtime_saves'] = [];
think\facade\Request::$input = $validLink;
check($link->batch()['ok'] === true && count($GLOBALS['runtime_saves']['link']) === 2, 'Valid link batch did not return success');
$GLOBALS['runtime_saves'] = [];
unset($validLink['link_logo'][1]);
think\facade\Request::$input = $validLink;
check($link->batch()['ok'] === false && $GLOBALS['runtime_saves'] === [], 'Invalid second link was validated after writing the first');
$GLOBALS['runtime_saves'] = [];
think\facade\Request::$input = ['ids' => [1, 2], 'link_name' => 'AB', 'link_sort' => '01',
    'link_url' => 'XY', 'link_type' => '00', 'link_logo' => 'ZZ'];
check($link->batch()['ok'] === false && $GLOBALS['runtime_saves'] === [], 'Scalar field containers were interpreted as character arrays');
$validType = ['ids' => [1, 2]];
foreach ([1, 2] as $id) {
    foreach (['type_name', 'type_sort', 'type_en', 'type_tpl', 'type_tpl_list', 'type_tpl_detail'] as $field) {
        $validType[$field . '_' . $id] = $field === 'type_name' ? 'type ' . $id : '';
    }
}
$GLOBALS['runtime_saves'] = [];
think\facade\Request::$input = $validType;
check($type->batch()['ok'] === true && count($GLOBALS['runtime_saves']['type']) === 2, 'Valid type batch did not return success');
$GLOBALS['runtime_saves'] = [];
unset($validType['type_tpl_2']);
think\facade\Request::$input = $validType;
check($type->batch()['ok'] === false && $GLOBALS['runtime_saves'] === [], 'Invalid second type was validated after writing the first');
$GLOBALS['runtime_cache']['type'] = [1 => ['type_mid' => 1, 'type_pid' => 0, 'type_extend' => []]];
think\facade\Request::$input = ['id' => 1];
$result = $type->extend();
check($result['ok'] === true && $result['data'] === [], 'Root type without extensions raised a diagnostic');
foreach ([[], ['id' => [1]], ['id' => 99]] as $input) {
    think\facade\Request::$input = $input;
    check($type->extend()['ok'] === false, 'Malformed or unknown extension lookup accepted');
}
echo 'Bulk form regressions: ' . $checks . " assertions passed\n";
