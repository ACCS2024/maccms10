<?php
/** Attachment pagination and accumulated batch insertion regressions. */
require __DIR__ . "/fixtures/security_audit_controller_stubs.php";
require dirname(__DIR__) . '/application/admin/controller/Base.php';
require dirname(__DIR__) . '/application/admin/controller/Annex.php';
$temp = audit_temp_dir('annex');
$originalDirectory = getcwd();
mkdir($temp . '/upload');
try {
$annex = (new \ReflectionClass(\app\admin\controller\Annex::class))->newInstanceWithoutConstructor();
foreach ([[], ['start' => 1, 'page_count' => 2, 'data_count' => 501]] as $input) {
    \think\facade\Request::$input = $input;
    $annex->check();
    check($GLOBALS['audit_limit'] === [500, 500], 'Attachment check lost its page limit');
}
chdir($temp);
foreach ([1, 2] as $id) {
    file_put_contents('upload/image' . $id . '.jpg', 'fixture');
    $GLOBALS['audit_rows'][] = ['vod_id' => $id, 'vod_name' => 'Fixture ' . $id, 'vod_pic' => 'upload/image' . $id . '.jpg',
        'vod_pic_thumb' => '', 'vod_pic_slide' => '', 'vod_content' => ''];
}
\think\facade\Request::$input = ['ck' => 1, 'start' => 1, 'tbi' => 4];
$annex->init();
check($GLOBALS['audit_limit'] === [500, 500], 'Attachment initialization lost its page limit');
check(count($GLOBALS['audit_inserts']) === 1 && count($GLOBALS['audit_inserts'][0]) === 2, 'Attachment initialization duplicated its accumulated batch');
chdir($originalDirectory);

echo 'Attachment batch regressions: ' . $checks . " assertions passed\n";
} finally { chdir($originalDirectory); audit_remove_temp($temp); }
