<?php
// Render real notice templates with fixture data; no database writes or connection.
require dirname(__DIR__) . '/vendor/autoload.php';
date_default_timezone_set('Asia/Shanghai');
$config = require dirname(__DIR__) . '/config/view.php';
$config['view_path'] = dirname(__DIR__) . '/template/m1938pc3_v2/html9/';
$config['cache_path'] = sys_get_temp_dir() . '/maccms-rep-fixtures/';
$config['tpl_cache'] = false;
$fixtures = [];
foreach (['empty', 'published', 'undated', 'disabled'] as $state) {
    $data = [
        'zy_rep_enabled' => $state !== 'disabled',
        'zy_rep_url' => '/index.php/macrep.html',
        'zy_rep_latest' => $state === 'empty' ? null : [
            'rep_create_time' => $state === 'undated' ? 0 : strtotime('2026-09-09 17:06:00'),
            'rep_type' => '图片域名替换 <测试>',
        ],
    ];
    $template = new \think\Template($config);
    ob_start();
    $template->fetch('public/v2/rep-notice', $data);
    $fixtures[$state] = ob_get_clean();
}
echo json_encode($fixtures, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
