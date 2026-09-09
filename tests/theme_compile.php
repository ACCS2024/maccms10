<?php
// Parse templates with the repository's real Think template/taglib implementation,
// then lint the generated PHP. This does not execute queries or connect to a database.
require dirname(__DIR__) . '/vendor/autoload.php';
$root = dirname(__DIR__) . '/template/m1938pc3_v2/html9/';
$config = require dirname(__DIR__) . '/config/view.php';
$config['view_path'] = $root;
$config['cache_path'] = sys_get_temp_dir() . '/maccms-theme-v2-compile/';
$config['tpl_cache'] = false;
@mkdir($config['cache_path'], 0755, true);
$pages = ['index/index', 'vod/index', 'vod/type', 'vod/show', 'vod/search', 'vod/detail', 'vod/play', 'art/index', 'art/type', 'art/show', 'art/search', 'art/detail'];
foreach ($pages as $page) {
    $template = new \think\Template($config);
    $content = file_get_contents($root . $page . '.html');
    $template->parse($content);
    $file = $config['cache_path'] . str_replace('/', '-', $page) . '.php';
    file_put_contents($file, $content);
    exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file) . ' 2>&1', $output, $status);
    if ($status !== 0) { fwrite(STDERR, $page . ': ' . implode("\n", $output) . "\n"); exit(1); }
    echo 'PASS ' . $page . "\n";
    $output = [];
}
