<?php
/**
 * 由当前 application/extra/maccms.php 生成一份【中性】样板
 * application/data/config/maccms.example.php。
 *
 * 为什么需要它:application/extra/maccms.php 是每站独有的运行时配置(站名/域名/
 * 主题/图床/各类密钥),却曾被 track 进仓库,里面存的是冒烟机的值 ——
 * 乐播新机部署后主题变成 vozy、site_url 指着 216.180.225.139、图床指向
 * img.test.com,全站图片 404。现在该文件已 .gitignore,仓库里只保留这份样板。
 *
 * 用法:php deploy/make-extra-config-example.php [源文件]
 */

$src = $argv[1] ?? (__DIR__ . '/../application/extra/maccms.php');
$dst = __DIR__ . '/../application/data/config/maccms.example.php';

if (!is_file($src)) { fwrite(STDERR, "FATAL: source not found: $src\n"); exit(1); }
$cfg = include $src;
if (!is_array($cfg)) { fwrite(STDERR, "FATAL: source did not return an array\n"); exit(1); }

/** 站点身份 / 基础设施 / 密钥 —— 一律清成中性值,绝不带任何一个站的真实取值 */
$neutral = [
    'site' => [
        'site_name'        => 'MacCMS',
        'site_url'         => '',
        'site_wapurl'      => '',
        'site_keywords'    => '',
        'site_description' => '',
        'site_icp'         => '',
        'site_email'       => '',
        'site_qq'          => '',
        'site_tel'         => '',
        'site_wx'          => '',
        // 主题:default/html 是随包发行、一定存在的那套,任何新站都能先跑起来
        'template_dir'     => 'default',
        'html_dir'         => 'html',
        'mob_template_dir' => 'default',
        'mob_html_dir'     => 'html',
    ],
    'upload' => [
        // 图床必须由各站自己填。留空 + mode=local 时 maccms 走本地 /upload,
        // 不会像 http://img.test.com/ 那样把所有相对封面指到一个不存在的域名。
        'mode'              => 'local',
        'remoteurl'         => '',
        'watermark_content' => '',
    ],
    'meilisearch' => [
        'api_key'   => '',
        // 留空即由 MeilisearchService::defaultIndexUid() 按库名派生本站唯一索引名。
        // 千万不要写 maccms_contents —— 那是全局共享名,多站共用一台 Meili 会互相
        // 覆盖文档,而且本机通常没有该索引,会让 Meili 永远 404、全站静默回落 MySQL。
        'index_uid' => '',
    ],
    'api' => [
        'vod' => ['imgurl' => '', 'auth' => ''],
        'art' => ['imgurl' => '', 'auth' => ''],
    ],
];

$apply = function (array $cfg, array $patch) use (&$apply) {
    foreach ($patch as $k => $v) {
        if (is_array($v) && isset($cfg[$k]) && is_array($cfg[$k])) {
            $cfg[$k] = $apply($cfg[$k], $v);
        } elseif (array_key_exists($k, $cfg) || !is_array($v)) {
            $cfg[$k] = $v;
        }
    }
    return $cfg;
};
$cfg = $apply($cfg, $neutral);

/** 兜底:任何看起来像密钥/口令的键一律清空,防止将来新增字段又把密钥带进仓库 */
$scrub = function (&$arr) use (&$scrub) {
    foreach ($arr as $k => &$v) {
        if (is_array($v)) { $scrub($v); continue; }
        if (!is_string($v) || $v === '') { continue; }
        if (preg_match('/(pass|pwd|secret|token|api_key|apikey|access_key|appkey|app_secret|master_key)/i', (string)$k)) {
            $v = '';
        }
    }
};
$scrub($cfg);

$header = <<<'PHP'
<?php
// ─────────────────────────────────────────────────────────────────────────────
// application/extra/maccms.php 的【中性样板】。
//
// 真正生效的是 application/extra/maccms.php —— 那是每站独有的运行时配置
// (站名/域名/主题/图床/各类密钥),已 .gitignore,不入库。
//
// config/maccms.php 会在真实文件缺失时自动播种:
//     runtime 影子备份  →  本样板
// 所以全新克隆/误删也能起得来,再进安装或后台把各站真实值填上。
//
// 本文件由 deploy/make-extra-config-example.php 生成,请勿手工塞入任何站点真实值。
// ─────────────────────────────────────────────────────────────────────────────

return
PHP;

@mkdir(dirname($dst), 0755, true);
file_put_contents($dst, $header . " " . var_export($cfg, true) . ";\n");

// 自检:样板本身必须是合法 PHP 且不含任何一个站的域名/密钥残留
$out = [];
exec('php -l ' . escapeshellarg($dst) . ' 2>&1', $out, $rc);
if ($rc !== 0) { fwrite(STDERR, "FATAL: generated file has syntax errors\n" . implode("\n", $out) . "\n"); exit(1); }

$body = file_get_contents($dst);
$leaks = [];
foreach (['216.180.225.139', 'img.test.com', 'lbpictupian', 'lebozy', 'maccms_contents', 'test.cn', 'icp123'] as $needle) {
    if (stripos($body, $needle) !== false) { $leaks[] = $needle; }
}
if ($leaks) { fwrite(STDERR, "FATAL: sample still leaks: " . implode(', ', $leaks) . "\n"); exit(1); }

echo "written: $dst (" . strlen($body) . " bytes)\n";
echo "syntax OK, no site-specific leftovers\n";
