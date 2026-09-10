<?php
namespace think\facade {
    class View {
        public static function fetch($template, $data = []) { return '[' . $template . ']'; }
    }
}
namespace {
    require __DIR__ . '/fixtures/security_audit_test_helpers.php';
    $root = dirname(__DIR__);
    require $root . '/vendor/autoload.php';
    require $root . '/application/common.php';
    $GLOBALS['config'] = include $root . '/application/data/config/maccms.example.php';
    $previous = getcwd(); chdir($root);
    try {
        foreach ([
            'upload' => ['Alibaba','Ftp','Qiniu','S3','Uomg','Upyun','Weibo'],
            'pay' => ['Alipay','Codepay','Epay','Jeepay','Weixin','Zhapay'],
            'editor' => ['Ckeditor','Kindeditor','Tinymce','Ueditor','Umeditor'],
            'urlsend' => ['Baidu','Baidufast'], 'sms' => ['Aliyun','Qcloud'], 'email' => ['Phpmailer'],
        ] as $kind => $expected) {
            $result = mac_extends_list($kind);
            $actual = array_keys($result['ext_list']); sort($actual); sort($expected);
            check($actual === $expected, 'Extension discovery lost an adapter or included a helper: ' . $kind);
            foreach ($result['ext_list'] as $name) { check(is_string($name) && $name !== '', 'Adapter label is unusable'); }
        }
        check(!array_key_exists('StorageResult', mac_extends_list('upload')['ext_list']), 'Utility is exposed as an upload adapter');
        echo "Extension discovery: {$checks} assertions passed on PHP " . PHP_VERSION . "\n";
    } finally { chdir($previous); }
}
