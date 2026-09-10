<?php
namespace app\common\extend\sms {
    function curl_init() { return new \stdClass(); }
    function curl_setopt($handle, $option, $value) { $GLOBALS['sms_options'][$option] = $value; return true; }
    function curl_exec($handle) { return $GLOBALS['sms_reply']; }
    function curl_errno($handle) { return 7; }
    function curl_error($handle) { return 'fixture transport failure'; }
    function curl_close($handle) { ++$GLOBALS['sms_closed']; }
}
namespace {
    require __DIR__ . '/fixtures/security_audit_test_helpers.php';
    require dirname(__DIR__) . '/application/common/extend/sms/Aliyun.php';
    $GLOBALS['config'] = ['sms' => ['aliyun' => ['appid' => 'fixture', 'appkey' => 'fixture'],
        'sign' => 'fixture', 'tpl_code_reg' => 'fixture']];
    $GLOBALS['sms_closed'] = 0;
    $client = new \app\common\extend\sms\Aliyun();
    $GLOBALS['sms_reply'] = '{"Code":"OK"}';
    check($client->submit('13800000000', '123456', 'reg', '', '')['code'] === 1, 'Valid SMS response rejected');
    check($GLOBALS['sms_options'][CURLOPT_URL] === 'https://dysmsapi.aliyuncs.com/', 'SMS must use HTTPS');
    check($GLOBALS['sms_options'][CURLOPT_SSL_VERIFYPEER] === true
        && $GLOBALS['sms_options'][CURLOPT_SSL_VERIFYHOST] === 2, 'SMS TLS validation required');
    foreach ([false, '', '{}', 'null', '[]', '{"Code":"FAIL","Message":[]}'] as $reply) {
        $GLOBALS['sms_reply'] = $reply;
        check($client->submit('13800000000', '123456', 'reg', '', '')['code'] !== 1, 'Invalid SMS response reported success');
    }
    check($GLOBALS['sms_closed'] === 7, 'Transport handles must close on success and failure');
    check($client->submit([], '123456', 'reg', '', '')['code'] !== 1, 'Array input must fail validation');
    echo 'SMS regressions: ' . $checks . " assertions passed\n";
}
