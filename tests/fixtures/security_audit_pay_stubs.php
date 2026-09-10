<?php
/** Real provider signatures/XML, controlled order outcomes, no application boot or network. */
namespace app\common\model {
    class Order
    {
        public function notify($code, $provider, $paid = null) {
            $GLOBALS['pay_calls'][] = [$code, $provider, $paid];
            if ($GLOBALS['pay_result'] instanceof \Throwable) { throw $GLOBALS['pay_result']; }
            return $GLOBALS['pay_result'];
        }
    }
}
namespace think\facade {
    class Db
    {
        public static function name($table) { return new \PayAuditQuery(); }
    }
}
namespace app\common\extend\pay {
    function file_get_contents($filename, ...$args) {
        if ($filename !== 'php://input') { throw new \RuntimeException('Unexpected file access'); }
        return $GLOBALS['pay_xml'];
    }
}
namespace {
    require_once __DIR__ . '/security_audit_test_helpers.php';
    function config($key) {
        return $key === 'database.connections.mysql.prefix' ? 'audit_' : $GLOBALS['pay_config'];
    }
    require dirname(__DIR__, 2) . '/application/common.php';
    class PayAuditQuery
    {
        public function where($field, $value) { return $this; }
        public function find() {
            if ($GLOBALS['pay_order'] instanceof Throwable) { throw $GLOBALS['pay_order']; }
            return $GLOBALS['pay_order'];
        }
    }
    function pay_reset(): void {
        foreach (['alipay', 'weixin', 'epay', 'codepay', 'zhapay', 'jeepay'] as $provider) {
            $GLOBALS['pay_config'][$provider] = ['appid' => 'fixture-app', 'appkey' => 'fixture-' . $provider . '-key',
                'mchid' => 'fixture-merchant', 'mch_no' => 'fixture-merchant', 'account' => 'fixture@example.invalid'];
        }
        $GLOBALS['config']['pay'] = $GLOBALS['pay_config'];
        $GLOBALS['pay_calls'] = [];
        $GLOBALS['pay_result'] = ['code' => 1, 'msg' => 'paid'];
        $GLOBALS['pay_order'] = ['order_price' => '10.00'];
        $_POST = $_GET = $_REQUEST = $_COOKIE = [];
        $_SERVER['REQUEST_METHOD'] = 'POST';
    }
    /** Build signatures independently from the production signing helpers. */
    function pay_sign(string $provider, array $payload): array {
        unset($payload['sign']);
        $signed = $payload;
        if (in_array($provider, ['alipay', 'epay'], true)) { unset($signed['sign_type']); }
        $signed = array_filter($signed, static fn($value) => $value !== '' && $value !== null);
        ksort($signed, SORT_STRING);
        $pairs = [];
        foreach ($signed as $name => $value) { $pairs[] = $name . '=' . $value; }
        $key = $GLOBALS['pay_config'][$provider]['appkey'];
        $message = implode('&', $pairs) . (in_array($provider, ['weixin', 'jeepay'], true) ? '&key=' : '') . $key;
        $digest = ($provider === 'weixin' && ($payload['sign_type'] ?? '') === 'HMAC-SHA256')
            ? hash_hmac('sha256', $message, $key) : md5($message);
        $payload['sign'] = in_array($provider, ['weixin', 'jeepay'], true) ? strtoupper($digest) : $digest;
        return $payload;
    }
    function pay_capture(string $provider, array $payload = [], ?string $xml = null): string {
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') { $_GET = $payload; }
        else { $_POST = $payload; }
        $GLOBALS['pay_xml'] = $xml ?? ($provider === 'weixin' ? mac_array2xml($payload) : '');
        $class = 'app\\common\\extend\\pay\\' . ucfirst($provider);
        ob_start();
        try { (new $class())->notify(); return ob_get_contents(); }
        finally { ob_end_clean(); }
    }
    function pay_failures(string $provider, array $valid, string $success): void {
        foreach ([['code' => 1001], ['code' => 2002], ['code' => 2003], ['code' => 2004], ['code' => 2005],
            ['code' => 0], ['code' => '1garbage'], [], new RuntimeException('fixture database failure')] as $result) {
            $GLOBALS['pay_result'] = $result;
            check(pay_capture($provider, $valid) !== $success, 'Failed or malformed order result was acknowledged as successful');
        }
        $GLOBALS['pay_result'] = ['code' => 1, 'msg' => 'already paid'];
        check(pay_capture($provider, $valid) === $success, 'Idempotent order success was not acknowledged');
    }
    pay_reset();
}
