<?php
// Isolated regression: no application boot, persistent storage or external network.
function config($key) { return $key === 'database.connections.mysql.prefix' ? 'mac_' : null; }
require dirname(__DIR__) . '/application/common.php';
require dirname(__DIR__) . '/application/common/util/JwtService.php';
set_error_handler(static function ($severity, $message, $file, $line) {
        if (!(error_reporting() & $severity)) { return false; }
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    $checks = 0;
    function check($expected, $actual, $label) {
        global $checks;
        if ($expected !== $actual) { throw new RuntimeException('FAIL: ' . $label); }
        ++$checks;
    }
    $GLOBALS['config'] = include dirname(__DIR__) . '/application/data/config/maccms.example.php';
    $GLOBALS['config']['app']['api_jwt_enabled'] = '1';
    $GLOBALS['config']['app']['api_jwt_secret'] = str_repeat('test-key-', 8);
    $GLOBALS['config']['app']['api_jwt_iss'] = 'audit-fixture';
    $token = \app\common\util\JwtService::encode(7, 'session-random');
    $claims = \app\common\util\JwtService::decodeAndVerify($token);
    check('7', $claims['sub'], 'issued JWT verifies');
    function b64($value) { return rtrim(strtr(base64_encode($value), '+/', '-_'), '='); }
    function signed(array $claims, array $header = ['alg' => 'HS256', 'typ' => 'JWT']) {
        $body = b64(json_encode($header)) . '.' . b64(json_encode($claims));
        return $body . '.' . b64(hash_hmac('sha256', $body, \app\common\util\JwtService::getSecret(), true));
    }
    foreach ([['iss', 'another-site'], ['exp', time()], ['exp', '9999999999'], ['iat', time() + 3600],
        ['nbf', time() + 3600], ['sub', '0'], ['sub', []], ['rnd', []]] as [$field, $value]) {
        $bad = $claims;
        $bad[$field] = $value;
        check(null, \app\common\util\JwtService::decodeAndVerify(signed($bad)), 'JWT claim rejected: ' . $field);
    }
    foreach ([['alg' => 'none', 'typ' => 'JWT'], ['alg' => 'HS256', 'typ' => 'other'],
        ['alg' => 'HS256', 'typ' => 'JWT', 'crit' => ['unknown']]] as $header) {
        check(null, \app\common\util\JwtService::decodeAndVerify(signed($claims, $header)), 'JWT header contract enforced');
    }
    check(null, \app\common\util\JwtService::decodeAndVerify($token . 'x'), 'modified signature rejected');
    $GLOBALS['config']['app']['api_jwt_enabled'] = '0';
    check(null, \app\common\util\JwtService::decodeAndVerify($token), 'disabled JWT rejected');


    echo "JWT validation contracts: {$checks} checks passed on PHP " . PHP_VERSION . "\n";
