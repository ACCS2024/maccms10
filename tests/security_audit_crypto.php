<?php
// Isolated regression: no application boot, persistent storage or external network.
function config($key) { return $key === 'database.connections.mysql.prefix' ? 'mac_' : null; }
require dirname(__DIR__) . '/application/common.php';
require dirname(__DIR__) . '/application/common/util/SensitiveDataCrypto.php';
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
    $crypto = ['admin_audit_crypto_secret' => str_repeat('fixture-key-', 4)];
    $encrypted = \app\common\util\SensitiveDataCrypto::encryptString('sensitive audit payload', $crypto);
    check(true, \app\common\util\SensitiveDataCrypto::isEncryptedPayload($encrypted), 'explicit key encrypts');
    check('sensitive audit payload', \app\common\util\SensitiveDataCrypto::decryptString($encrypted, $crypto), 'GCM round trip');
    check(false, \app\common\util\SensitiveDataCrypto::decryptString($encrypted, ['admin_audit_crypto_secret' => str_repeat('wrong', 8)]), 'wrong key rejected');
    check(false, \app\common\util\SensitiveDataCrypto::encryptString('sensitive audit payload', []), 'no predictable-key fallback');
    check(false, \app\common\util\SensitiveDataCrypto::encryptString('sensitive audit payload', ['admin_audit_crypto_secret' => 'short']), 'short key cannot write ciphertext');
    check('historical plaintext', \app\common\util\SensitiveDataCrypto::decryptString('historical plaintext', []), 'historical plaintext remains readable');
    $iv = str_repeat('x', 12);
    $tag = '';
    $oldKey = hash('sha256', 'maccms.sensitive_crypto.v1|mac|mac_', true);
    $old = openssl_encrypt('historical ciphertext', 'aes-256-gcm', $oldKey, OPENSSL_RAW_DATA, $iv, $tag);
    check('historical ciphertext', \app\common\util\SensitiveDataCrypto::decryptString('MACENC1:' . base64_encode($iv . $tag . $old), []),
        'legacy derived-key ciphertext remains readable');

    echo "Audit encryption contracts: {$checks} checks passed on PHP " . PHP_VERSION . "\n";
