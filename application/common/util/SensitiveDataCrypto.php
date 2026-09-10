<?php
namespace app\common\util;

/**
 * 敏感字符串对称加密（AES-256-GCM），用于审计日志等落库场景。
 * 新写入必须配置独立强密钥；加密失败返回 false，不降级为明文。
 * 旧版派生密钥仅保留用于读取历史日志。
 */
class SensitiveDataCrypto
{
    const PREFIX_GCM = 'MACENC1:';

    const IV_LEN = 12;

    const TAG_LEN = 16;

    const METHOD = 'aes-256-gcm';

    public static function hasStrongSecret(array $app): bool
    {
        return is_string($app['admin_audit_crypto_secret'] ?? null)
            && strlen(trim($app['admin_audit_crypto_secret'])) >= 32;
    }

    /**
     * 当前环境是否可用 AES-256-GCM（与 encryptString 实际是否加密一致）。
     */
    public static function supportsAes256Gcm()
    {
        if (!function_exists('openssl_encrypt')) {
            return false;
        }
        $methods = openssl_get_cipher_methods();
        if (!is_array($methods)) {
            return false;
        }

        return in_array(self::METHOD, $methods, true);
    }

    /**
     * @param array<string,mixed> $app maccms app 配置块
     */
    public static function deriveKeyFromApp(array $app)
    {
        $explicit = isset($app['admin_audit_crypto_secret']) ? trim((string)$app['admin_audit_crypto_secret']) : '';
        if ($explicit !== '') {
            return hash('sha256', $explicit, true);
        }
        $flag = isset($app['cache_flag']) ? (string)$app['cache_flag'] : 'mac';
        $pfx = '';
        if (function_exists('config')) {
            $pfx = (string)(config('database.connections.mysql.prefix') ?: '');
        }

        return hash('sha256', 'maccms.sensitive_crypto.v1|' . $flag . '|' . $pfx, true);
    }

    /**
     * 加密为带版本前缀的 ASCII 串；配置不足或失败返回 false。
     */
    public static function encryptString($plaintext, ?array $app = null)
    {
        if ($plaintext === null || $plaintext === '') {
            return $plaintext;
        }
        $app = $app ?? (isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : []);
        if (!self::hasStrongSecret($app) || !self::supportsAes256Gcm()) {
            return false;
        }
        $key = self::deriveKeyFromApp($app);
        $iv = random_bytes(self::IV_LEN);
        $tag = '';
        $ct = @openssl_encrypt((string)$plaintext, self::METHOD, $key, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LEN);
        if ($ct === false || strlen($tag) !== self::TAG_LEN) {
            return false;
        }

        return self::PREFIX_GCM . base64_encode($iv . $tag . $ct);
    }

    /**
     * 若为加密串则解密；否则原样返回历史明文。
     *
     * @return string|false
     */
    public static function decryptString($stored, ?array $app = null)
    {
        if ($stored === null || $stored === '') {
            return $stored;
        }
        $stored = (string)$stored;
        if (strpos($stored, self::PREFIX_GCM) !== 0) {
            return $stored;
        }
        $app = $app ?? (isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : []);
        if (!self::supportsAes256Gcm()) {
            return false;
        }
        $raw = @base64_decode(substr($stored, strlen(self::PREFIX_GCM)), true);
        if ($raw === false || strlen($raw) < self::IV_LEN + self::TAG_LEN + 1) {
            return false;
        }
        $iv = substr($raw, 0, self::IV_LEN);
        $tag = substr($raw, self::IV_LEN, self::TAG_LEN);
        $ct = substr($raw, self::IV_LEN + self::TAG_LEN);
        $key = self::deriveKeyFromApp($app);
        $plain = @openssl_decrypt($ct, self::METHOD, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($plain === false) {
            return false;
        }

        return $plain;
    }

    public static function isEncryptedPayload($stored)
    {
        return is_string($stored) && strpos($stored, self::PREFIX_GCM) === 0;
    }
}
