<?php
namespace app\common\util;

/**
 * Session CSRF for UEditor AI proxy (same idea as addons\aicontent\Aicontent::generateCsrfToken).
 */
class UeditorAiCsrf
{
    private const SESSION_KEY = 'ueditor_ai_csrf_token';

    public static function token(): string
    {
        $t = session(self::SESSION_KEY);
        if ($t === null || $t === '') {
            $t = bin2hex(random_bytes(16));
            session(self::SESSION_KEY, $t);
        }

        $t = (string) $t;
        /* 对话框与内容页不同 window 时 Cookie + 服务端比对；HTTPS 下需 Secure 否则部分浏览器不发送 */
        if (!headers_sent()) {
            $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                || (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443);
            if (\PHP_VERSION_ID >= 70300) {
                setcookie('ueditor_ai_csrf', $t, [
                    'expires'  => time() + 7200,
                    'path'     => '/',
                    'secure'   => $secure,
                    'httponly' => false,
                    'samesite' => 'Lax',
                ]);
            } else {
                setcookie('ueditor_ai_csrf', $t, time() + 7200, '/', '', $secure, false);
            }
        }

        return $t;
    }

    /**
     * 仅接受调用方显式提交的令牌。Cookie 可供同源 JS 读取，但浏览器自动携带的
     * Cookie 不能作为 CSRF 证明，否则缺失或错误的请求令牌也会被放行。
     */
    public static function validate($submitted): bool
    {
        $expected = session(self::SESSION_KEY);
        if ($expected === null || $expected === '') {
            return false;
        }
        $expected = (string) $expected;
        return is_string($submitted) && $submitted !== '' && hash_equals($expected, $submitted);
    }
}
