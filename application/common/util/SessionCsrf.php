<?php
namespace app\common\util;

use think\Request;

/** Explicit browser credential bound to the current server-side session. */
final class SessionCsrf
{
    public static function issue(): string
    {
        $token = session('__csrf_token__');
        if (!is_string($token) || $token === '' || strlen($token) > 128) {
            $token = bin2hex(random_bytes(32));
            session('__csrf_token__', $token);
        }
        return $token;
    }

    public static function validate(Request $request): bool
    {
        $expected = session('__csrf_token__');
        if (!is_string($expected) || $expected === '' || strlen($expected) > 128) { return false; }
        // A present invalid header never falls back to another credential source.
        $submitted = $request->header('X-CSRF-Token');
        if ($submitted === null) { $submitted = $request->post('csrf_token'); }
        return is_string($submitted) && $submitted !== '' && strlen($submitted) <= 128
            && hash_equals($expected, $submitted);
    }
}
