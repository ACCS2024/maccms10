<?php
namespace app\common\util;

use think\Request;

/** Explicit session token for uploads authenticated by automatically sent browser cookies. */
final class UploadCsrf
{
    public static function validate(Request $request): bool
    {
        $expected = session('__csrf_token__');
        if (!is_string($expected) || $expected === '' || strlen($expected) > 128) { return false; }
        // An explicitly supplied invalid header must not fall back to a second credential source.
        $submitted = $request->header('X-CSRF-Token');
        if ($submitted === null) { $submitted = $request->post('csrf_token'); }
        return is_string($submitted) && $submitted !== '' && strlen($submitted) <= 128
            && hash_equals($expected, $submitted);
    }
}
