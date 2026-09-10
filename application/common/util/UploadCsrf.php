<?php
namespace app\common\util;

use think\Request;

/** Explicit session token for uploads authenticated by automatically sent browser cookies. */
final class UploadCsrf
{
    public static function validate(Request $request): bool
    {
        return SessionCsrf::validate($request);
    }
}
