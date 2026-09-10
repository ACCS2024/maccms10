<?php
namespace app\common\util;

use app\common\model\User;
use think\Request;

/** The returned account is internal: callers must never serialize its credential fields. */
final class MemberWrite
{
    public static function identity(): array
    {
        try {
            $result = (new User())->checkLogin(false);
            if (($result['code'] ?? null) === 1 && PointsBalance::amount($result['info']['user_id'] ?? null) !== null) {
                return $result;
            }
        } catch (\Throwable $error) {
            return ['code'=>1006, 'msg'=>lang('data_err')];
        }
        return ['code'=>1401, 'msg'=>lang('api/please_login_first')];
    }

    public static function authorize(Request $request): array
    {
        if ($request->method(true) !== 'POST' || $request->method() !== 'POST') {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $identity = self::identity();
        if ($identity['code'] !== 1) { return $identity; }
        // A Bearer-looking header is insufficient: identity() must have verified the enabled JWT.
        if (!(JwtService::isEnabled() && JwtService::bearerFromRequest($request) !== '')
            && !SessionCsrf::validate($request)) {
            return ['code'=>1403, 'msg'=>lang('token_err')];
        }
        return $identity;
    }
}
