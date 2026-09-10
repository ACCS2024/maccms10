<?php
namespace addons\aicontent\service;

use think\exception\HttpResponseException;

final class AdminAccess
{
    public static function current(): array
    {
        $result = (new \app\common\model\Admin())->checkLogin();
        if (($result['code'] ?? 0) !== 1) {
            throw new HttpResponseException(json(['code' => 0, 'message' => lang('Unauthorized. Please log in to the admin panel.')], 401));
        }
        return $result['info'];
    }

    public static function requireAny(array $admin, array $permissions): void
    {
        if (!self::allows($admin, $permissions)) {
            throw new HttpResponseException(json(['code' => 0, 'message' => lang('permission_denied')], 403));
        }
    }

    public static function allows(array $admin, array $permissions): bool
    {
        if ((int)($admin['admin_id'] ?? 0) === 1) { return true; }
        $normalize = static fn($key) => strtolower(str_replace('_', '', trim($key)));
        $granted = array_map($normalize, explode(',', (string)($admin['admin_auth'] ?? '')));
        foreach ($permissions as $permission) {
            if (in_array($normalize($permission), $granted, true)) { return true; }
        }
        return false;
    }

    public static function contentPermission($type): string
    {
        $map = ['video' => 'vod/info', 'article' => 'art/info', 'topic' => 'topic/info'];
        if (!is_string($type) || !isset($map[$type])) {
            throw new HttpResponseException(json(['code' => 0, 'message' => lang('param_err')], 400));
        }
        return $map[$type];
    }
}
