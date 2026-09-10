<?php
namespace app\common\util;

use think\Request;

/** Shared caching is reserved for an anonymous public catalog, never an authorization result. */
final class ContentCachePolicy
{
    public static function hasPrivateContext(Request $request): bool
    {
        $authorization = $request->header('authorization');
        if ($authorization !== null && $authorization !== '') {
            return true;
        }
        if (!empty($GLOBALS['user']['user_id'])) {
            return true;
        }
        foreach (['user_id', 'user_name', 'user_check', 'is_member', 'group_id', 'group_name'] as $name) {
            if ($request->cookie($name) !== null) {
                return true;
            }
        }
        $sessionName = config('session.name', 'PHPSESSID');
        if (is_string($sessionName) && $sessionName !== '' && $request->cookie($sessionName) !== null) {
            return true;
        }
        $sessionParam = config('session.var_session_id');
        if (is_string($sessionParam) && $sessionParam !== '' && $request->request($sessionParam) !== null) {
            return true;
        }
        try {
            // Includes password grants and CSRF tokens, even when no session Cookie was supplied.
            return $request->session() !== [];
        } catch (\Throwable $error) {
            // Before SessionInit, an anonymous and stateless request has not been established.
            return true;
        }
    }

    public static function isPublicCatalog(Request $request): bool
    {
        if (!defined('ENTRANCE') || !in_array(ENTRANCE, ['index', 'api'], true)
            || $request->method(true) !== 'GET' || $request->method() !== 'GET') {
            return false;
        }
        $controller = strtolower($request->controller());
        $action = strtolower($request->action());
        if (ENTRANCE === 'index' && $controller === 'index') {
            return $action === 'index';
        }
        if (!in_array($controller, ['vod', 'art', 'manga', 'actor', 'topic', 'role', 'website'], true)) {
            return false;
        }
        return in_array($action, ENTRANCE === 'index' ? ['index', 'type', 'show'] : [
            'get_list', 'get_recommend', 'get_hot', 'get_latest', 'get_banner',
            'get_year', 'get_class', 'get_area', 'get_rank', 'get_latest_by_type', 'suggest',
        ], true);
    }

    public static function requiresPrivateResponse(Request $request): bool
    {
        return defined('ENTRANCE') && in_array(ENTRANCE, ['index', 'api'], true)
            && (!self::isPublicCatalog($request) || self::hasPrivateContext($request));
    }
}
