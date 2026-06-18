<?php
namespace app\middleware;

use think\exception\HttpResponseException;
use think\facade\Request;
use think\facade\Session;

/**
 * 后台 CSRF 校验。
 * TP8 适配：dispatch 数组不再可用，改从 pathinfo 解析 controller/action。
 */
class CsrfGuard
{
    public function handle($request, \Closure $next)
    {
        if (PHP_SAPI === 'cli') {
            return $next($request);
        }
        if (!defined('ENTRANCE') || ENTRANCE !== 'admin') {
            return $next($request);
        }

        $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : [];
        if (empty($app['security_csrf_admin']) || (string)$app['security_csrf_admin'] === '0') {
            return $next($request);
        }

        [$c, $a] = $this->parsePathinfo($request);
        $routeKey = $c . '/' . $a;

        if ($routeKey === 'index/login' || $a === 'login') {
            return $next($request);
        }
        if ($c === 'upload' && strncmp($a, 'ueditor', 7) === 0) {
            return $next($request);
        }
        if ($routeKey === 'assistant/chat') {
            return $next($request);
        }

        $exempt = isset($app['security_csrf_admin_exempt']) ? trim((string)$app['security_csrf_admin_exempt']) : '';
        if ($exempt !== '') {
            foreach (explode(',', $exempt) as $one) {
                $one = strtolower(trim(str_replace('\\', '/', $one)));
                if ($one !== '' && ($one === $routeKey || $one === $c . '/*')) {
                    return $next($request);
                }
            }
        }

        if (!$request->isPost() && in_array($a, $this->mutatingActions($app), true)) {
            $this->deny($request, $app);
        }

        if (!$request->isPost() && in_array($routeKey, $this->forcePostRoutes($app), true)) {
            $this->deny($request, $app);
        }

        if (!$request->isPost()) {
            return $next($request);
        }

        $ok     = false;
        $header = (string)($request->header('X-CSRF-Token') ?? '');
        if ($header !== '' && Session::has('__csrf_token__')
            && hash_equals((string)Session::get('__csrf_token__'), $header)) {
            $ok = true;
        }
        if (!$ok) {
            $param = $request->param('__token__');
            if (is_string($param) && $param !== '' && Session::has('__token__')
                && hash_equals((string)Session::get('__token__'), $param)) {
                $ok = true;
            }
        }
        if (!$ok) {
            $this->deny($request, $app);
        }

        return $next($request);
    }

    private function parsePathinfo($request): array
    {
        $pi    = strtolower(trim((string)$request->pathinfo(), '/'));
        $pi    = (string)preg_replace('/\.(html|htm)$/i', '', $pi);
        $parts = array_values(array_filter(explode('/', $pi), static fn($p) => $p !== ''));
        $c     = $parts[0] ?? '';
        $a     = $parts[1] ?? 'index';
        return [$c, $a];
    }

    private function mutatingActions(array $app): array
    {
        $list = ['del', 'field'];
        $cfg  = isset($app['security_csrf_admin_post_actions']) ? trim((string)$app['security_csrf_admin_post_actions']) : '';
        if ($cfg !== '') {
            foreach (explode(',', $cfg) as $one) {
                $one = strtolower(trim($one));
                if ($one !== '' && !in_array($one, $list, true)) {
                    $list[] = $one;
                }
            }
        }
        return $list;
    }

    private function forcePostRoutes(array $app): array
    {
        $list = ['database/import'];
        $cfg  = isset($app['security_csrf_admin_post_routes']) ? trim((string)$app['security_csrf_admin_post_routes']) : '';
        if ($cfg !== '') {
            foreach (explode(',', $cfg) as $one) {
                $one = strtolower(trim(str_replace('\\', '/', $one)));
                if ($one !== '' && !in_array($one, $list, true)) {
                    $list[] = $one;
                }
            }
        }
        return $list;
    }

    private function deny($request, array $app): void
    {
        $msg  = function_exists('lang') ? lang('token_err') : 'CSRF token mismatch';
        $code = isset($app['security_csrf_http_code']) ? (int)$app['security_csrf_http_code'] : 403;
        if ($code < 400 || $code > 599) {
            $code = 403;
        }
        if ($request->isAjax()) {
            throw new HttpResponseException(json(['code' => 1002, 'msg' => $msg], $code));
        }
        throw new HttpResponseException(response($msg, $code));
    }
}
