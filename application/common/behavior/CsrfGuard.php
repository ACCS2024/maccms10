<?php
namespace app\common\behavior;

use think\exception\HttpResponseException;
use think\Request;
use think\Response;
use think\Session;

/**
 * 后台 CSRF：校验 POST 的 __token__ 或请求头 X-CSRF-Token 与 Session 一致（不删除 Session，避免与控制器内 Token 校验冲突）。
 *
 * security_csrf_admin_exempt：逗号分隔，项为小写 controller/action 或 controller/*（不含模块名；与 parseDispatch 得到的 $c/$a 一致）。
 * 默认配置里含 upload/*：部分上传端点不便带表单字段；开启校验后若某模块仍报 token_err，可临时追加如 make/*、cj/* 再逐步收紧。
 * upload/ueditor* 与 assistant/chat 在代码中已硬豁免。
 */
class CsrfGuard
{
    public function run(&$dispatch)
    {
        if (PHP_SAPI === 'cli') {
            return;
        }
        if (!defined('ENTRANCE') || ENTRANCE !== 'admin') {
            return;
        }

        $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : [];
        if (empty($app['security_csrf_admin']) || (string)$app['security_csrf_admin'] === '0') {
            return;
        }

        $req = Request::instance();
        if (!$req->isPost()) {
            return;
        }

        list($m, $c, $a) = self::parseDispatch($dispatch);
        $routeKey = strtolower($c) . '/' . strtolower($a);

        // 登录入口豁免:登录前尚无会话令牌,登录本身即认证入口
        if ($routeKey === 'index/login' || strtolower($a) === 'login') {
            return;
        }
        if ($c === 'upload' && strncmp(strtolower($a), 'ueditor', 7) === 0) {
            return;
        }
        if ($routeKey === 'assistant/chat') {
            return;
        }

        $exempt = isset($app['security_csrf_admin_exempt']) ? trim((string)$app['security_csrf_admin_exempt']) : '';
        if ($exempt !== '') {
            foreach (explode(',', $exempt) as $one) {
                $one = strtolower(trim(str_replace('\\', '/', $one)));
                if ($one !== '' && ($one === $routeKey || $one === $c . '/*')) {
                    return;
                }
            }
        }

        // 双令牌校验:① 稳定 X-CSRF-Token 头 vs 会话 __csrf_token__(覆盖全部后台 ajax)
        //            ② 传统表单一次性 __token__ vs 会话 __token__(控制器内 validate('Token') 用)
        $ok = false;
        $header = $req->header('X-CSRF-Token');
        $header = ($header === null) ? '' : (string)$header;
        if ($header !== '' && Session::has('__csrf_token__')
            && hash_equals((string)Session::get('__csrf_token__'), $header)) {
            $ok = true;
        }
        if (!$ok) {
            $param = $req->param('__token__');
            if (is_string($param) && $param !== '' && Session::has('__token__')
                && hash_equals((string)Session::get('__token__'), $param)) {
                $ok = true;
            }
        }
        if (!$ok) {
            self::deny($req, $app);
        }
    }

    /**
     * @return array{0:string,1:string,2:string} module, controller, action (lower)
     */
    private static function parseDispatch($dispatch)
    {
        $m = '';
        $c = '';
        $a = '';
        if (empty($dispatch['type']) || $dispatch['type'] !== 'module' || empty($dispatch['module'])) {
            return [$m, $c, $a];
        }
        $mod = $dispatch['module'];
        if (is_array($mod)) {
            $parts = array_values(array_map(static function ($v) {
                return strtolower((string)$v);
            }, $mod));
        } else {
            $parts = explode('/', trim(str_replace('\\', '/', (string)$mod), '/'));
            $parts = array_values(array_filter(array_map('strtolower', $parts), static function ($p) {
                return $p !== '';
            }));
        }
        if (defined('ENTRANCE') && ENTRANCE === 'admin' && count($parts) === 2) {
            array_unshift($parts, 'admin');
        }
        $m = (string)($parts[0] ?? '');
        $c = (string)($parts[1] ?? '');
        $a = (string)($parts[2] ?? '');

        return [$m, $c, $a];
    }

    private static function readSubmittedToken(Request $req)
    {
        $t = $req->param('__token__');
        if (is_string($t) && $t !== '') {
            return $t;
        }
        if (is_array($t)) {
            return '';
        }
        $h = $req->header('X-CSRF-Token');
        if ($h !== null && $h !== '') {
            return (string)$h;
        }

        return '';
    }

    private static function deny(Request $req, array $app)
    {
        $msg = function_exists('lang') ? lang('token_err') : 'CSRF token mismatch';
        $code = isset($app['security_csrf_http_code']) ? (int)$app['security_csrf_http_code'] : 403;
        if ($code < 400 || $code > 599) {
            $code = 403;
        }
        if ($req->isAjax()) {
            throw new HttpResponseException(json(['code' => 1002, 'msg' => $msg], $code));
        }
        throw new HttpResponseException(Response::create($msg, 'html', $code));
    }
}
