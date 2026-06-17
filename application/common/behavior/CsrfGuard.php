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

        list($m, $c, $a) = self::parseDispatch($dispatch);
        $c = strtolower($c);
        $a = strtolower($a);
        $routeKey = $c . '/' . $a;

        // 登录入口豁免:登录前尚无会话令牌,登录本身即认证入口
        if ($routeKey === 'index/login' || $a === 'login') {
            return;
        }
        if ($c === 'upload' && strncmp($a, 'ueditor', 7) === 0) {
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

        // 变更类动作(默认 del/field,可经 security_csrf_admin_post_actions 追加)强制走 POST:
        // 这些是纯写操作(无 GET 读/渲染语义),前台 admin_common.js 已统一改为 $.post 携带令牌提交。
        // GET 触发(顶层导航式 CSRF)直接拒绝——SameSite=Lax 已挡零点击子资源攻击,此处补齐顶层导航缺口。
        if (!$req->isPost() && in_array($a, self::mutatingActions($app), true)) {
            self::deny($req, $app);
        }

        // 高危写操作(按 controller/action 精确限定,默认 database/import 数据库恢复)强制 POST:
        // 这些动作名(如 import)在其他控制器另有 GET 读语义,不能按动作名全局拒绝,故用 c/a 精确限定。
        // 合法入口本就是带 X-CSRF-Token 的 $.post(列表页 j-ajax 按钮),GET 触发(顶层导航式 CSRF)直接拒绝。
        if (!$req->isPost() && in_array($routeKey, self::forcePostRoutes($app), true)) {
            self::deny($req, $app);
        }

        // 非变更类的 GET 不校验令牌(保持列表/表单页可直接导航访问)
        if (!$req->isPost()) {
            return;
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

    /**
     * 需强制 POST 的变更类动作名(小写)。默认 del/field（纯写操作，无 GET 读语义）;
     * 站点可经 config app.security_csrf_admin_post_actions（逗号分隔）按需追加，如 move,clearcache。
     */
    private static function mutatingActions(array $app)
    {
        $list = ['del', 'field'];
        $cfg = isset($app['security_csrf_admin_post_actions']) ? trim((string)$app['security_csrf_admin_post_actions']) : '';
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

    /**
     * 需强制 POST 的高危写操作(controller/action 小写;默认 database/import 数据库恢复)。
     * 动作名(如 import)在其他控制器另有 GET 读语义,故按 c/a 精确限定,不进 mutatingActions 全局名单。
     * 合法调用本就走带令牌的 $.post;站点可经 config app.security_csrf_admin_post_routes(逗号分隔 c/a)追加。
     */
    private static function forcePostRoutes(array $app)
    {
        $list = ['database/import'];
        $cfg = isset($app['security_csrf_admin_post_routes']) ? trim((string)$app['security_csrf_admin_post_routes']) : '';
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
