<?php
declare(strict_types=1);

namespace app;

use think\exception\Handle;
use think\exception\HttpException;
use think\facade\View;
use think\Request;
use think\Response;
use Throwable;

/**
 * 全局异常处理 —— 注册于 application/provider.php。
 *
 * 解决的问题
 * ----------
 * TP8 默认的错误页（think_exception.html）在任何 HTTP 状态下都携带框架指纹：
 * "系统发生错误 / ThinkPHP" 等字样，随机 URL 扫描即可探知后端技术栈。
 *
 * 设计原则
 * --------
 * 1. 404（路由缺失）：无论 debug 模式是否开启，始终返回主题适配的错误页。
 *    优先渲染当前主题的 error/404.html（带 header/footer，风格与整站一致）；
 *    若主题模板本身损坏，降级为内联纯 HTML 兜底，确保 404 页不会再次 500。
 *
 * 2. 其他异常 + debug=true（开发环境）：透传给 TP8 默认处理器，保留完整
 *    stack trace，方便开发调试。
 *
 * 3. 其他异常 + debug=false（生产环境）：返回简洁错误页，不暴露框架/路径/
 *    SQL 片段等内部信息。
 *    扩展点：可为常见状态码（403/500 等）添加对应主题模板（error/5xx.html）。
 *
 * debug 模式开关
 * ---------------
 * 仅通过 config/app.php 的 app_debug 控制，不应在后台 UI 提供切换入口。
 * 原因：admin 凭证泄漏 → 开启 debug → 任意报错页暴露完整 stack。
 * 生产排查问题请使用日志（runtime/index/log），而非开 debug。
 *
 * 主题模板目录约定
 * -----------------
 * template/{template_dir}/{html_dir}/error/404.html
 * 当前主题（vozy/vo20w2）已提供该模板。
 * 其他主题适配时，在对应 error/ 子目录下按需添加即可。
 */
class ExceptionHandle extends Handle
{
    /**
     * 将异常转换为 HTTP 响应。
     *
     * 覆盖父类 render()，优先处理 404，再区分 debug/生产模式。
     */
    public function render(Request $request, Throwable $e): Response
    {
        // ── 1. 路由 404 ──────────────────────────────────────────────────────
        // HttpException 404 = 路由找不到，与 debug 模式无关，始终返回主题化页。
        // 先尝试渲染主题模板；若主题文件本身有问题则降级为纯 HTML 兜底。
        if ($e instanceof HttpException && $e->getStatusCode() === 404) {
            return $this->themeErrorPage(404, 'error/404', '页面不存在', '您访问的页面不存在');
        }

        // ── 2. debug=true（开发环境）─────────────────────────────────────────
        // 保留 TP8 完整 debug 页（文件/行号/堆栈/SQL），方便开发调试。
        // 注意：此分支不应在生产服务器触达，请确保 config/app.php app_debug=false。
        if ($this->app->isDebug()) {
            return parent::render($request, $e);
        }

        // ── 3. 生产环境其他异常 ───────────────────────────────────────────────
        // 取 HTTP 状态码（HttpException 携带语义码，其余 PHP 异常统一 500）。
        // 不向客户端暴露 message/file/trace，错误细节只写日志。
        // 扩展点：可仿照 404 为 403/500 增加主题模板（themeErrorPage(500, 'error/5xx', ...)）。
        $status = ($e instanceof HttpException) ? $e->getStatusCode() : 500;
        return $this->plainPage($status, '页面错误', '服务器发生错误，请稍后重试');
    }

    /**
     * 优先渲染主题 error 模板，失败时降级为内联纯 HTML。
     *
     * 降级原因：异常处理器本身不能抛出异常，若主题模板损坏（语法错误、
     * include 缺失等）会触发新的异常，导致白屏。try/catch 在此是必要的防御。
     *
     * 为什么要手动 assign $maccms
     * ----------------------------
     * 正常请求中，$maccms 由 common/controller/All::label_maccms() 在
     * controller initialize() 阶段 assign 到 View。404 路由不命中时，
     * controller 从未实例化，$maccms 缺失导致 View::fetch 抛 ErrorException。
     * AppInit 中间件已在 ExceptionHandle 之前运行，$GLOBALS['config'] 可用，
     * 故在此手动补齐 View 所需的最小 $maccms 字段集。
     *
     * @param int    $status   HTTP 状态码
     * @param string $tpl      相对于主题目录的模板路径，如 'error/404'
     * @param string $title    降级页标题
     * @param string $message  降级页描述
     */
    private function themeErrorPage(int $status, string $tpl, string $title, string $message): Response
    {
        try {
            // 从 AppInit 已初始化的 $GLOBALS['config'] 中提取 $maccms 模板变量。
            // 仅补 error 模板（head/foot）实际依赖的字段；如遇其他缺失字段
            // 可在此追加，不影响主流程，异常时仍 fallback 到 plainPage。
            $cfg = $GLOBALS['config'] ?? [];
            $site = $cfg['site'] ?? [];
            $maccms = array_merge($site, [
                'path'      => defined('MAC_PATH') ? MAC_PATH : '',
                'path_tpl'  => $GLOBALS['MAC_PATH_TEMPLATE'] ?? '',
                'date'      => date('Y-m-d'),
                'http_type' => $GLOBALS['http_type'] ?? 'http://',
                'seo'       => $cfg['seo'] ?? [],
                // head/include 模板需要的字段；error 页无实际菜单/会员语境，置 0。
                'mid'       => 0,
                'aid'       => 0,
                'controller_action' => 'error/404',
                'user_status' => $cfg['user']['status'] ?? 0,
                'search_hot'  => $cfg['app']['search_hot'] ?? '',
            ]);
            View::assign('maccms', $maccms);
            View::assign('param', []);
            View::assign('popedom', ['code' => 1, 'msg' => '', 'trysee' => 0, 'confirm' => 0]);

            $content = View::fetch($tpl);
            return Response::create($content, 'html', $status);
        } catch (Throwable $t) {
            // 主题模板不存在或渲染失败，降级为纯 HTML，保证页面可访问。
            // 此处故意不 rethrow，避免 404 处理器本身造成 500。
            return $this->plainPage($status, $title, $message);
        }
    }

    /**
     * 最终兜底：无任何框架/主题依赖的内联 HTML。
     *
     * 仅在以下情况使用：
     * - 主题模板渲染失败（降级自 themeErrorPage）
     * - 生产环境非 404 异常（500 等，尚无对应主题模板时）
     *
     * @param int    $status  HTTP 状态码
     * @param string $title   页面标题
     * @param string $message 副标题描述
     */
    private function plainPage(int $status, string $title, string $message): Response
    {
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{$title}</title>
<style>
body{margin:0;padding:0;font-family:Arial,sans-serif;background:#f5f5f5;color:#333;}
.w{max-width:600px;margin:120px auto;text-align:center;}
h1{font-size:80px;margin:0;color:#ccc;}
h2{font-size:24px;margin:10px 0 20px;}
p{color:#888;}
a{color:#e6004d;text-decoration:none;}
a:hover{text-decoration:underline;}
</style>
</head>
<body>
<div class="w">
  <h1>{$status}</h1>
  <h2>{$title}</h2>
  <p>{$message}，<a href="/">返回首页</a></p>
</div>
</body>
</html>
HTML;
        return Response::create($html, 'html', $status);
    }
}
