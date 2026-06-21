<?php
declare(strict_types=1);

namespace app;

use think\exception\Handle;
use think\exception\HttpException;
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
 * 1. 404（路由缺失）：无论 debug 模式是否开启，始终返回无指纹的简洁页。
 *    404 是"资源不存在"，不是 bug；dev 环境也不需要看 stack trace。
 *
 * 2. 其他异常 + debug=true（开发环境）：透传给 TP8 默认处理器，保留完整
 *    stack trace，方便开发调试。
 *
 * 3. 其他异常 + debug=false（生产环境）：返回简洁错误页，不暴露框架/路径/
 *    SQL 片段等内部信息。
 *
 * debug 模式开关
 * ---------------
 * 仅通过 config/app.php 的 app_debug 控制，不应在后台 UI 提供切换入口。
 * 原因：admin 凭证泄漏 → 开启 debug → 任意报错页暴露完整 stack。
 * 需要在生产排查问题时，使用日志（runtime/index/log）而非开 debug。
 *
 * 扩展说明
 * --------
 * 如需渲染主题模板（如 template/vozy/vo20w2/error/404.html），在
 * render404() 中替换 plainPage() 调用，通过 TP8 View 渲染即可。
 * 目前主题未提供 error/ 子目录，故暂用内联 HTML，保持零依赖。
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
        // HttpException 404 = 路由找不到，与 debug 模式无关，始终返回简洁页。
        // 如需主题化 404 页，在此调用 View::fetch() 渲染 error/404.html。
        if ($e instanceof HttpException && $e->getStatusCode() === 404) {
            return $this->plainPage(404, '页面不存在', '您访问的页面不存在');
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
        // 如需主题化错误页，在此渲染 error/5xx.html。
        $status = ($e instanceof HttpException) ? $e->getStatusCode() : 500;
        return $this->plainPage($status, '页面错误', '服务器发生错误，请稍后重试');
    }

    /**
     * 生成无框架指纹的简洁 HTML 响应。
     *
     * @param int    $status  HTTP 状态码
     * @param string $title   页面标题及大标题
     * @param string $message 副标题描述
     *
     * TODO: 当主题提供 error/ 模板目录后，改由 View 渲染主题模板，
     *       当前内联 HTML 仅作兜底，不依赖任何框架/主题文件。
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
