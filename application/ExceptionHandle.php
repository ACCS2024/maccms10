<?php
declare(strict_types=1);

namespace app;

use think\exception\Handle;
use think\exception\HttpException;
use think\exception\HttpResponseException;
use think\facade\Log;
use think\facade\View;
use think\template\exception\TemplateNotFoundException;
use think\Request;
use think\Response;
use Throwable;

/**
 * 商业级全局异常处理器
 *
 * 设计原则
 * --------
 * 1. 永不向外部暴露：堆栈、文件路径、SQL片段、类名、框架版本、PHP版本。
 *    无论 app_debug 取值如何，对外只输出 HTTP 状态码 + 通用描述 + error_id。
 *
 * 2. 防御纵深：ExceptionHandle 本身不依赖 app_debug 决定是否显示细节；
 *    细节只写日志，由运维人员通过 runtime/{app}/log 目录查看。
 *
 * 3. API 请求返回 JSON，浏览器请求返回主题 HTML 页；
 *    均含 error_id 供用户提供给客服定位。
 *
 * 4. 分级日志：
 *    - 404：不记录（扫描器噪音）
 *    - 403/429 等客户端错误：warning 级别
 *    - 5xx 服务端错误：error 级别，含完整 trace
 *
 * 5. 多层降级：themed template → plain HTML → 最小 inline HTML，
 *    确保异常处理器本身不会再次抛出异常。
 *
 * 主题模板约定（新增 error/5xx.html）
 * --------------------------------------
 * template/{tpl_dir}/{html_dir}/error/404.html  — 已有
 * template/{tpl_dir}/{html_dir}/error/5xx.html  — 新增，用于 403/429/500/503
 * 模板可读 {$error_code} {$error_title} {$error_message} {$error_id}
 */
class ExceptionHandle extends Handle
{
    /** 对用户展示的状态码 → [标题, 描述] 映射 */
    private const STATUS_MAP = [
        400 => ['请求格式有误',   '您的请求格式有误，请检查参数后重试'],
        403 => ['禁止访问',       '您没有权限访问此页面'],
        404 => ['页面不存在',     '您访问的页面不存在或已被删除'],
        405 => ['请求方式不允许', '当前请求方式不被支持'],
        429 => ['请求过于频繁',   '您的请求太频繁，请稍后再试'],
        500 => ['服务器错误',     '服务器发生了一点小问题，我们已记录，请稍后重试'],
        503 => ['服务暂时不可用', '系统正在维护中，请稍后再试'],
    ];

    /**
     * 将异常转为 HTTP 响应（覆盖父类，无论 debug 状态均不透传内部信息）
     */
    public function render(Request $request, Throwable $e): Response
    {
        // ── 控制流异常必须原样放行，绝不能当成错误渲染 ──────────────────────
        // TP8 用 HttpResponseException 承载「提前结束请求并返回某个 Response」：
        // redirect()、$this->error()/success()、中间件的拒绝响应，全都靠它。
        // 框架基类 Handle::render() 第一步就是 `return $e->getResponse();`，
        // 本类此前完全覆盖了 render() 却没有保留这一分支，导致：
        //   · 后台未登录跳登录页 → 500（整个后台不可用）
        //   · 后台任何 error()/success() 提示 → 500
        //   · CsrfGuard 拒绝非法请求 → 500
        // 即所有正常的跳转与提示都被渲染成了服务器错误。
        if ($e instanceof HttpResponseException) {
            return $e->getResponse();
        }

        $status  = $this->resolveStatus($e);
        $errorId = $this->generateErrorId();
        $message = $this->messageFor($status, $e);

        $this->writeLog($e, $status, $errorId, $request);

        // API 请求（ENTRANCE=api 或 Accept/X-Requested-With 标识 JSON 客户端）→ JSON
        if ($this->isApiRequest($request)) {
            return $this->jsonError($status, $errorId, $message);
        }

        // 浏览器请求 → 主题 HTML 页
        return $this->htmlError($status, $errorId, $message);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // 私有：工具方法
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * 从异常推导 HTTP 状态码
     */
    private function resolveStatus(Throwable $e): int
    {
        if ($e instanceof HttpException) {
            $s = $e->getStatusCode();
            // 仅放行合法的 4xx/5xx；其他奇怪状态码归 500
            return ($s >= 400 && $s < 600) ? $s : 500;
        }
        return 500;
    }

    /**
     * 生成短 error ID：E-{微秒时间戳后6位}-{4位随机十六进制}
     * 足够唯一，且对用户友好（不需暴露精确时间戳）
     */
    private function generateErrorId(): string
    {
        $ts  = substr((string)(int)(microtime(true) * 1000), -6);
        $rnd = sprintf('%04x', random_int(0, 0xffff));
        return 'E-' . $ts . '-' . $rnd;
    }

    /**
     * 按严重程度写日志
     * - 404：静默（扫描器/误输 URL 噪音太多）
     * - 4xx：warning（客户端错误，记录 URL+IP 便于排查恶意行为）
     * - 5xx：error（服务端错误，记录完整 trace）
     */
    private function writeLog(Throwable $e, int $status, string $errorId, Request $request): void
    {
        if ($status === 404) {
            return;
        }

        try {
            $url    = (string)$request->url(true);
            $ip     = (string)$request->ip();
            $method = (string)$request->method();

            if ($status >= 500) {
                Log::error('[' . $errorId . '] ' . $status . ' ' . $method . ' ' . $url
                    . ' IP:' . $ip
                    . ' | ' . get_class($e) . ': ' . $e->getMessage()
                    . ' in ' . $e->getFile() . ':' . $e->getLine()
                    . "\n" . $e->getTraceAsString());
            } else {
                Log::warning('[' . $errorId . '] ' . $status . ' ' . $method . ' ' . $url
                    . ' IP:' . $ip
                    . ' | ' . get_class($e) . ': ' . $e->getMessage());
            }
        } catch (Throwable $logEx) {
            // 日志失败不能让异常处理器本身崩溃
        }
    }

    /**
     * 判断是否为 API / JSON 请求
     */
    private function isApiRequest(Request $request): bool
    {
        // 入口文件标识优先（api.php 定义 ENTRANCE=api）
        if (defined('ENTRANCE') && ENTRANCE === 'api') {
            return true;
        }
        // Accept 头包含 json
        $accept = strtolower((string)$request->header('accept', ''));
        if (strpos($accept, 'application/json') !== false) {
            return true;
        }
        // Ajax 请求（前端 fetch/axios 通常带此头）
        if ($request->isAjax()) {
            return true;
        }
        return false;
    }

    /**
     * JSON 错误响应（API 专用）
     */
    private function jsonError(int $status, string $errorId, ?array $message = null): Response
    {
        [$title, $desc] = $message ?? $this->statusText($status);
        $body = [
            'code'     => 0,
            'msg'      => $title,
            'detail'   => $desc,
            'error_id' => $errorId,
        ];

        return Response::create($body, 'json', $status)
            ->header(['Content-Type' => 'application/json; charset=utf-8']);
    }

    /**
     * HTML 错误响应：尝试主题模板 → 纯 HTML 降级 → 最小内联 HTML
     */
    private function htmlError(int $status, string $errorId, ?array $message = null): Response
    {
        [$title, $desc] = $message ?? $this->statusText($status);

        // 第一层：尝试渲染主题模板
        try {
            $tpl = ($status === 404) ? 'error/404' : 'error/5xx';
            $this->prepareViewVars($status, $title, $desc, $errorId);
            $content = View::fetch($tpl);
            return Response::create($content, 'html', $status)
                ->header(['Cache-Control' => 'no-store, no-cache, must-revalidate']);
        } catch (Throwable $t1) {
            // 模板渲染失败（主题缺少 5xx.html 等情况），降级
        }

        // 第二层：纯 HTML（无任何框架依赖）
        try {
            return $this->plainPage($status, $title, $desc, $errorId);
        } catch (Throwable $t2) {
            // 极端情况下 plainPage 也失败（不应发生），最终兜底
        }

        // 第三层：最小内联 HTML，绝不失败
        return Response::create(
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' . $status . '</title></head>'
            . '<body><h1>' . $status . '</h1><p>' . htmlspecialchars($title, ENT_QUOTES) . '</p>'
            . '<p><small>' . htmlspecialchars($errorId, ENT_QUOTES) . '</small></p></body></html>',
            'html',
            $status
        );
    }

    /**
     * 为主题模板注入所需变量（404/5xx 共用）
     */
    private function prepareViewVars(int $status, string $title, string $desc, string $errorId): void
    {
        // 补全 $maccms 以防 error 模板 include head/foot 时缺字段
        $cfg  = $GLOBALS['config'] ?? [];
        $site = $cfg['site'] ?? [];
        $maccms = array_merge($site, [
            'path'               => defined('MAC_PATH') ? MAC_PATH : '',
            'path_tpl'           => $GLOBALS['MAC_PATH_TEMPLATE'] ?? '',
            'date'               => date('Y-m-d'),
            'http_type'          => $GLOBALS['http_type'] ?? 'http://',
            'seo'                => $cfg['seo'] ?? [],
            'mid'                => 0,
            'aid'                => 0,
            'controller_action'  => 'error/' . $status,
            'user_status'        => $cfg['user']['status'] ?? 0,
            'search_hot'         => $cfg['app']['search_hot'] ?? '',
        ]);
        View::assign('maccms',       $maccms);
        View::assign('param',        []);
        View::assign('popedom',      ['code' => 1, 'msg' => '', 'trysee' => 0, 'confirm' => 0]);
        View::assign('error_code',   $status);
        View::assign('error_title',  $title);
        View::assign('error_message', $desc);
        View::assign('error_id',     $errorId);
    }

    /**
     * 无任何框架/主题依赖的纯 HTML 降级页
     */
    private function plainPage(int $status, string $title, string $desc, string $errorId): Response
    {
        $s   = htmlspecialchars((string)$status,  ENT_QUOTES);
        $t   = htmlspecialchars($title,            ENT_QUOTES);
        $d   = htmlspecialchars($desc,             ENT_QUOTES);
        $eid = htmlspecialchars($errorId,          ENT_QUOTES);

        $html = <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{$s} - {$t}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f7f7f7;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center}
.w{max-width:520px;width:90%;text-align:center;padding:40px 0}
.code{font-size:96px;font-weight:700;color:#e0e0e0;line-height:1}
.title{font-size:22px;font-weight:600;margin:12px 0 8px}
.desc{color:#888;line-height:1.6;margin-bottom:24px}
.actions a{display:inline-block;margin:0 8px;padding:10px 22px;border-radius:6px;text-decoration:none;font-size:14px}
.btn-home{background:#e6004d;color:#fff}
.btn-back{background:#f0f0f0;color:#555}
.btn-home:hover{background:#c40041}
.btn-back:hover{background:#e0e0e0}
.eid{margin-top:32px;color:#bbb;font-size:12px;font-family:monospace}
</style>
</head>
<body>
<div class="w">
  <div class="code">{$s}</div>
  <div class="title">{$t}</div>
  <p class="desc">{$d}</p>
  <div class="actions">
    <a href="/" class="btn-home">返回首页</a>
    <a href="javascript:history.back();" class="btn-back">返回上页</a>
  </div>
  <div class="eid">错误参考码：{$eid}</div>
</div>
</body>
</html>
HTML;
        return Response::create($html, 'html', $status)
            ->header(['Cache-Control' => 'no-store, no-cache, must-revalidate']);
    }

    /**
     * 返回状态码对应的 [title, description]
     */
    private function statusText(int $status): array
    {
        return self::STATUS_MAP[$status]
            ?? ['服务器错误', '服务器发生了一点小问题，我们已记录，请稍后重试'];
    }

    /**
     * 为常见的部署/主题问题提供可行动的提示，同时不向访客泄露文件路径。
     * 完整异常仍由 writeLog() 记录，便于管理员按 error_id 定位缺失模板。
     */
    private function messageFor(int $status, Throwable $e): array
    {
        if ($e instanceof TemplateNotFoundException) {
            return [
                '页面暂时不可用',
                '当前页面暂时无法访问，请稍后重试。',
            ];
        }

        return $this->statusText($status);
    }
}
